const crypto = require('node:crypto');
const otp = require('otplib');
const qr = require('qrcode');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { rateLimit } = require('express-rate-limit');

const challenges = new Map();
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function key() {
  const value = process.env.MFA_ENCRYPTION_KEY || '';
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error('Configure MFA_ENCRYPTION_KEY com 64 caracteres hexadecimais.');
  return Buffer.from(value, 'hex');
}
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
}
function decrypt(value) {
  const data = Buffer.from(value, 'base64');
  const cipher = crypto.createDecipheriv('aes-256-gcm', key(), data.subarray(0, 12));
  cipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString('utf8');
}
function issueChallenge(user) {
  for (const [id, item] of challenges) if (item.expires < Date.now()) challenges.delete(id);
  if (challenges.size >= 10000) throw new Error('Too many challenges');
  const token = crypto.randomBytes(32).toString('hex');
  challenges.set(hash(token), { user, expires: Date.now() + 300000, attempts: 0 });
  return token;
}
async function enabled(pool, id) {
  const [rows] = await pool.execute('SELECT enabled FROM usuario_mfa WHERE usuario_id = ?', [id]);
  return Boolean(rows[0]?.enabled);
}
async function consume(pool, id, code, requireEnabled = true) {
  if (typeof code !== 'string' || code.length > 100) return false;
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute('SELECT * FROM usuario_mfa WHERE usuario_id = ? FOR UPDATE', [id]);
    const row = rows[0];
    if (!row || Boolean(row.enabled) !== requireEnabled) return false;
    const recovery = typeof row.recovery === 'string' ? JSON.parse(row.recovery) : row.recovery;
    const recoveryIndex = requireEnabled ? recovery.indexOf(hash(code.trim())) : -1;
    if (recoveryIndex >= 0) {
      recovery.splice(recoveryIndex, 1);
      await connection.execute('UPDATE usuario_mfa SET recovery = ? WHERE usuario_id = ?', [JSON.stringify(recovery), id]);
    } else {
      if (!/^\d{6}$/.test(code.trim())) return false;
      const result = await otp.verify({ secret: decrypt(row.secret), token: code.trim(), afterTimeStep: Number(row.last_step) >= 0 ? Number(row.last_step) : undefined, epochTolerance: 30 });
      if (!result.valid) return false;
      await connection.execute('UPDATE usuario_mfa SET last_step = ? WHERE usuario_id = ?', [result.timeStep, id]);
    }
    if (!requireEnabled) await connection.execute('UPDATE usuario_mfa SET enabled = TRUE WHERE usuario_id = ?', [id]);
    await connection.commit();
    return true;
  } finally {
    await connection.rollback();
    connection.release();
  }
}
function register(app, pool, secret) {
  const limit = rateLimit({ windowMs: 300000, limit: 20, message: { message: 'Muitas tentativas. Aguarde cinco minutos e tente novamente.' } });
  app.use('/2fa', limit, (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const authenticate = async (req, res, next) => {
    try {
      const token = req.headers.authorization?.match(/^Bearer (\S+)$/i)?.[1];
      const user = jwt.verify(token, secret, { algorithms: ['HS256'] });
      const [rows] = await pool.execute('SELECT * FROM usuarios WHERE id = ?', [user.userId]);
      if (!rows[0]) return res.sendStatus(401);
      req.account = rows[0];
      next();
    } catch { res.status(401).json({ message: 'Sua sessão expirou. Entre novamente.' }); }
  };
  app.post('/2fa/verify', async (req, res) => {
    const token = req.body?.challengeToken;
    const challenge = typeof token === 'string' ? challenges.get(hash(token)) : null;
    if (!challenge || challenge.expires < Date.now() || ++challenge.attempts > 5) return res.status(401).json({ message: 'Verificação expirada. Entre novamente.' });
    // Remove before awaiting: concurrent submissions cannot reuse this challenge.
    challenges.delete(hash(token));
    try {
      if (!await consume(pool, challenge.user.id, req.body.code)) {
        if (challenge.attempts < 5) challenges.set(hash(token), challenge);
        return res.status(401).json({ message: 'Código inválido ou já utilizado.' });
      }
      const [users] = await pool.execute('SELECT id, email FROM usuarios WHERE id = ?', [challenge.user.id]);
      if (!users[0]) return res.sendStatus(401);
      return res.json({ auth: true, token: jwt.sign({ userId: users[0].id, email: users[0].email }, secret, { expiresIn: '2h', algorithm: 'HS256' }) });
    } catch { res.status(503).json({ message: 'Não foi possível verificar o código. Entre novamente em alguns instantes.' }); }
  });
  app.get('/2fa/status', authenticate, async (req, res) => {
    try { res.json({ enabled: await enabled(pool, req.account.id) }); }
    catch { res.status(503).json({ message: 'Não foi possível consultar a segurança da conta.' }); }
  });
  app.post('/2fa/setup', authenticate, async (req, res) => {
    try {
      if (typeof req.body.senha !== 'string' || !await bcrypt.compare(req.body.senha, req.account.senha)) return res.status(401).json({ message: 'Senha incorreta.' });
      const value = otp.generateSecret();
      const codes = Array.from({ length: 10 }, () => crypto.randomBytes(12).toString('hex'));
      const encrypted = encrypt(value);
      await pool.execute('INSERT INTO usuario_mfa (usuario_id, secret, recovery) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE secret = IF(enabled, secret, VALUES(secret)), recovery = IF(enabled, recovery, VALUES(recovery)), last_step = IF(enabled, last_step, -1)', [req.account.id, encrypted, JSON.stringify(codes.map(hash))]);
      if (await enabled(pool, req.account.id)) return res.status(409).json({ message: 'A verificação em duas etapas já está ativa.' });
      const uri = otp.generateURI({ issuer: 'Loxecutivo', label: req.account.email, secret: value });
      res.json({ secret: value, qrCode: await qr.toDataURL(uri), recoveryCodes: codes });
    } catch { res.status(503).json({ message: 'Não foi possível configurar a verificação em duas etapas. Contate o administrador.' }); }
  });
  app.post('/2fa/enable', authenticate, async (req, res) => {
    try {
      if (!await consume(pool, req.account.id, req.body.code, false)) return res.status(400).json({ message: 'Código inválido. Confira o aplicativo autenticador.' });
      res.json({ enabled: true });
    } catch { res.status(503).json({ message: 'Não foi possível ativar a verificação.' }); }
  });
  app.post('/2fa/disable', authenticate, async (req, res) => {
    try {
      if (typeof req.body.senha !== 'string' || !await bcrypt.compare(req.body.senha, req.account.senha) || !await consume(pool, req.account.id, req.body.code)) return res.status(400).json({ message: 'Senha ou código inválido.' });
      await pool.execute('DELETE FROM usuario_mfa WHERE usuario_id = ?', [req.account.id]);
      res.json({ enabled: false });
    } catch { res.status(503).json({ message: 'Não foi possível desativar a verificação.' }); }
  });
}
module.exports = { register, enabled, issueChallenge, encrypt, decrypt, consume };
