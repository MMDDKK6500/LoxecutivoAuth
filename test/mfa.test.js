const test = require('node:test');
const assert = require('node:assert/strict');
const otp = require('otplib');
const mfa = require('../mfa');
process.env.MFA_ENCRYPTION_KEY = 'ab'.repeat(32);

test('encrypts secrets and rejects tampered ciphertext', () => {
  const encrypted = mfa.encrypt('secret');
  assert.equal(mfa.decrypt(encrypted), 'secret');
  const bytes = Buffer.from(encrypted, 'base64');
  bytes[20] ^= 1;
  assert.throws(() => mfa.decrypt(bytes.toString('base64')));
});

test('accepts TOTP once and rejects replay and wrong codes', async () => {
  const secret = otp.generateSecret();
  const row = { secret: mfa.encrypt(secret), enabled: 1, last_step: -1, recovery: [] };
  const connection = {
    beginTransaction: async () => {}, commit: async () => {}, rollback: async () => {}, release: () => {},
    execute: async (sql, args) => {
      if (sql.startsWith('SELECT')) return [[row]];
      if (sql.includes('last_step')) row.last_step = args[0];
      return [{}];
    },
  };
  const pool = { getConnection: async () => connection };
  const code = await otp.generate({ secret });
  assert.equal(await mfa.consume(pool, 1, code), true);
  assert.equal(await mfa.consume(pool, 1, code), false);
  assert.equal(await mfa.consume(pool, 1, 'invalid'), false);
  const recoveryCode = 'a'.repeat(24);
  row.recovery = [require('node:crypto').createHash('sha256').update(recoveryCode).digest('hex')];
  assert.equal(await mfa.consume(pool, 1, recoveryCode), true);
  assert.equal(await mfa.consume(pool, 1, recoveryCode), false);
});
