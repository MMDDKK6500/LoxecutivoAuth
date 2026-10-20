require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const bcrypt = require('bcrypt');
const app = express();
const cors = require('cors');



const SECRET_KEY = process.env.SECRET_KEY
if (!SECRET_KEY) {
    throw new Error('SECRET_KEY must be configured');
}

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

const allowedOrigins = (process.env.CORS_ORIGINS || 'https://loxecutivo.mmddkk.dev.br,http://localhost:5173')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
app.use(cors({
    credentials: true,
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Origem não permitida.'));
    },
}));

const normalizeEmail = (value) => typeof value === 'string' ? value.trim().toLowerCase() : '';
const validateCredentials = (email, senha) => {
    if (!email || !senha) return 'E-mail e palavra-passe são obrigatórios.';
    if (!/^\S+@\S+\.\S+$/.test(email)) return 'O e-mail informado é inválido.';
    if (senha.length < 4 || senha.length > 128) return 'A palavra-passe deve ter entre 4 e 128 caracteres.';
    return null;
};
const bearerToken = (request) => request.headers.authorization?.match(/^Bearer\s+(\S+)$/i)?.[1] || null;

// Endpoint para criar um novo utilizador (Registo)
app.post('/registrar', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';
    const validationError = validateCredentials(email, senha);
    if (validationError) return res.status(400).json({ message: validationError });

    try {
        // 1. Verificar se o e-mail já está registado na base de dados
        const [utilizadoresExistentes] = await pool.execute('SELECT id FROM usuarios WHERE email = ?', [email]);
        
        if (utilizadoresExistentes.length > 0) {
            return res.status(409).json({ message: "Este e-mail já se encontra registado." });
        }

        // Use a deliberately expensive password hash and never store plaintext passwords.
        const senhaHash = await bcrypt.hash(senha, 12);

        // 4. Inserir o novo utilizador na base de dados
        await pool.execute(
            'INSERT INTO usuarios (email, senha) VALUES (?, ?)', 
            [email, senhaHash]
        );

        return res.status(201).json({ message: "Utilizador criado com sucesso!" });

    } catch (error) {
        console.error("Erro ao criar utilizador:", error);
        return res.status(500).json({ message: "Erro interno no servidor." });
    }
});

app.delete('/remover', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';
    const validationError = validateCredentials(email, senha);
    if (validationError) return res.status(400).json({ message: validationError });

    const token = bearerToken(req);
    if (!token) return res.status(401).json({ message: 'Token não fornecido.' });
    try {
        const tokenUser = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
        if (tokenUser.email !== email) return res.status(403).json({ message: 'A conta autenticada não corresponde ao e-mail informado.' });
    } catch (_error) {
        return res.status(401).json({ message: 'Token inválido ou expirado.' });
    }

    try {
        // Verifica se o utilizador existe
        const [utilizadores] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        if (utilizadores.length === 0) {
            return res.status(404).json({ message: "Utilizador não encontrado." });
        }

        const utilizador = utilizadores[0];
        
        // Compara a senha digitada com o hash salvo no banco
        const senhaValida = await bcrypt.compare(senha, utilizador.senha);

        if (!senhaValida) {
            return res.status(401).json({ message: "Palavra-passe incorreta." });
        }

        // Remove o utilizador da base de dados
        await pool.execute('DELETE FROM usuarios WHERE email = ?', [email]);

        return res.status(200).json({ message: "Utilizador removido com sucesso!" });

    } catch (error) {
        console.error("Erro ao remover utilizador:", error);
        return res.status(500).json({ message: "Erro interno no servidor." });
    }

});


// Endpoint 1: Gerar o Token (Login)
app.post('/login', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';
    const validationError = validateCredentials(email, senha);
    if (validationError) return res.status(400).json({ auth: false, message: validationError });

    try {
        // O símbolo '?' protege contra SQL Injection
        const [usuarios] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', [email]);

        const usuario = usuarios[0];
        const senhaValida = usuario ? await bcrypt.compare(senha, usuario.senha) : false;

        // The same response prevents account enumeration through the login endpoint.
        if (!usuario || !senhaValida) {
            return res.status(401).json({ auth: false, message: "Credenciais inválidas." });
        }

        // Gera o token JWT com os dados do banco
        const payload = { userId: usuario.id, email: usuario.email };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h', algorithm: 'HS256' });

        return res.json({ auth: true, token: token });

    } catch (error) {
        console.error("Erro no banco:", error);
        return res.status(500).json({ auth: false, message: "Erro interno no servidor." });
    }
});

// Endpoint 2: Validar o Token (Usado pelo Gateway ou pelo Core)
app.post('/validar', (req, res) => {
    const token = bearerToken(req);

    if (!token) return res.status(401).json({ auth: false, message: "Token não fornecido." });

    try {
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
        return res.status(200).json({ auth: true, user: decoded });
    } catch (_error) {
        return res.status(401).json({ auth: false, message: "Token inválido ou expirado." });
    }
});

app.use((error, _req, res, next) => {
    if (error?.message === 'Origem não permitida.') {
        return res.status(403).json({ message: error.message });
    }
    return next(error);
});

if (require.main === module) {
    const port = Number(process.env.PORT || 8082);
    app.listen(port, '127.0.0.1', () => console.log(`Auth Service rodando na porta ${port}`));
}

module.exports = { app, normalizeEmail, validateCredentials };
