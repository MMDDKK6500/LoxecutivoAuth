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

app.use(express.json());
app.use(cors());

// Endpoint para criar um novo utilizador (Registo)
app.post('/registrar', async (req, res) => {
    const { email, senha } = req.body;

    // Validação básica
    if (!email || !senha) {
        return res.status(400).json({ message: "E-mail e palavra-passe são obrigatórios." });
    }

    try {
        // 1. Verificar se o e-mail já está registado na base de dados
        const [utilizadoresExistentes] = await pool.execute('SELECT id FROM usuarios WHERE email = ?', [email]);
        
        if (utilizadoresExistentes.length > 0) {
            return res.status(409).json({ message: "Este e-mail já se encontra registado." });
        }

        // 2. Encriptar a palavra-passe (Hashing) com custo 10 (salt rounds)
        const saltRounds = 10;
        const senhaHash = await bcrypt.hash(senha, saltRounds);

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
    const { email, senha } = req.body;
    
    if (!email) {
        return res.status(400).json({ message: "E-mail é obrigatório para remover o utilizador." });
    }

    if (!senha) {
        return res.status(400).json({ message: "Palavra-passe é obrigatória para remover o utilizador." });
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
    const { email, senha } = req.body;

    try {
        // O símbolo '?' protege contra SQL Injection
        const [usuarios] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', [email]);

        // Verifica se o usuário existe
        if (usuarios.length === 0) {
            return res.status(401).json({ auth: false, message: "Usuário não encontrado." });
        }

        const usuario = usuarios[0];

        // Compara a senha digitada com o hash salvo no banco (Ex: bcrypt.hashSync("123", 10))
        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({ auth: false, message: "Senha incorreta." });
        }

        // Gera o token JWT com os dados do banco
        const payload = { userId: usuario.id, email: usuario.email };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h' });

        return res.json({ auth: true, token: token });

    } catch (error) {
        console.error("Erro no banco:", error);
        return res.status(500).json({ auth: false, message: "Erro interno no servidor." });
    }
});

// Endpoint 2: Validar o Token (Usado pelo Gateway ou pelo Core)
app.post('/validar', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Pega o token do header "Bearer <token>"

    if (!token) return res.status(401).json({ auth: false, message: "Token não fornecido." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ auth: false, message: "Token inválido ou expirado." });
        
        // Se o token for válido, devolve os dados decodificados para o Core
        return res.status(200).json({ auth: true, user: decoded });
    });
});

app.listen(8082, () => console.log('Auth Service rodando na porta 8082'));
