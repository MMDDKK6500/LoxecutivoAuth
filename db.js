// db.js
const mysql = require('mysql2/promise');

// Cria o pool de conexões com o banco isolado do Auth Service
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'loxecutivo_auth', // Banco exclusivo para segurança
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = pool;