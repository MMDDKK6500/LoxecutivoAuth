process.env.DB_HOST = '127.0.0.1';
process.env.DB_USER = 'test';
process.env.DB_PASSWORD = 'test';
process.env.DB_NAME = 'test';
process.env.SECRET_KEY = 'test-secret-key-that-is-long-enough';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('../db');
const { app, normalizeEmail, validateCredentials } = require('../index');

test('normalizes emails before authentication', () => {
    assert.equal(normalizeEmail('  User@Example.COM '), 'user@example.com');
    assert.equal(normalizeEmail(null), '');
});

test('rejects malformed credentials before reaching the database', async () => {
    const response = await request(app).post('/login').send({ email: 'not-an-email', senha: '1234' });
    assert.equal(response.status, 400);
    assert.equal(response.body.auth, false);
    assert.match(response.body.message, /e-mail/i);
    assert.equal(validateCredentials('user@example.com', '1234'), null);
});

test('validates signed tokens and rejects missing or wrong-algorithm tokens', async () => {
    const validToken = jwt.sign({ userId: 7, email: 'user@example.com' }, process.env.SECRET_KEY, { expiresIn: '2m', algorithm: 'HS256' });
    const valid = await request(app).post('/validar').set('Authorization', `Bearer ${validToken}`);
    assert.equal(valid.status, 200);
    assert.equal(valid.body.user.userId, 7);

    const missing = await request(app).post('/validar');
    assert.equal(missing.status, 401);

    const wrongAlgorithm = jwt.sign({ userId: 7 }, process.env.SECRET_KEY, { algorithm: 'HS384' });
    const rejected = await request(app).post('/validar').set('Authorization', `Bearer ${wrongAlgorithm}`);
    assert.equal(rejected.status, 401);
});

test('login returns one generic error for unknown users and bad passwords', async () => {
    const originalExecute = pool.execute;
    const passwordHash = await bcrypt.hash('1234', 4);
    pool.execute = async (_query, parameters) => {
        if (parameters[0] === 'missing@example.com') return [[]];
        return [[{ id: 4, email: 'user@example.com', senha: passwordHash }]];
    };

    try {
        const unknown = await request(app).post('/login').send({ email: 'missing@example.com', senha: '1234' });
        const badPassword = await request(app).post('/login').send({ email: 'user@example.com', senha: 'wrong' });
        assert.equal(unknown.status, 401);
        assert.equal(badPassword.status, 401);
        assert.equal(unknown.body.message, badPassword.body.message);
    } finally {
        pool.execute = originalExecute;
    }
});

test('login issues a token accepted by the validator', async () => {
    const originalExecute = pool.execute;
    const passwordHash = await bcrypt.hash('1234', 4);
    pool.execute = async () => [[{ id: 4, email: 'user@example.com', senha: passwordHash }]];

    try {
        const login = await request(app).post('/login').send({ email: ' USER@example.com ', senha: '1234' });
        assert.equal(login.status, 200);
        assert.equal(login.body.auth, true);
        const validation = await request(app).post('/validar').set('Authorization', `Bearer ${login.body.token}`);
        assert.equal(validation.status, 200);
        assert.equal(validation.body.user.email, 'user@example.com');
    } finally {
        pool.execute = originalExecute;
    }
});

test('account removal requires a valid token for the same account', async () => {
    const missingToken = await request(app).delete('/remover').send({ email: 'user@example.com', senha: '1234' });
    assert.equal(missingToken.status, 401);

    const otherUserToken = jwt.sign({ userId: 9, email: 'other@example.com' }, process.env.SECRET_KEY, { algorithm: 'HS256' });
    const wrongAccount = await request(app)
        .delete('/remover')
        .set('Authorization', `Bearer ${otherUserToken}`)
        .send({ email: 'user@example.com', senha: '1234' });
    assert.equal(wrongAccount.status, 403);
});

test('rejects untrusted browser origins', async () => {
    const response = await request(app).options('/validar').set('Origin', 'https://attacker.example');
    assert.equal(response.status, 403);
});
