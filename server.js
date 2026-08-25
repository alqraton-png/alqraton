const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const Database = require('better-sqlite3');

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 3000;
const jwtSecret = process.env.JWT_SECRET || 'change-this-secret';
const database = new Database(path.join(__dirname, 'alqraton.db'));

database.pragma('journal_mode = WAL');
database.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
`);

const adminEmail = process.env.ADMIN_EMAIL || 'admin@alqraton.com';
const adminPassword = process.env.ADMIN_PASSWORD || 'change-this-password';
const existingAdmin = database.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
if (!existingAdmin) {
    const passwordHash = bcrypt.hashSync(adminPassword, 12);
    database.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
        .run('Administrator', adminEmail, passwordHash, 'admin');
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

function createToken(user) {
    return jwt.sign({ id: user.id, email: user.email, role: user.role }, jwtSecret, { expiresIn: '7d' });
}

function requireAuth(request, response, next) {
    const authorization = request.headers.authorization || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : null;
    if (!token) return response.status(401).json({ error: 'Giriş tələb olunur.' });

    try {
        request.user = jwt.verify(token, jwtSecret);
        next();
    } catch {
        response.status(401).json({ error: 'Sessiya etibarsızdır.' });
    }
}

function requireAdmin(request, response, next) {
    if (request.user.role !== 'admin') return response.status(403).json({ error: 'Admin icazəsi tələb olunur.' });
    next();
}

app.get('/api/health', (request, response) => {
    response.json({ status: 'ok' });
});

app.post('/api/auth/register', (request, response) => {
    const { name, email, password } = request.body;
    if (!name || !email || !password || password.length < 6) {
        return response.status(400).json({ error: 'Ad, email və ən azı 6 simvolluq parol daxil edin.' });
    }

    try {
        const passwordHash = bcrypt.hashSync(password, 12);
        const result = database.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)')
            .run(name.trim(), email.trim().toLowerCase(), passwordHash);
        response.status(201).json({ id: result.lastInsertRowid, message: 'Qeydiyyat tamamlandı.' });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return response.status(409).json({ error: 'Bu email artıq qeydiyyatdan keçib.' });
        response.status(500).json({ error: 'Qeydiyyat zamanı xəta baş verdi.' });
    }
});

app.post('/api/auth/login', (request, response) => {
    const { email, password } = request.body;
    const user = database.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
    if (!user || !bcrypt.compareSync(password || '', user.password)) {
        return response.status(401).json({ error: 'Email və ya parol yanlışdır.' });
    }

    response.json({ token: createToken(user), user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/messages', (request, response) => {
    const { name, email, subject, message } = request.body;
    if (!name || !email || !subject || !message) return response.status(400).json({ error: 'Bütün xanaları doldurun.' });

    database.prepare('INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)')
        .run(name.trim(), email.trim(), subject.trim(), message.trim());
    response.status(201).json({ message: 'Mesajınız qəbul edildi.' });
});

app.get('/api/messages', requireAuth, requireAdmin, (request, response) => {
    response.json(database.prepare('SELECT id, name, email, subject, message, created_at FROM messages ORDER BY id DESC').all());
});

app.get('/api/products', (request, response) => {
    response.json(database.prepare('SELECT * FROM products ORDER BY id DESC').all());
});

app.post('/api/products', requireAuth, requireAdmin, (request, response) => {
    const { name, description } = request.body;
    if (!name || !description) return response.status(400).json({ error: 'Məhsul adı və açıqlaması tələb olunur.' });
    const result = database.prepare('INSERT INTO products (name, description) VALUES (?, ?)').run(name.trim(), description.trim());
    response.status(201).json({ id: result.lastInsertRowid, name, description });
});

app.delete('/api/products/:id', requireAuth, requireAdmin, (request, response) => {
    const result = database.prepare('DELETE FROM products WHERE id = ?').run(request.params.id);
    if (!result.changes) return response.status(404).json({ error: 'Məhsul tapılmadı.' });
    response.status(204).send();
});

app.get('/admin', (request, response) => {
    response.sendFile(path.join(__dirname, 'admin.html'));
});

app.use((request, response) => {
    response.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Alqraton server running at http://localhost:${port}`);
});
