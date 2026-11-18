'use strict';

const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const { promisify } = require('node:util');
const {
    randomBytes,
    scrypt,
    timingSafeEqual
} = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'accounts.sqlite');
const BODY_LIMIT = 16 * 1024;
const deriveKey = promisify(scrypt);
const dummySalt = Buffer.alloc(16, 0x7f);

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    throw new Error('PORT must be a valid TCP port.');
}

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });

const database = new DatabaseSync(DATABASE_PATH);
database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
`);

const findAccountByEmail = database.prepare(`
    SELECT id, username, email, password_salt, password_hash
    FROM accounts
    WHERE email = ?
`);
const insertAccount = database.prepare(`
    INSERT INTO accounts (username, email, password_salt, password_hash)
    VALUES (?, ?, ?, ?)
`);

const publicFiles = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/index.html', ['index.html', 'text/html; charset=utf-8']],
    ['/style.css', ['style.css', 'text/css; charset=utf-8']],
    ['/script.js', ['script.js', 'text/javascript; charset=utf-8']],
    ['/mythical-dragon-beast-anime-style.jpg', ['mythical-dragon-beast-anime-style.jpg', 'image/jpeg']]
]);

function sendJson(response, status, payload) {
    const body = Buffer.from(JSON.stringify(payload));
    response.writeHead(status, {
        'Cache-Control': 'no-store',
        'Content-Length': body.length,
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff'
    });
    response.end(body);
}

function requestError(status, message) {
    const error = new Error(message);
    error.status = status;
    return error;
}

async function readJsonBody(request) {
    const contentType = request.headers['content-type'] || '';
    if (contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
        throw requestError(415, 'Send the form as JSON.');
    }

    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
        size += chunk.length;
        if (size > BODY_LIMIT) {
            throw requestError(413, 'The submitted form is too large.');
        }
        chunks.push(chunk);
    }

    let body;
    try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        throw requestError(400, 'The submitted form is not valid JSON.');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw requestError(400, 'The submitted form must be a JSON object.');
    }
    return body;
}

function isValidEmail(email) {
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUsername(username) {
    return /^[A-Za-z0-9_-]{3,32}$/.test(username);
}

async function hashPassword(password, salt) {
    return deriveKey(password, salt, 64, {
        N: 16384,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024
    });
}

async function createAccount(request, response) {
    const body = await readJsonBody(request);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!isValidUsername(username)) {
        sendJson(response, 400, { error: 'Username must be 3–32 letters, numbers, underscores, or hyphens.' });
        return;
    }
    if (!isValidEmail(email)) {
        sendJson(response, 400, { error: 'Enter a valid email address.' });
        return;
    }
    if (password.length < 8 || password.length > 128) {
        sendJson(response, 400, { error: 'Password must be between 8 and 128 characters.' });
        return;
    }

    const salt = randomBytes(16);
    const passwordHash = await hashPassword(password, salt);
    try {
        insertAccount.run(username, email, salt.toString('hex'), passwordHash.toString('hex'));
    } catch (error) {
        if (error.errcode === 2067) {
            sendJson(response, 409, { error: 'An account with that username or email already exists.' });
            return;
        }
        throw error;
    }

    sendJson(response, 201, { message: 'Account created. You can now sign in.' });
}

async function signIn(request, response) {
    const body = await readJsonBody(request);
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!isValidEmail(email) || password.length === 0 || password.length > 128) {
        sendJson(response, 400, { error: 'Enter a valid email and password.' });
        return;
    }

    const account = findAccountByEmail.get(email);
    const salt = account ? Buffer.from(account.password_salt, 'hex') : dummySalt;
    const passwordHash = await hashPassword(password, salt);
    const storedHash = account ? Buffer.from(account.password_hash, 'hex') : Buffer.alloc(64);

    if (!account || !timingSafeEqual(passwordHash, storedHash)) {
        sendJson(response, 401, { error: 'Invalid email or password.' });
        return;
    }

    sendJson(response, 200, { message: 'Signed in successfully.', username: account.username });
}

async function serveFile(response, file, contentType) {
    const content = await fs.promises.readFile(path.join(__dirname, file));
    response.writeHead(200, {
        'Cache-Control': 'no-cache',
        'Content-Length': content.length,
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff'
    });
    response.end(content);
}

async function handleRequest(request, response) {
    const url = new URL(request.url, 'http://localhost');
    if (request.method === 'POST' && url.pathname === '/api/auth/signup') {
        await createAccount(request, response);
        return;
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/signin') {
        await signIn(request, response);
        return;
    }
    if (request.method !== 'GET') {
        sendJson(response, 405, { error: 'Method not allowed.' });
        return;
    }

    const file = publicFiles.get(url.pathname);
    if (!file) {
        sendJson(response, 404, { error: 'Not found.' });
        return;
    }
    await serveFile(response, file[0], file[1]);
}

const server = http.createServer((request, response) => {
    handleRequest(request, response).catch((error) => {
        if (error.status) {
            sendJson(response, error.status, { error: error.message });
            return;
        }
        console.error('Request failed:', error);
        sendJson(response, 500, { error: 'The server could not complete the request.' });
    });
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running at http://127.0.0.1:${PORT}`);
    console.log(`SQLite database: ${DATABASE_PATH}`);
});

server.on('error', (error) => {
    console.error('Could not start the server:', error);
    process.exitCode = 1;
});
