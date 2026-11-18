'use strict';

const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const { promisify } = require('node:util');
const {
    createHash,
    randomBytes,
    scrypt,
    timingSafeEqual
} = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'accounts.sqlite');
const BODY_LIMIT = 16 * 1024;
const GOOGLE_STATE_TTL = 10 * 60 * 1000;
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const deriveKey = promisify(scrypt);
const dummySalt = Buffer.alloc(16, 0x7f);
const pendingGoogleStates = new Map();

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    throw new Error('PORT must be a valid TCP port.');
}

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });

const database = new DatabaseSync(DATABASE_PATH);
database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_salt TEXT,
        password_hash TEXT,
        google_subject TEXT UNIQUE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
`);

const accountColumns = database.prepare('PRAGMA table_info(accounts)').all();
if (!accountColumns.some((column) => column.name === 'google_subject')) {
    database.exec('BEGIN IMMEDIATE');
    try {
        database.exec(`
            ALTER TABLE accounts RENAME TO accounts_before_google_sign_in;
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt TEXT,
                password_hash TEXT,
                google_subject TEXT UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO accounts (id, username, email, password_salt, password_hash, created_at)
            SELECT id, username, email, password_salt, password_hash, created_at
            FROM accounts_before_google_sign_in;
            DROP TABLE accounts_before_google_sign_in;
        `);
        database.exec('COMMIT');
    } catch (error) {
        database.exec('ROLLBACK');
        throw error;
    }
}

database.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
`);

const findAccountByEmail = database.prepare(`
    SELECT id, username, email, password_salt, password_hash, google_subject
    FROM accounts
    WHERE email = ?
`);
const findAccountByGoogleSubject = database.prepare(`
    SELECT id, username, email
    FROM accounts
    WHERE google_subject = ?
`);
const findAccountByUsername = database.prepare(`
    SELECT id
    FROM accounts
    WHERE username = ?
`);
const insertAccount = database.prepare(`
    INSERT INTO accounts (username, email, password_salt, password_hash)
    VALUES (?, ?, ?, ?)
`);
const insertGoogleAccount = database.prepare(`
    INSERT INTO accounts (username, email, google_subject)
    VALUES (?, ?, ?)
`);
const linkGoogleAccount = database.prepare(`
    UPDATE accounts
    SET google_subject = ?
    WHERE id = ? AND google_subject IS NULL
`);
const insertSession = database.prepare(`
    INSERT INTO sessions (token_hash, account_id, expires_at)
    VALUES (?, ?, ?)
`);
const findSession = database.prepare(`
    SELECT accounts.id, accounts.username
    FROM sessions
    JOIN accounts ON accounts.id = sessions.account_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
`);
const deleteSession = database.prepare('DELETE FROM sessions WHERE token_hash = ?');
const deleteExpiredSessions = database.prepare('DELETE FROM sessions WHERE expires_at <= ?');

const publicFiles = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/index.html', ['index.html', 'text/html; charset=utf-8']],
    ['/style.css', ['style.css', 'text/css; charset=utf-8']],
    ['/script.js', ['script.js', 'text/javascript; charset=utf-8']],
    ['/mythical-dragon-beast-anime-style.jpg', ['mythical-dragon-beast-anime-style.jpg', 'image/jpeg']]
]);

function sendJson(response, status, payload, headers = {}) {
    const body = Buffer.from(JSON.stringify(payload));
    response.writeHead(status, {
        'Cache-Control': 'no-store',
        'Content-Length': body.length,
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        ...headers
    });
    response.end(body);
}

function getGoogleConfig() {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
        return null;
    }

    return {
        clientId,
        clientSecret,
        redirectUri: process.env.GOOGLE_REDIRECT_URI
            || `http://127.0.0.1:${PORT}/auth/google/callback`
    };
}

function googleRedirect(response, result, cookies = []) {
    response.writeHead(303, {
        'Cache-Control': 'no-store',
        Location: `/?google=${encodeURIComponent(result)}`,
        ...(cookies.length ? { 'Set-Cookie': cookies } : {})
    });
    response.end();
}

function getCookie(request, name) {
    const cookies = request.headers.cookie || '';
    for (const item of cookies.split(';')) {
        const separator = item.indexOf('=');
        if (separator < 0) {
            continue;
        }
        if (item.slice(0, separator).trim() === name) {
            return item.slice(separator + 1).trim();
        }
    }
    return '';
}

function cookiesAreEqual(first, second) {
    const firstBytes = Buffer.from(first);
    const secondBytes = Buffer.from(second);
    return firstBytes.length === secondBytes.length
        && timingSafeEqual(firstBytes, secondBytes);
}

function sessionCookie(token, maxAge = SESSION_TTL / 1000, secure = false) {
    return `auth_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

function createSession(accountId) {
    const token = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const expiresAt = Date.now() + SESSION_TTL;
    deleteExpiredSessions.run(Date.now());
    insertSession.run(tokenHash, accountId, expiresAt);
    return token;
}

function startGoogleSignIn(request, response) {
    const config = getGoogleConfig();
    if (!config) {
        googleRedirect(response, 'not_configured');
        return;
    }

    const state = randomBytes(32).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const expiresAt = Date.now() + GOOGLE_STATE_TTL;
    for (const [pendingState, pending] of pendingGoogleStates) {
        if (pending.expiresAt <= Date.now()) {
            pendingGoogleStates.delete(pendingState);
        }
    }
    const account = getCurrentSession(request);
    pendingGoogleStates.set(state, {
        codeVerifier,
        expiresAt,
        accountId: account ? account.id : null
    });

    const secure = config.redirectUri.startsWith('https://');
    const googleUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    googleUrl.search = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        prompt: 'select_account',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    }).toString();

    response.writeHead(302, {
        'Cache-Control': 'no-store',
        Location: googleUrl.toString(),
        'Set-Cookie': `google_oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/auth/google/callback; Max-Age=${GOOGLE_STATE_TTL / 1000}${secure ? '; Secure' : ''}`
    });
    response.end();
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
    const hasPassword = account && account.password_salt && account.password_hash;
    const salt = hasPassword ? Buffer.from(account.password_salt, 'hex') : dummySalt;
    const passwordHash = await hashPassword(password, salt);
    const storedHash = hasPassword ? Buffer.from(account.password_hash, 'hex') : Buffer.alloc(64);

    if (!hasPassword || !timingSafeEqual(passwordHash, storedHash)) {
        sendJson(response, 401, { error: 'Invalid email or password.' });
        return;
    }

    const token = createSession(account.id);
    sendJson(response, 200, {
        message: 'Signed in successfully.',
        username: account.username
    }, {
        'Set-Cookie': sessionCookie(token, undefined, process.env.NODE_ENV === 'production')
    });
}

function createGoogleUsername(name, email) {
    let base = (name || email.split('@')[0])
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^A-Za-z0-9_-]+/g, '_')
        .replace(/^[_-]+|[_-]+$/g, '')
        .slice(0, 24);
    if (base.length < 3) {
        base = 'google_user';
    }

    for (let attempt = 0; attempt < 20; attempt += 1) {
        const suffix = attempt === 0 ? '' : `_${randomBytes(3).toString('hex')}`;
        const username = `${base.slice(0, 32 - suffix.length)}${suffix}`;
        if (!findAccountByUsername.get(username)) {
            return username;
        }
    }
    throw new Error('Could not generate a unique username for the Google account.');
}

async function completeGoogleSignIn(request, response, url) {
    const state = url.searchParams.get('state') || '';
    const pending = pendingGoogleStates.get(state);
    const stateCookie = getCookie(request, 'google_oauth_state');
    const clearStateCookie = `google_oauth_state=; HttpOnly; SameSite=Lax; Path=/auth/google/callback; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;

    if (!pending || pending.expiresAt <= Date.now() || !cookiesAreEqual(state, stateCookie)) {
        pendingGoogleStates.delete(state);
        googleRedirect(response, 'invalid_state', [clearStateCookie]);
        return;
    }
    pendingGoogleStates.delete(state);

    if (url.searchParams.has('error')) {
        googleRedirect(response, 'cancelled', [clearStateCookie]);
        return;
    }

    const code = url.searchParams.get('code');
    const config = getGoogleConfig();
    if (!code || !config) {
        googleRedirect(response, config ? 'provider_error' : 'not_configured', [clearStateCookie]);
        return;
    }

    try {
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code,
                code_verifier: pending.codeVerifier,
                grant_type: 'authorization_code',
                redirect_uri: config.redirectUri
            }),
            signal: AbortSignal.timeout(10000)
        });
        const tokens = await tokenResponse.json();
        if (!tokenResponse.ok || typeof tokens.access_token !== 'string') {
            throw new Error('Google token exchange was rejected.');
        }

        const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` },
            signal: AbortSignal.timeout(10000)
        });
        const profile = await profileResponse.json();
        if (!profileResponse.ok
            || typeof profile.sub !== 'string'
            || typeof profile.email !== 'string'
            || profile.email_verified !== true) {
            throw new Error('Google did not return a verified email address.');
        }

        const email = profile.email.trim().toLowerCase();
        if (!isValidEmail(email)) {
            throw new Error('Google returned an invalid email address.');
        }
        let account = findAccountByGoogleSubject.get(profile.sub);
        if (!account) {
            const emailAccount = findAccountByEmail.get(email);
            if (emailAccount) {
                const currentSession = getCurrentSession(request);
                if (pending.accountId !== emailAccount.id
                    || !currentSession
                    || currentSession.id !== emailAccount.id
                    || emailAccount.google_subject) {
                    googleRedirect(response, 'account_exists', [clearStateCookie]);
                    return;
                }
                linkGoogleAccount.run(profile.sub, emailAccount.id);
            } else {
                const username = createGoogleUsername(
                    typeof profile.name === 'string' ? profile.name : '',
                    email
                );
                try {
                    insertGoogleAccount.run(username, email, profile.sub);
                } catch (error) {
                    if (error.errcode !== 2067) {
                        throw error;
                    }
                }
            }

            account = findAccountByGoogleSubject.get(profile.sub);
            if (!account) {
                googleRedirect(response, 'account_exists', [clearStateCookie]);
                return;
            }
        }

        const sessionToken = createSession(account.id);
        const secure = config.redirectUri.startsWith('https://');
        googleRedirect(response, 'signed_in', [
            clearStateCookie,
            sessionCookie(sessionToken, undefined, secure)
        ]);
    } catch (error) {
        console.error('Google sign-in failed:', error);
        googleRedirect(response, 'provider_error', [clearStateCookie]);
    }
}

function getCurrentSession(request) {
    const token = getCookie(request, 'auth_session');
    if (!token) {
        return null;
    }
    const tokenHash = createHash('sha256').update(token).digest('hex');
    return findSession.get(tokenHash, Date.now()) || null;
}

function signOut(request, response) {
    const token = getCookie(request, 'auth_session');
    if (token) {
        const tokenHash = createHash('sha256').update(token).digest('hex');
        deleteSession.run(tokenHash);
    }
    sendJson(response, 200, { message: 'Signed out.' }, {
        'Set-Cookie': sessionCookie('', 0, process.env.NODE_ENV === 'production')
    });
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
    if (request.method === 'GET' && url.pathname === '/auth/google') {
        startGoogleSignIn(request, response);
        return;
    }
    if (request.method === 'GET' && url.pathname === '/auth/google/callback') {
        await completeGoogleSignIn(request, response, url);
        return;
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/signup') {
        await createAccount(request, response);
        return;
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/signin') {
        await signIn(request, response);
        return;
    }
    if (request.method === 'GET' && url.pathname === '/api/auth/session') {
        const account = getCurrentSession(request);
        sendJson(response, 200, account
            ? { authenticated: true, username: account.username }
            : { authenticated: false });
        return;
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/signout') {
        signOut(request, response);
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
