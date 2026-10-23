// ══════════════════════════════════════════════════════════════════
//  lib/auth.js  –  Secure auth helpers  (Security upgrade)
//
//  NEW: Persistent account lockout (AccountLockout class).
//    • Previous rateLimit.js was in-process only — a server restart
//      cleared all lockout state, letting an attacker restart the
//      process to bypass it.
//    • Lockout state is now persisted to the SQLite DB (account_lockouts
//      table) so it survives restarts.
//    • After LOCKOUT_MAX_ATTEMPTS failed logins the account is locked
//      for LOCKOUT_WINDOW_MS (default 15 minutes).
//    • On each successful login the failure counter is reset.
//    • recordFailure() and isLocked() are the two public methods
//      used from routes/api.js login handler.
//
//  KEPT: hashPassword, verifyPassword, makeToken, verifyToken,
//        getTokenFromReq (unchanged from previous bug-fix version).
// ══════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const config = require('../config/app');

const PBKDF2_ITERS   = 100_000;
const PBKDF2_KEYLEN  = 64;
const PBKDF2_DIGEST  = 'sha512';
const TOKEN_TTL_SEC  = 60 * 60;   // 1 hour

// ── Account lockout constants ─────────────────────────────────────
const LOCKOUT_MAX_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS    = 15 * 60 * 1000;  // 15 minutes
const LOCKOUT_TABLE_DDL = `
    CREATE TABLE IF NOT EXISTS account_lockouts (
        email       TEXT    PRIMARY KEY,
        failures    INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        last_attempt TEXT   NOT NULL DEFAULT (datetime('now'))
    );
`;

// ── Password hashing ──────────────────────────────────────────────

function hashPassword(password, existingSalt) {
    const salt = existingSalt
        ? Buffer.from(existingSalt, 'hex')
        : crypto.randomBytes(32);

    const hash = crypto.pbkdf2Sync(
        password, salt, PBKDF2_ITERS, PBKDF2_KEYLEN, PBKDF2_DIGEST
    );
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
    try {
        const [saltHex, storedHashHex] = stored.split(':');
        if (!saltHex || !storedHashHex) return false;

        const derived = crypto.pbkdf2Sync(
            password,
            Buffer.from(saltHex, 'hex'),
            PBKDF2_ITERS,
            PBKDF2_KEYLEN,
            PBKDF2_DIGEST
        );
        const storedBuf = Buffer.from(storedHashHex, 'hex');

        if (derived.length !== storedBuf.length) return false;
        return crypto.timingSafeEqual(derived, storedBuf);
    } catch {
        return false;
    }
}

// ── JWT ───────────────────────────────────────────────────────────

function b64(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function makeToken(payload) {
    const now    = Math.floor(Date.now() / 1000);
    const full   = { ...payload, iat: now, exp: now + TOKEN_TTL_SEC };
    const header = b64({ alg: 'HS256', typ: 'JWT' });
    const body   = b64(full);
    const sig    = crypto
        .createHmac('sha256', config.jwtSecret)
        .update(`${header}.${body}`)
        .digest('base64url');
    return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
    if (!token || typeof token !== 'string') return null;
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const [header, body, sig] = parts;

        const expectedBuf = Buffer.from(
            crypto.createHmac('sha256', config.jwtSecret)
                .update(`${header}.${body}`)
                .digest('base64url')
        );
        const sigBuf = Buffer.from(sig);

        if (sigBuf.length !== expectedBuf.length) return null;
        if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

        const payload = JSON.parse(Buffer.from(body, 'base64url').toString());

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && now > payload.exp) return null;

        return payload;
    } catch {
        return null;
    }
}

function getTokenFromReq(req) {
    const auth = req.headers['authorization'] || '';
    if (!auth.startsWith('Bearer ')) return null;
    const token = auth.slice(7).trim();
    return token.split('.').length === 3 ? token : null;
}

// ── Persistent account lockout ────────────────────────────────────

class AccountLockout {
    constructor() {
        this._ready = false;
    }

    /**
     * Lazily initialise the lockouts table.
     * Called on first use so that getDb() is already available.
     */
    _init() {
        if (this._ready) return;
        try {
            const { getDb } = require('./db');
            getDb().exec(LOCKOUT_TABLE_DDL);
            this._ready = true;
        } catch (e) {
            // Non-fatal — degraded to no lockout if DB isn't ready yet.
            console.warn('AccountLockout: DB not available yet:', e.message);
        }
    }

    /**
     * Check whether the given email is currently locked out.
     * @returns {{ locked: boolean, remainingMs: number }}
     */
    isLocked(email) {
        this._init();
        if (!this._ready) return { locked: false, remainingMs: 0 };
        try {
            const { getDb } = require('./db');
            const row = getDb()
                .prepare('SELECT failures, locked_until FROM account_lockouts WHERE email = ?')
                .get(email.toLowerCase());

            if (!row) return { locked: false, remainingMs: 0 };
            if (!row.locked_until) return { locked: false, remainingMs: 0 };

            const until = new Date(row.locked_until).getTime();
            const now   = Date.now();
            if (now < until) {
                return { locked: true, remainingMs: until - now };
            }
            // Lock expired — clear it
            getDb()
                .prepare('UPDATE account_lockouts SET failures = 0, locked_until = NULL WHERE email = ?')
                .run(email.toLowerCase());
            return { locked: false, remainingMs: 0 };
        } catch {
            return { locked: false, remainingMs: 0 };
        }
    }

    /**
     * Record a failed login attempt.
     * Locks the account after LOCKOUT_MAX_ATTEMPTS failures.
     */
    recordFailure(email) {
        this._init();
        if (!this._ready) return;
        try {
            const { getDb } = require('./db');
            const db  = getDb();
            const key = email.toLowerCase();

            db.prepare(`
                INSERT INTO account_lockouts (email, failures, last_attempt)
                VALUES (?, 1, datetime('now'))
                ON CONFLICT(email) DO UPDATE SET
                    failures     = failures + 1,
                    last_attempt = datetime('now')
            `).run(key);

            const row = db.prepare('SELECT failures FROM account_lockouts WHERE email = ?').get(key);
            if (row && row.failures >= LOCKOUT_MAX_ATTEMPTS) {
                const until = new Date(Date.now() + LOCKOUT_WINDOW_MS).toISOString();
                db.prepare('UPDATE account_lockouts SET locked_until = ? WHERE email = ?')
                  .run(until, key);
            }
        } catch (e) {
            console.warn('AccountLockout.recordFailure:', e.message);
        }
    }

    /**
     * Reset the failure counter after a successful login.
     */
    recordSuccess(email) {
        this._init();
        if (!this._ready) return;
        try {
            const { getDb } = require('./db');
            getDb()
                .prepare('DELETE FROM account_lockouts WHERE email = ?')
                .run(email.toLowerCase());
        } catch { /* non-fatal */ }
    }
}

const lockout = new AccountLockout();

module.exports = {
    hashPassword,
    verifyPassword,
    makeToken,
    verifyToken,
    getTokenFromReq,
    lockout,
    LOCKOUT_WINDOW_MS,
    LOCKOUT_MAX_ATTEMPTS,
};