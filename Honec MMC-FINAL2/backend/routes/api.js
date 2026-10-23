// ══════════════════════════════════════════════════════════════════
//  routes/api.js  (Security upgrade)
//
//  NEW: CSRF protection via csrfMiddleware().
//    Every non-OPTIONS, state-mutating request (POST/DELETE) now
//    goes through csrfMiddleware() before any logic runs.
//    The middleware returns false and sends 403 automatically if
//    the token is missing or wrong. Callers just check the return.
//
//  NEW: Persistent account lockout integrated into /api/login.
//    Uses lockout.isLocked() / .recordFailure() / .recordSuccess()
//    from lib/auth.js instead of the in-process authLimiter alone.
//    Both defences co-exist:
//      • authLimiter  — rate-limits by IP (short burst protection).
//      • lockout      — locks by email after N failures (persistent,
//                       survives restarts, targeted at credential
//                       stuffing against a specific account).
//
//  KEPT: all previous bug fixes (dummyHash, requireAdmin guard,
//        parseSegmentId trailing-slash fix).
// ══════════════════════════════════════════════════════════════════

const { sendJson, readBody, corsHeaders, csrfMiddleware }
                                            = require('../lib/http');
const { getDb }                              = require('../lib/db');
const {
    hashPassword, verifyPassword, makeToken, verifyToken, getTokenFromReq,
    lockout, LOCKOUT_WINDOW_MS,
}                                            = require('../lib/auth');
const { writeLog, readLogs }                 = require('../lib/logger');
const { createLimiter }                      = require('../lib/rateLimit');
const crypto                                 = require('crypto');

const authLimiter  = createLimiter({ windowMs: 60_000, max: 10,
    message: 'Too many authentication attempts. Wait a minute.' });
const writeLimiter = createLimiter({ windowMs: 60_000, max: 30 });

// ── Validators ────────────────────────────────────────────────────
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(email) {
    return typeof email === 'string' && EMAIL_RE.test(email) && email.length <= 254;
}

function validateLength(val, min, max) {
    return typeof val === 'string' && val.length >= min && val.length <= max;
}

function parseSegmentId(pathname) {
    const seg = pathname.split('/').pop();
    if (!seg) return NaN;
    const id = parseInt(seg, 10);
    return Number.isInteger(id) && id > 0 ? id : NaN;
}

// ── Route handler ─────────────────────────────────────────────────
async function routeApi(req, res, pathname) {
    const method = req.method.toUpperCase();

    if (method === 'OPTIONS') {
        res.writeHead(204, { ...corsHeaders(req) });
        return res.end();
    }

    // ── CSRF check (all state-mutating API requests) ───────────────
    // csrfMiddleware() returns false and sends 403 on failure.
    // It returns the token string on success.
    // Exempt: OPTIONS (handled above), GET/HEAD (no state mutation).
    if (!['GET', 'HEAD'].includes(method)) {
        const csrfOk = csrfMiddleware(req, res);
        if (csrfOk === false) return;
    }

    // ── POST /api/register ─────────────────────────────────────────
    if (pathname === '/api/register' && method === 'POST') {
        if (!authLimiter.check(req, res)) return;

        const body = await readBody(req);
        const { name, email, password } = body;

        if (!validateLength(name, 1, 120))
            return sendJson(res, 400, { error: 'Name must be 1–120 characters.' }, req);
        if (!validateEmail(email))
            return sendJson(res, 400, { error: 'Invalid email address.' }, req);
        if (!validateLength(password, 6, 128))
            return sendJson(res, 400, { error: 'Password must be 6–128 characters.' }, req);

        const db     = getDb();
        const count  = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
        const role   = count === 0 ? 'admin' : 'user';
        const hashed = hashPassword(password);

        try {
            db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
                .run(name.trim(), email.toLowerCase().trim(), hashed, role);
        } catch (e) {
            if (e.message.includes('UNIQUE'))
                return sendJson(res, 409, { error: 'Email already registered.' }, req);
            throw e;
        }

        const user  = db.prepare('SELECT id, name, email, role FROM users WHERE email = ?')
                        .get(email.toLowerCase().trim());
        const token = makeToken({ id: user.id, email: user.email, role: user.role });
        writeLog('info', 'user_registered', { email: user.email, role });
        return sendJson(res, 201, { token, user }, req);
    }

    // ── POST /api/login ────────────────────────────────────────────
    if (pathname === '/api/login' && method === 'POST') {
        if (!authLimiter.check(req, res)) return;

        const body = await readBody(req);
        const { email, password } = body;

        if (!email || !password)
            return sendJson(res, 400, { error: 'Email and password required.' }, req);

        const normalizedEmail = (email || '').toLowerCase().trim();

        // NEW: persistent lockout check (survives restarts)
        const { locked, remainingMs } = lockout.isLocked(normalizedEmail);
        if (locked) {
            const mins = Math.ceil(remainingMs / 60_000);
            writeLog('warn', 'login_locked', { email: normalizedEmail });
            return sendJson(res, 429, {
                error: `Account temporarily locked. Try again in ${mins} minute${mins !== 1 ? 's' : ''}.`,
            }, req);
        }

        const db   = getDb();
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);

        // Dummy hash — valid "saltHex:hashHex" format so PBKDF2 doesn't throw.
        const dummySalt = crypto.randomBytes(32).toString('hex');
        const dummyKey  = crypto.randomBytes(64).toString('hex');
        const dummyHash = `${dummySalt}:${dummyKey}`;

        const valid = user
            ? verifyPassword(password, user.password)
            : verifyPassword(password, dummyHash);

        if (!user || !valid) {
            // Only record failure for real accounts (to avoid
            // locking non-existent accounts via enumeration)
            if (user) {
                lockout.recordFailure(normalizedEmail);
                writeLog('warn', 'login_failed', { email: normalizedEmail });
            }
            return sendJson(res, 401, { error: 'Invalid email or password.' }, req);
        }

        // Successful login — clear failure count
        lockout.recordSuccess(normalizedEmail);

        const token = makeToken({ id: user.id, email: user.email, role: user.role });
        writeLog('info', 'user_login', { email: user.email });
        return sendJson(res, 200, {
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role },
        }, req);
    }

    // ── POST /api/contact ──────────────────────────────────────────
    if (pathname === '/api/contact' && method === 'POST') {
        if (!writeLimiter.check(req, res)) return;

        const { name, email, subject, message } = await readBody(req);
        if (!validateLength(name, 1, 120))     return sendJson(res, 400, { error: 'Name required (max 120 chars).' }, req);
        if (!validateEmail(email))             return sendJson(res, 400, { error: 'Invalid email.' }, req);
        if (!validateLength(subject, 1, 200))  return sendJson(res, 400, { error: 'Subject required (max 200 chars).' }, req);
        if (!validateLength(message, 1, 5000)) return sendJson(res, 400, { error: 'Message required (max 5000 chars).' }, req);

        getDb().prepare('INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)')
                .run(name.trim(), email.trim(), subject.trim(), message.trim());
        writeLog('info', 'contact_message', { email });
        return sendJson(res, 201, { ok: true }, req);
    }

    // ── POST /api/newsletter ───────────────────────────────────────
    if (pathname === '/api/newsletter' && method === 'POST') {
        if (!writeLimiter.check(req, res)) return;

        const { email } = await readBody(req);
        if (!validateEmail(email)) return sendJson(res, 400, { error: 'Valid email required.' }, req);
        try {
            getDb().prepare('INSERT INTO newsletters (email) VALUES (?)')
                    .run(email.toLowerCase().trim());
        } catch (e) {
            if (e.message.includes('UNIQUE'))
                return sendJson(res, 200, { ok: true, note: 'Already subscribed.' }, req);
            throw e;
        }
        return sendJson(res, 201, { ok: true }, req);
    }

    // ── GET /api/me ────────────────────────────────────────────────
    if (pathname === '/api/me' && method === 'GET') {
        const payload = verifyToken(getTokenFromReq(req));
        if (!payload) return sendJson(res, 401, { error: 'Not logged in.' }, req);
        const user = getDb()
            .prepare('SELECT id, name, email, role FROM users WHERE id = ?')
            .get(payload.id);
        if (!user) return sendJson(res, 401, { error: 'User not found.' }, req);
        return sendJson(res, 200, user, req);
    }

    // ── Admin guard ────────────────────────────────────────────────
    function requireAdmin() {
        if (res.writableEnded) return null;
        const payload = verifyToken(getTokenFromReq(req));
        if (!payload || payload.role !== 'admin') {
            sendJson(res, 403, { error: 'Admin access required.' }, req);
            return null;
        }
        return payload;
    }

    // ── GET /api/messages ──────────────────────────────────────────
    if (pathname === '/api/messages' && method === 'GET') {
        if (!requireAdmin()) return;
        const rows = getDb()
            .prepare('SELECT * FROM messages ORDER BY id DESC LIMIT 100')
            .all();
        return sendJson(res, 200, rows, req);
    }

    // ── DELETE /api/messages/:id ───────────────────────────────────
    if (pathname.startsWith('/api/messages/') && method === 'DELETE') {
        if (!requireAdmin()) return;
        const id = parseSegmentId(pathname);
        if (isNaN(id)) return sendJson(res, 400, { error: 'Invalid id.' }, req);
        getDb().prepare('DELETE FROM messages WHERE id = ?').run(id);
        return sendJson(res, 200, { ok: true }, req);
    }

    // ── GET /api/users ─────────────────────────────────────────────
    if (pathname === '/api/users' && method === 'GET') {
        if (!requireAdmin()) return;
        const rows = getDb()
            .prepare('SELECT id, name, email, role, created FROM users ORDER BY id')
            .all();
        return sendJson(res, 200, rows, req);
    }

    // ── DELETE /api/users/:id ──────────────────────────────────────
    if (pathname.startsWith('/api/users/') && method === 'DELETE') {
        const admin = requireAdmin();
        if (!admin) return;
        const id = parseSegmentId(pathname);
        if (isNaN(id)) return sendJson(res, 400, { error: 'Invalid id.' }, req);
        if (Number(id) === Number(admin.id))
            return sendJson(res, 400, { error: 'Cannot delete your own account.' }, req);
        getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
        writeLog('info', 'user_deleted', { target_id: id, by: admin.id });
        return sendJson(res, 200, { ok: true }, req);
    }

    // ── GET /api/newsletter ────────────────────────────────────────
    if (pathname === '/api/newsletter' && method === 'GET') {
        if (!requireAdmin()) return;
        const rows = getDb()
            .prepare('SELECT id, email, created FROM newsletters ORDER BY id DESC LIMIT 500')
            .all();
        return sendJson(res, 200, rows, req);
    }

    // ── GET /api/logs ──────────────────────────────────────────────
    if (pathname === '/api/logs' && method === 'GET') {
        if (!requireAdmin()) return;
        return sendJson(res, 200, readLogs(80), req);
    }

    // ── 404 ────────────────────────────────────────────────────────
    return sendJson(res, 404, { error: 'API route not found.' }, req);
}

module.exports = { routeApi };