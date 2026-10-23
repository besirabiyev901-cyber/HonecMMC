// ══════════════════════════════════════════════════════════════════
//  lib/http.js  –  HTTP helpers  (Security upgrade)
//
//  NEW: Helmet-equivalent header set covering the gaps flagged in
//  the security review. Notable additions:
//    • Permissions-Policy to disable powerful features
//    • Cross-Origin-Opener-Policy / Embedder-Policy / Resource-Policy
//    • Content-Security-Policy moved here so every response (API +
//      static) gets it rather than only HTML files in app.js.
//      app.js still overrides CSP per-request for HTML with a nonce.
//
//  NEW: CSRF double-submit cookie pattern via csrfMiddleware().
//    • GET/HEAD/OPTIONS are exempt.
//    • State-mutating methods (POST/PUT/PATCH/DELETE) require the
//      X-CSRF-Token header to match the __csrf cookie value.
//    • The cookie is HttpOnly=false so JS can read it; the header
//      requirement is the protection (cross-origin JS can't read
//      your cookies, so an attacker can't replicate the header).
//
//  CHANGED: readBody() already collects Buffers (previous fix).
//  CHANGED: sendJson() header merge order (previous fix).
// ══════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const MAX_BODY_BYTES = 64 * 1024; // 64 KB

const CORS_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:3000')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

// ── Security headers (Helmet-equivalent) ─────────────────────────
// Every response gets these. HTML responses additionally get a
// per-request CSP with a nonce (set in app.js buildCsp()).
const SECURITY_HEADERS = {
    // Prevent MIME sniffing
    'X-Content-Type-Options': 'nosniff',
    // Disallow framing everywhere (defence-in-depth alongside CSP frame-ancestors)
    'X-Frame-Options': 'DENY',
    // Legacy XSS filter (still respected by old IE/Edge)
    'X-XSS-Protection': '1; mode=block',
    // Limit referrer leakage
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    // No caching of API responses
    'Cache-Control': 'no-store',
    // Force HTTPS for 1 year including sub-domains
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    // Isolate the browsing context from cross-origin openers (stops
    // cross-origin window.opener attacks and is required for SharedArrayBuffer)
    'Cross-Origin-Opener-Policy': 'same-origin',
    // Prevent cross-origin embedding of this page's resources
    'Cross-Origin-Embedder-Policy': 'require-corp',
    // Prevent cross-origin reads of responses (Fetch metadata guard)
    'Cross-Origin-Resource-Policy': 'same-origin',
    // Disable browser features we don't use
    'Permissions-Policy': [
        'camera=()',
        'microphone=()',
        'geolocation=()',
        'payment=()',
        'usb=()',
        'interest-cohort=()',   // no FLoC
    ].join(', '),
    // Baseline CSP for non-HTML API responses (no inline anything)
    'Content-Security-Policy': [
        "default-src 'none'",
        "frame-ancestors 'none'",
    ].join('; '),
};

// ── CORS ──────────────────────────────────────────────────────────
function corsHeaders(req) {
    if (process.env.NODE_ENV !== 'production') {
        return {
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        };
    }
    const requestOrigin = req?.headers?.origin || '';
    const allowed = CORS_ORIGINS.includes(requestOrigin)
        ? requestOrigin
        : CORS_ORIGINS[0];
    return {
        'Access-Control-Allow-Origin':  allowed,
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Vary': 'Origin',
    };
}

// ── sendJson ──────────────────────────────────────────────────────
function sendJson(res, status, body, req = null) {
    if (res.writableEnded) return;
    const payload = JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type':   'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(payload),
        ...SECURITY_HEADERS,
        ...corsHeaders(req),
    });
    res.end(payload);
}

// ── readBody ──────────────────────────────────────────────────────
function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;

        req.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                req.destroy();
                return reject(new Error('Request body too large.'));
            }
            chunks.push(chunk);
        });

        req.on('end', () => {
            if (!chunks.length) return resolve({});
            const raw = Buffer.concat(chunks).toString('utf8');
            try { resolve(JSON.parse(raw)); }
            catch { reject(new Error('Invalid JSON body.')); }
        });

        req.on('error', reject);
    });
}

// ── CSRF double-submit cookie ─────────────────────────────────────
// Usage in routeApi: call csrfMiddleware(req, res) at the top.
// Returns false (and has already sent 403) if CSRF check fails.
// Returns true if the request is safe to proceed.
//
// The cookie __csrf is set on first GET and must be echoed back
// via X-CSRF-Token header on every state-mutating request.
// SameSite=Strict blocks cross-site form submissions outright;
// the header check is the second line of defence for same-site
// requests that may arrive from sub-domains in future.

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_COOKIE  = '__csrf';
const CSRF_TTL_MS  = 4 * 60 * 60 * 1000; // 4 hours

function parseCookies(req) {
    const raw = req.headers['cookie'] || '';
    return Object.fromEntries(
        raw.split(';').map(s => {
            const eq = s.indexOf('=');
            if (eq === -1) return [s.trim(), ''];
            return [s.slice(0, eq).trim(), s.slice(eq + 1).trim()];
        })
    );
}

function setCsrfCookie(res, token) {
    const flags = [
        `${CSRF_COOKIE}=${token}`,
        'Path=/',
        // Not HttpOnly — JS needs to read this to put it in the header
        'SameSite=Strict',
        `Max-Age=${CSRF_TTL_MS / 1000}`,
        // Only set Secure in production (localhost has no TLS)
        ...(process.env.NODE_ENV === 'production' ? ['Secure'] : []),
    ].join('; ');
    // Append — don't clobber existing Set-Cookie headers
    const existing = res.getHeader('Set-Cookie');
    if (existing) {
        res.setHeader('Set-Cookie', Array.isArray(existing)
            ? [...existing, flags]
            : [existing, flags]);
    } else {
        res.setHeader('Set-Cookie', flags);
    }
}

/**
 * Enforce CSRF protection.
 * @returns {string|false} The CSRF token if the request is allowed,
 *                         or false if a 403 was already sent.
 */
function csrfMiddleware(req, res) {
    const cookies = parseCookies(req);
    const method  = req.method.toUpperCase();

    // Always refresh / issue the token on safe methods
    if (SAFE_METHODS.has(method)) {
        let token = cookies[CSRF_COOKIE];
        if (!token || token.length < 32) {
            token = crypto.randomBytes(24).toString('hex');
            setCsrfCookie(res, token);
        }
        return token;
    }

    // State-mutating request: token must exist and match header
    const cookieToken  = cookies[CSRF_COOKIE];
    const headerToken  = req.headers['x-csrf-token'] || '';

    if (!cookieToken || !headerToken) {
        sendJson(res, 403, { error: 'CSRF token missing.' }, req);
        return false;
    }

    // Constant-time compare to prevent timing attacks
    const cookieBuf = Buffer.from(cookieToken);
    const headerBuf = Buffer.from(headerToken);
    if (cookieBuf.length !== headerBuf.length ||
        !crypto.timingSafeEqual(cookieBuf, headerBuf)) {
        sendJson(res, 403, { error: 'CSRF token invalid.' }, req);
        return false;
    }

    return cookieToken;
}

module.exports = {
    sendJson,
    readBody,
    corsHeaders,
    csrfMiddleware,
    SECURITY_HEADERS,
};