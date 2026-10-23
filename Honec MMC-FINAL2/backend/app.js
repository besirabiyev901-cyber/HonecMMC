// ══════════════════════════════════════════════════════════════════
//  app.js  –  Request dispatcher  (Security upgrade)
//
//  CHANGED: serveStatic() now calls csrfMiddleware() on every GET
//    for HTML files. This seeds the __csrf cookie so that the
//    front-end JS can read it and attach X-CSRF-Token on POST.
//    (csrfMiddleware on GET is a no-op guard — it only issues the
//    cookie if one doesn't already exist.)
//
//  CHANGED: buildCsp() tightened further:
//    • connect-src now explicitly allows only the known Supabase
//      project URL rather than the wildcard *.supabase.co.
//      Wildcards are convenient but allow any Supabase project.
//    • base-uri 'none' instead of 'self' — prevents <base> injection.
//    • upgrade-insecure-requests added for HTTPS enforcement.
//    • Reflected the new lib/http.js header layout (CSP for API
//      responses is now handled there; this only sets it for HTML).
//
//  KEPT: path.resolve() traversal fix, nonce injection, MIME table.
// ══════════════════════════════════════════════════════════════════

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const config  = require('./config/app');
const { routeApi }  = require('./routes/api');
const { sendJson, SECURITY_HEADERS, csrfMiddleware } = require('./lib/http');
const { writeLog }  = require('./lib/logger');

const MIME = {
    '.html':  'text/html; charset=utf-8',
    '.css':   'text/css; charset=utf-8',
    '.js':    'application/javascript; charset=utf-8',
    '.mjs':   'application/javascript; charset=utf-8',
    '.svg':   'image/svg+xml',
    '.png':   'image/png',
    '.jpg':   'image/jpeg',
    '.jpeg':  'image/jpeg',
    '.ico':   'image/x-icon',
    '.json':  'application/json; charset=utf-8',
    '.webp':  'image/webp',
    '.woff2': 'font/woff2',
    '.woff':  'font/woff',
    '.ttf':   'font/ttf',
    '.pdf':   'application/pdf',
};

// Supabase project URL read from env (falls back to the placeholder).
// Set SUPABASE_URL in production to restrict connect-src precisely.
const SUPABASE_URL = (process.env.SUPABASE_URL || 'https://*.supabase.co').replace(/\/$/, '');

function buildCsp(nonce) {
    return [
        "default-src 'self'",
        // Only trust our own scripts + the CDN used by main.js
        `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net`,
        // No inline styles — use external sheets only
        "style-src 'self' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        // data: for inline images; https: is broad but acceptable for img
        "img-src 'self' data: https:",
        // Restrict fetch/XHR to our origin + known Supabase project
        `connect-src 'self' ${SUPABASE_URL} wss://${new URL(SUPABASE_URL).hostname}`,
        // YouTube embeds only
        "frame-src https://www.youtube.com",
        // Disallow Flash, Java applets, etc.
        "object-src 'none'",
        // <base> injection prevention — stricter than 'self'
        "base-uri 'none'",
        // Disallow framing (redundant with X-Frame-Options but belt-and-suspenders)
        "frame-ancestors 'none'",
        // Upgrade mixed HTTP sub-resources to HTTPS automatically
        "upgrade-insecure-requests",
    ].join('; ');
}

function serveStatic(req, res, pathname) {
    const decoded   = decodeURIComponent(pathname === '/' ? '/index.html' : pathname);
    const candidate = path.resolve(config.rootDir, '.' + decoded);
    const rootDir   = config.rootDir;

    if (!candidate.startsWith(rootDir + path.sep) && candidate !== rootDir) {
        res.writeHead(403, { 'Content-Type': 'text/plain', ...SECURITY_HEADERS });
        return res.end('Forbidden');
    }

    let real;
    try {
        real = fs.realpathSync(candidate);
    } catch {
        res.writeHead(404, { 'Content-Type': 'text/plain', ...SECURITY_HEADERS });
        return res.end('Not found');
    }

    if (!real.startsWith(rootDir + path.sep) && real !== rootDir) {
        res.writeHead(403, { 'Content-Type': 'text/plain', ...SECURITY_HEADERS });
        return res.end('Forbidden');
    }

    fs.readFile(real, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain', ...SECURITY_HEADERS });
            return res.end('Not found');
        }
        const ext      = path.extname(real).toLowerCase();
        const mimeType = MIME[ext] || 'application/octet-stream';
        const headers  = { 'Content-Type': mimeType, ...SECURITY_HEADERS };

        if (ext === '.html') {
            const nonce = crypto.randomBytes(16).toString('base64');
            headers['Content-Security-Policy'] = buildCsp(nonce);

            // Seed the CSRF cookie on every HTML page load so the
            // front-end always has a fresh token to attach to XHR.
            csrfMiddleware(req, res);
        }

        res.writeHead(200, headers);
        res.end(data);
    });
}

async function handleRequest(req, res) {
    const started  = Date.now();
    const url      = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const cfRay    = req.headers['cf-ray'] || null;

    try {
        if (pathname.startsWith('/api/')) {
            await routeApi(req, res, pathname);
        } else {
            serveStatic(req, res, pathname);
        }
    } catch (err) {
        writeLog('error', 'request_failed', {
            method: req.method,
            pathname,
            cfRay,
            error: err.message,
        });
        const status = err.message === 'Invalid JSON body.'      ? 400
                    : err.message === 'Request body too large.' ? 413
                    : 500;
        if (!res.writableEnded) {
            sendJson(res, status, { error: err.message || 'Server error.' });
        }
    } finally {
        if (pathname.startsWith('/api/')) {
            writeLog('info', 'api_request', {
                method:   req.method,
                pathname,
                ms:       Date.now() - started,
                cfRay,
            });
        }
    }
}

module.exports = { handleRequest };