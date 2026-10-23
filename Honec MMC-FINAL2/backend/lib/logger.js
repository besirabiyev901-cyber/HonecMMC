// ══════════════════════════════════════════════════════════════════
//  lib/logger.js
//  Sensitive fields redacted before disk/DB writes.
//  readLogs returns newest-first with sane default limit.
// ══════════════════════════════════════════════════════════════════

const fs   = require('fs');
const path = require('path');

const LOG_DIR  = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(LOG_DIR, 'honec.log');

const REDACT_KEYS = new Set(['password', 'token', 'secret', 'authorization']);

function redact(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
        if (REDACT_KEYS.has(k.toLowerCase())) {
            out[k] = '[REDACTED]';
        } else if (k.toLowerCase() === 'email' && typeof v === 'string') {
            const [local, domain] = v.split('@');
            out[k] = local ? `${local[0]}***@${domain || '?'}` : '[REDACTED]';
        } else {
            out[k] = v;
        }
    }
    return out;
}

function writeLog(level, event, data = {}) {
    try {
        const safeData = redact(data);
        if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
        const line = JSON.stringify({
            ts: new Date().toISOString(),
            level,
            event,
            ...safeData,
        }) + '\n';
        fs.appendFileSync(LOG_FILE, line);

        try {
            const { getDb } = require('./db');
            getDb()
                .prepare('INSERT INTO logs (level, event, data) VALUES (?, ?, ?)')
                .run(level, event, JSON.stringify(safeData));
        } catch (_) { /* db may not be ready yet */ }
    } catch (_) { /* never crash on logging */ }
}

function readLogs(limit = 50) {
    try {
        const { getDb } = require('./db');
        return getDb()
            .prepare('SELECT * FROM logs ORDER BY id DESC LIMIT ?')
            .all(limit);
    } catch (_) { return []; }
}

module.exports = { writeLog, readLogs };