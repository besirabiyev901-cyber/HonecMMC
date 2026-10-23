// ══════════════════════════════════════════════════════════════════
//  lib/rateLimit.js  –  In-process sliding-window rate limiter
//  Reads CF-Connecting-IP (Cloudflare real IP) first, then
//  X-Forwarded-For, then socket address.
// ══════════════════════════════════════════════════════════════════

const { sendJson } = require('./http');

function getClientIp(req) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return cf.trim();

    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();

    return req.socket?.remoteAddress || 'unknown';
}

function createLimiter({ windowMs = 60_000, max = 20, message = 'Too many requests. Try again later.' } = {}) {
    const store = new Map();

    setInterval(() => {
        const cutoff = Date.now() - windowMs;
        for (const [ip, times] of store) {
            const trimmed = times.filter(t => t > cutoff);
            if (trimmed.length === 0) store.delete(ip);
            else store.set(ip, trimmed);
        }
    }, Math.max(windowMs, 60_000)).unref();

    function check(req, res) {
        const ip     = getClientIp(req);
        const now    = Date.now();
        const cutoff = now - windowMs;

        let times = (store.get(ip) || []).filter(t => t > cutoff);
        if (times.length >= max) {
            sendJson(res, 429, { error: message }, req);
            return false;
        }
        times.push(now);
        store.set(ip, times);
        return true;
    }

    return { check };
}

module.exports = { createLimiter, getClientIp };