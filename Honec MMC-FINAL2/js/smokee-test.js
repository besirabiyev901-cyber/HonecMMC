// ══════════════════════════════════════════════════════════════════
//  smoke-test.js
//  BUG FIX: required '../config/app' but the test lives in the project
//  root, not a subdirectory. Changed to './config/app'.
// ══════════════════════════════════════════════════════════════════

const http   = require('http');
const config = require('./config/app');   // FIX: was '../config/app'

const BASE = `http://localhost:${config.port}`;

function get(path) {
    return new Promise((resolve, reject) => {
        http.get(BASE + path, res => {
            let body = '';
            res.on('data', d => body += d);
            res.on('end', () => resolve({ status: res.statusCode, body }));
        }).on('error', reject);
    });
}

(async () => {
    try {
        const r  = await get('/');
        console.log(`GET /       → ${r.status}`);

        const r2 = await get('/api/me');
        console.log(`GET /api/me → ${r2.status}`);

        // Expect 401 for /api/me without a token
        if (r2.status !== 401) {
            console.error(`❌ Expected 401 on /api/me, got ${r2.status}`);
            process.exit(1);
        }

        const r3 = await get('/api/nonexistent');
        console.log(`GET /api/nonexistent → ${r3.status}`);
        if (r3.status !== 404) {
            console.error(`❌ Expected 404 on unknown route, got ${r3.status}`);
            process.exit(1);
        }

        console.log('✅ Smoke test passed.');
    } catch (e) {
        console.error('❌ Smoke test failed:', e.message);
        process.exit(1);
    }
})();