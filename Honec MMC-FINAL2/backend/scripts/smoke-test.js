const http = require('http');
const config = require('../config/app');

const BASE = `http://localhost:${config.port}`;

async function get(path) {
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
        const r = await get('/');
        console.log(`GET /  → ${r.status}`);
        const r2 = await get('/api/me');
        console.log(`GET /api/me → ${r2.status}`);
        console.log('✅ Smoke test passed.');
    } catch (e) {
        console.error('❌ Smoke test failed:', e.message);
        process.exit(1);
    }
})();
