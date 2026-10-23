// ══════════════════════════════════════════════════════════════════
//  server.js
//  BUG FIX: db.js had its own SIGINT/SIGTERM handlers that called
//  process.exit() independently of server.close(), meaning in-flight
//  requests could be cut off before the server finished draining.
//  Those handlers are removed from db.js; closeDb() is called here
//  after server.close() completes.
// ══════════════════════════════════════════════════════════════════

const http   = require('http');
const config = require('./config/app');
const { ensureDatabase, closeDb } = require('./lib/db');
const { writeLog }                = require('./lib/logger');
const { handleRequest }           = require('./app');

ensureDatabase();

const server = http.createServer(handleRequest);
let currentPort = config.port;

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`⚠️  Port ${currentPort} busy – trying ${currentPort + 1}…`);
        currentPort += 1;
        server.listen(currentPort);
    } else {
        writeLog('error', 'server_error', { error: err.message });
        console.error('Server error:', err);
        process.exit(1);
    }
});

server.listen(currentPort, () => {
    const env = config.nodeEnv;
    writeLog('info', 'server_started', { port: currentPort, env });
    console.log(`✅ Honec backend [${env}] → http://localhost:${currentPort}`);
    if (env !== 'production') {
        console.log('   Set NODE_ENV=production and JWT_SECRET for a hardened build.');
    }
});

// ── Graceful shutdown ──────────────────────────────────────────────
function shutdown(signal) {
    console.log(`\n🛑 ${signal} received – shutting down…`);
    writeLog('info', 'server_stopped', { signal });
    server.close(() => {
        console.log('✅ Server closed.');
        // FIX: close DB only after all connections are drained.
        closeDb();
        process.exit(0);
    });
    setTimeout(() => { closeDb(); process.exit(1); }, 10_000).unref();
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));