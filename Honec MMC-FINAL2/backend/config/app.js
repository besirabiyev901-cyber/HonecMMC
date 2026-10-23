// ══════════════════════════════════════════════════════════════════
//  config/app.js
//  BUG FIX: rootDir was pointing two levels up from config/ which
//  resolves to the parent of the project root — path traversal risk.
//  Fixed to point at the actual project root (one level up from config/).
// ══════════════════════════════════════════════════════════════════

const path = require('path');

const DEFAULT_SECRET = 'honec-secret-change-in-production';
const jwtSecret = process.env.JWT_SECRET || DEFAULT_SECRET;

if (process.env.NODE_ENV === 'production' && jwtSecret === DEFAULT_SECRET) {
    console.error('FATAL: JWT_SECRET env variable must be set in production.');
    process.exit(1);
}

module.exports = {
    port:      Number(process.env.PORT) || 3000,
    jwtSecret,
    // FIX: was path.join(__dirname, '../../') — pointed OUTSIDE the project.
    // Should be one level up from config/ to reach the project root.
    rootDir:   path.resolve(__dirname, '..', '..'),
    dbPath:    process.env.DB_PATH || path.join(__dirname, '..', 'data', 'honec.db'),
    nodeEnv:   process.env.NODE_ENV || 'development',
};