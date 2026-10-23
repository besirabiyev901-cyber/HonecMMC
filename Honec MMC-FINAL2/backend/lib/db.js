// ══════════════════════════════════════════════════════════════════
//  lib/db.js  –  SQLite database  (Security upgrade)
//
//  NEW: account_lockouts table added to ensureDatabase().
//    Stores persistent login failure state so lockouts survive
//    server restarts (see lib/auth.js AccountLockout).
//
//  KEPT: single closeDb() point, WAL mode, foreign keys ON,
//        all previous tables unchanged.
// ══════════════════════════════════════════════════════════════════

const fs     = require('fs');
const path   = require('path');
const config = require('../config/app');

let db;

function getDb() {
    if (db) return db;
    try {
        const Database = require('better-sqlite3');
        const dir = path.dirname(config.dbPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        db = new Database(config.dbPath);

        db.pragma('journal_mode = WAL');
        db.pragma('foreign_keys = ON');
        db.pragma('synchronous = NORMAL');
        db.pragma('temp_store = MEMORY');
        db.pragma('mmap_size = 268435456');   // 256 MB

        return db;
    } catch (e) {
        console.error('DB init failed:', e.message);
        throw e;
    }
}

function ensureDatabase() {
    const db = getDb();
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT    NOT NULL CHECK(length(name)  BETWEEN 1 AND 120),
            email     TEXT    NOT NULL UNIQUE CHECK(length(email) <= 254),
            password  TEXT    NOT NULL,
            role      TEXT    NOT NULL DEFAULT 'user'
                            CHECK(role IN ('admin','moderator','user')),
            created   TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT    NOT NULL CHECK(length(name)    <= 120),
            email     TEXT    NOT NULL CHECK(length(email)   <= 254),
            subject   TEXT    NOT NULL CHECK(length(subject) <= 200),
            message   TEXT    NOT NULL CHECK(length(message) <= 5000),
            created   TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS newsletters (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            email   TEXT NOT NULL UNIQUE CHECK(length(email) <= 254),
            created TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
            title       TEXT    NOT NULL CHECK(length(title)       BETWEEN 1 AND 300),
            description TEXT    NOT NULL CHECK(length(description) BETWEEN 1 AND 10000),
            image_url   TEXT,
            video_url   TEXT,
            link_url    TEXT,
            link_label  TEXT    CHECK(length(link_label) <= 100),
            published   INTEGER NOT NULL DEFAULT 1 CHECK(published IN (0,1)),
            created     TEXT    NOT NULL DEFAULT (datetime('now')),
            updated     TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS post_files (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            name       TEXT    NOT NULL CHECK(length(name) BETWEEN 1 AND 200),
            url        TEXT    NOT NULL,
            type       TEXT    NOT NULL DEFAULT 'file' CHECK(type IN ('file','link')),
            created    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS post_comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER NOT NULL REFERENCES posts(id)    ON DELETE CASCADE,
            author_id  INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
            content    TEXT    NOT NULL CHECK(length(content) BETWEEN 1 AND 1000),
            created    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS post_likes (
            post_id    INTEGER NOT NULL REFERENCES posts(id)    ON DELETE CASCADE,
            user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
            created    TEXT    NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (post_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS logs (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            level   TEXT NOT NULL,
            event   TEXT NOT NULL,
            data    TEXT,
            created TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- NEW: persistent login failure / lockout tracking.
        -- Survives server restarts unlike the in-process rate limiter.
        -- Managed exclusively via lib/auth.js AccountLockout class.
        CREATE TABLE IF NOT EXISTS account_lockouts (
            email        TEXT    PRIMARY KEY,
            failures     INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            last_attempt TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_users_email           ON users(email);
        CREATE INDEX IF NOT EXISTS idx_messages_created      ON messages(created DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_created          ON logs(created DESC);
        CREATE INDEX IF NOT EXISTS idx_lockouts_locked_until ON account_lockouts(locked_until);
        CREATE INDEX IF NOT EXISTS idx_posts_created         ON posts(created DESC);
        CREATE INDEX IF NOT EXISTS idx_posts_author          ON posts(author_id);
        CREATE INDEX IF NOT EXISTS idx_post_files_post       ON post_files(post_id);
        CREATE INDEX IF NOT EXISTS idx_post_comments_post    ON post_comments(post_id);
        CREATE INDEX IF NOT EXISTS idx_post_comments_author  ON post_comments(author_id);
        CREATE INDEX IF NOT EXISTS idx_post_likes_post       ON post_likes(post_id);
    `);

    console.log('✅ Database ready at', config.dbPath);
}

function closeDb() {
    try { db?.close(); db = undefined; } catch (_) {}
}

process.on('exit', closeDb);

module.exports = { getDb, ensureDatabase, closeDb };