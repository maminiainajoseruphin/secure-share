CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    max_views INTEGER,
    views_remaining INTEGER
);
