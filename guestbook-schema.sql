CREATE TABLE IF NOT EXISTS guestbook (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 message TEXT NOT NULL,
 ip_hash TEXT,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS guestbook_recent_idx ON guestbook (id DESC);
CREATE INDEX IF NOT EXISTS guestbook_rate_idx ON guestbook (ip_hash, created_at);
