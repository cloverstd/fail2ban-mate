PRAGMA foreign_keys = ON;
CREATE TABLE nodes (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
 token_hash TEXT UNIQUE, enroll_hash TEXT UNIQUE, enroll_expires INTEGER,
 mode TEXT NOT NULL DEFAULT 'websocket' CHECK(mode IN ('websocket','polling')),
 poll_interval INTEGER NOT NULL DEFAULT 30 CHECK(poll_interval BETWEEN 5 AND 300),
 config_revision INTEGER NOT NULL DEFAULT 1, applied_config_revision INTEGER NOT NULL DEFAULT 0,
 applied_policy_revision INTEGER NOT NULL DEFAULT 0, last_seq INTEGER NOT NULL DEFAULT 0,
 last_seen INTEGER, observed_at INTEGER, actual_mode TEXT, fallback_reason TEXT,
 version TEXT, error TEXT, jails_json TEXT NOT NULL DEFAULT '[]',
 ip TEXT, country TEXT, city TEXT, latitude REAL, longitude REAL, created_at INTEGER NOT NULL
);
CREATE TABLE bans (
 node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, jail TEXT NOT NULL, ip TEXT NOT NULL,
 country TEXT, city TEXT, latitude REAL, longitude REAL, observed_at INTEGER NOT NULL,
 PRIMARY KEY(node_id,jail,ip)
);
CREATE INDEX bans_observed ON bans(observed_at DESC);
CREATE TABLE events (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 seq INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('ban','unban')),
 jail TEXT NOT NULL, ip TEXT NOT NULL, observed_at INTEGER NOT NULL,
 received_at INTEGER NOT NULL, country TEXT, city TEXT, latitude REAL, longitude REAL
);
CREATE INDEX events_node_time ON events(node_id,received_at DESC);
CREATE INDEX events_retention ON events(received_at);
CREATE TABLE commands (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('ban','unban')), jail TEXT NOT NULL, ip TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','succeeded','failed','expired')),
 error TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER, actor TEXT NOT NULL
);
CREATE INDEX commands_delivery ON commands(node_id,status,expires_at);
CREATE INDEX commands_retention ON commands(created_at);
CREATE TABLE whitelist (id TEXT PRIMARY KEY, ip TEXT NOT NULL UNIQUE, expires_at INTEGER, created_at INTEGER NOT NULL, actor TEXT NOT NULL);
CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), policy_revision INTEGER NOT NULL DEFAULT 1);
INSERT INTO settings(id) VALUES (1);
CREATE TABLE audit (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX audit_time ON audit(created_at DESC);
