CREATE TABLE integrations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT UNIQUE,
  token_prefix TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE TABLE dynamic_whitelist (
  id TEXT PRIMARY KEY,
  integration_id TEXT NOT NULL REFERENCES integrations(id),
  rule_key TEXT NOT NULL,
  ip TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  synced_at INTEGER NOT NULL,
  UNIQUE(integration_id, rule_key)
);
CREATE INDEX dynamic_whitelist_ip ON dynamic_whitelist(ip);
CREATE INDEX dynamic_whitelist_expiry ON dynamic_whitelist(expires_at);

CREATE VIEW whitelist_rules AS
SELECT id, ip, expires_at, created_at, actor, 'manual' AS source,
       NULL AS owner_id, NULL AS synced_at
FROM whitelist
UNION ALL
SELECT w.id, w.ip, w.expires_at, w.created_at, i.name AS actor,
       'integration' AS source, w.rule_key AS owner_id, w.synced_at
FROM dynamic_whitelist w JOIN integrations i ON i.id=w.integration_id
WHERE i.revoked_at IS NULL;
