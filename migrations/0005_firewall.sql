CREATE TABLE firewall_groups (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 rules TEXT NOT NULL CHECK(json_valid(rules))
);
CREATE TABLE firewall_drafts (
 node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL DEFAULT 1, config TEXT NOT NULL CHECK(json_valid(config))
);
CREATE TABLE firewall_observations (
 node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 snapshot TEXT CHECK(json_valid(snapshot)),
 observed_at INTEGER NOT NULL DEFAULT 0, refresh INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE firewall_releases (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
 node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 target TEXT NOT NULL CHECK(json_valid(target)),
 status TEXT NOT NULL DEFAULT 'pending'
   CHECK(status IN ('pending','applying','applied','failed','rolled_back','superseded')),
 error TEXT, confirmed_at INTEGER, actor TEXT NOT NULL, created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, drift TEXT CHECK(json_valid(drift))
);
CREATE INDEX firewall_releases_node ON firewall_releases(node_id, sequence DESC);
CREATE TABLE firewall_revision (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL);
INSERT INTO firewall_revision VALUES (1, 1);
CREATE TRIGGER firewall_group_insert AFTER INSERT ON firewall_groups
BEGIN UPDATE firewall_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER firewall_group_update AFTER UPDATE ON firewall_groups
BEGIN UPDATE firewall_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER firewall_group_delete AFTER DELETE ON firewall_groups
BEGIN UPDATE firewall_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER firewall_draft_insert AFTER INSERT ON firewall_drafts
BEGIN UPDATE firewall_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER firewall_draft_update AFTER UPDATE ON firewall_drafts
BEGIN UPDATE firewall_revision SET revision=revision+1 WHERE id=1; END;
