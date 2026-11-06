CREATE TABLE ban_history (
 id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 jail TEXT NOT NULL, ip TEXT NOT NULL,
 country TEXT, city TEXT, latitude REAL, longitude REAL,
 observed_at INTEGER NOT NULL, unbanned_at INTEGER NOT NULL
);
CREATE INDEX ban_history_observed ON ban_history(observed_at DESC);
CREATE INDEX ban_history_retention ON ban_history(unbanned_at);
CREATE INDEX ban_history_period ON ban_history(node_id,jail,ip,observed_at);
CREATE INDEX events_ban_sequence ON events(node_id,jail,ip,seq);

-- Recover completed periods from retained events. Sequence, rather than wall
-- clock time, determines the order of changes reported by each node.
INSERT INTO ban_history
 (id,node_id,jail,ip,country,city,latitude,longitude,observed_at,unbanned_at)
SELECT 'event:'||e.id,e.node_id,e.jail,e.ip,e.country,e.city,e.latitude,e.longitude,
 e.observed_at,COALESCE(e.next_at,n.observed_at,e.received_at)
FROM (
 SELECT events.*,
  LEAD(observed_at) OVER (PARTITION BY node_id,jail,ip ORDER BY seq,id) AS next_at
 FROM events
) e JOIN nodes n ON n.id=e.node_id
WHERE e.kind='ban' AND (
 e.next_at IS NOT NULL OR NOT EXISTS (
  SELECT 1 FROM bans b WHERE b.node_id=e.node_id AND b.jail=e.jail
   AND b.ip=e.ip AND b.observed_at=e.observed_at
 )
);
