import type {
  AgentSync,
  Policy,
  ServerSync,
  Command,
  Ban,
} from "../shared/protocol";
import type { Env, NodeRow } from "./env";

export async function responseFor(
  env: Env,
  node: NodeRow,
  ackEvents: string[] = [],
  ackResults: string[] = [],
): Promise<ServerSync> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    "UPDATE commands SET status='expired',completed_at=? WHERE node_id=? AND status IN ('pending','running') AND expires_at<=?",
  )
    .bind(now, node.id, now)
    .run();
  const [settings, policies, commands] = await Promise.all([
    env.DB.prepare("SELECT policy_revision FROM settings WHERE id=1").first<{
      policy_revision: number;
    }>(),
    env.DB.prepare(
      "SELECT id,ip,expires_at FROM whitelist WHERE expires_at IS NULL OR expires_at>? ORDER BY created_at",
    )
      .bind(now)
      .all<Policy>(),
    env.DB.prepare(
      "SELECT id,kind,jail,ip,expires_at FROM commands WHERE node_id=? AND status IN ('pending','running') AND expires_at>? ORDER BY created_at,id LIMIT 100",
    )
      .bind(node.id, now)
      .all<Command>(),
  ]);
  if (commands.results.length)
    await env.DB.prepare(
      `UPDATE commands SET status='running' WHERE status='pending' AND id IN (${commands.results.map(() => "?").join(",")})`,
    )
      .bind(...commands.results.map((c) => c.id))
      .run();
  return {
    protocol: 1,
    type: "sync",
    server_time: now,
    config: {
      revision: node.config_revision,
      mode: node.mode,
      poll_interval: node.poll_interval,
    },
    policy_revision: settings!.policy_revision,
    policies: policies.results,
    commands: commands.results,
    ack_event_ids: ackEvents,
    ack_result_ids: ackResults,
    snapshot_required: node.observed_at === null,
  };
}
function upsertBan(env: Env, nodeID: string, b: Ban): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO bans(node_id,jail,ip,country,city,latitude,longitude,observed_at) VALUES(?,?,?,?,?,?,?,?)
    ON CONFLICT(node_id,jail,ip) DO UPDATE SET country=excluded.country,city=excluded.city,latitude=excluded.latitude,longitude=excluded.longitude,observed_at=excluded.observed_at`,
  ).bind(
    nodeID,
    b.jail,
    b.ip,
    b.country ?? null,
    b.city ?? null,
    b.latitude ?? null,
    b.longitude ?? null,
    b.observed_at,
  );
}
// All calls for a node are serialized by its Durable Object, including across transports.
export async function ingest(
  env: Env,
  node: NodeRow,
  p: AgentSync,
  geo?: Record<string, unknown>,
): Promise<ServerSync> {
  const now = Math.floor(Date.now() / 1000);
  const sql: D1PreparedStatement[] = [];
  for (const e of [...p.events].sort((a, b) => a.seq - b.seq)) {
    sql.push(
      env.DB.prepare(
        "INSERT OR IGNORE INTO events(id,node_id,seq,kind,jail,ip,observed_at,received_at,country,city,latitude,longitude) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
      ).bind(
        e.id,
        node.id,
        e.seq,
        e.kind,
        e.jail,
        e.ip,
        e.observed_at,
        now,
        e.country ?? null,
        e.city ?? null,
        e.latitude ?? null,
        e.longitude ?? null,
      ),
    );
    if (e.seq > node.last_seq)
      sql.push(
        e.kind === "ban"
          ? upsertBan(env, node.id, e)
          : env.DB.prepare(
              "DELETE FROM bans WHERE node_id=? AND jail=? AND ip=?",
            ).bind(node.id, e.jail, e.ip),
      );
  }
  if (p.snapshot && p.snapshot.seq >= node.last_seq) {
    // A failed jail read must never erase its last known bans.
    const missing = p.snapshot.unavailable_jails;
    sql.push(
      env.DB.prepare(
        `DELETE FROM bans WHERE node_id=?${missing.length ? " AND jail NOT IN (" + missing.map(() => "?").join(",") + ")" : ""}`,
      ).bind(node.id, ...missing),
    );
    for (const j of p.snapshot.jails)
      for (const b of j.bans) sql.push(upsertBan(env, node.id, b));
  }
  for (const r of p.results)
    sql.push(
      env.DB.prepare(
        "UPDATE commands SET status=?,error=?,completed_at=? WHERE id=? AND node_id=? AND status IN ('pending','running','expired')",
      ).bind(r.status, r.error ?? null, now, r.id, node.id),
    );
  const jailNames = p.snapshot
    ? [...p.snapshot.jails.map((j) => j.name), ...p.snapshot.unavailable_jails]
    : JSON.parse(node.jails_json);
  const observed = p.snapshot || p.events.length ? now : node.observed_at;
  const g = geo ?? {};
  sql.push(
    env.DB.prepare(
      `UPDATE nodes SET last_seen=?,observed_at=?,actual_mode=?,fallback_reason=?,version=?,error=?,
    applied_config_revision=?,applied_policy_revision=?,last_seq=MAX(last_seq,?),jails_json=?,
    ip=COALESCE(?,ip),country=COALESCE(?,country),city=COALESCE(?,city),latitude=COALESCE(?,latitude),longitude=COALESCE(?,longitude) WHERE id=?`,
    ).bind(
      now,
      observed,
      p.actual_mode,
      p.fallback_reason ?? null,
      p.version,
      p.error ?? null,
      p.applied_config_revision,
      p.applied_policy_revision,
      p.sequence,
      JSON.stringify(jailNames),
      g.ip ?? null,
      g.country ?? null,
      g.city ?? null,
      g.latitude ?? null,
      g.longitude ?? null,
      node.id,
    ),
  );
  await env.DB.batch(sql);
  node = { ...node, observed_at: observed };
  return {
    ...(await responseFor(
      env,
      node,
      p.events.map((e) => e.id),
      p.results.map((r) => r.id),
    )),
    ack_snapshot_seq: p.snapshot?.seq,
  };
}

export async function notifyDashboard(env: Env): Promise<void> {
  const response = await env.DASHBOARD.get(
    env.DASHBOARD.idFromName("admin"),
  ).fetch("https://internal/notify", { method: "POST" });
  await response.arrayBuffer();
}
export async function wakeNode(
  env: Env,
  id: string,
  close = false,
): Promise<void> {
  const response = await env.NODES.get(env.NODES.idFromName(id)).fetch(
    `https://internal/${close ? "close" : "wake"}`,
    { method: "POST", headers: { "x-node-id": id } },
  );
  await response.arrayBuffer();
}
export async function wakeAll(env: Env): Promise<void> {
  const rows = await env.DB.prepare(
    "SELECT id FROM nodes WHERE enabled=1 AND token_hash IS NOT NULL",
  ).all<{ id: string }>();
  await Promise.allSettled(rows.results.map((n) => wakeNode(env, n.id)));
  await notifyDashboard(env);
}
