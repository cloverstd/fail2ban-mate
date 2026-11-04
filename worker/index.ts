import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";
import type { Env, NodeRow } from "./env";
import { admin, agent, hash, secret, sameOrigin } from "./auth";
import {
  createNodeSchema,
  updateNodeSchema,
  commandSchema,
  whitelistSchema,
} from "./validation";
import { maskIP } from "./privacy";
import { connectingAddress, nodeAddresses, splitAddress } from "./addresses";
import { notifyDashboard, wakeNode, wakeAll } from "./sync";
export { NodeConnection, Dashboard } from "./connections";

type AppEnv = { Bindings: Env; Variables: { actor: string; authExp: number } };
const app = new Hono<AppEnv>();
const now = () => Math.floor(Date.now() / 1000);
async function audit(env: Env, actor: string, action: string, detail: unknown) {
  await env.DB.prepare(
    "INSERT INTO audit(id,actor,action,detail,created_at) VALUES(?,?,?,?,?)",
  )
    .bind(crypto.randomUUID(), actor, action, JSON.stringify(detail), now())
    .run();
}
async function enrollment(env: Env, id: string) {
  const code = secret();
  await env.DB.prepare(
    "UPDATE nodes SET enroll_hash=?,enroll_expires=? WHERE id=?",
  )
    .bind(await hash(code), now() + 600, id)
    .run();
  return code;
}
function nodeView(n: NodeRow) {
  const {
    token_hash,
    enroll_hash: _enroll,
    enroll_expires: _expires,
    ...rest
  } = n as NodeRow & { enroll_hash?: string; enroll_expires?: number };
  return {
    ...rest,
    ...nodeAddresses(n),
    jails: JSON.parse(n.jails_json),
    has_token: !!token_hash,
    online:
      !!n.enabled &&
      !!token_hash &&
      !!n.last_seen &&
      n.last_seen > now() - Math.max(180, n.poll_interval * 3),
  };
}
app.use("*", async (c, next) => {
  if (Number(c.req.header("content-length") ?? 0) > 8 * 1024 * 1024)
    return c.json({ error: "请求过大" }, 413);
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "same-origin");
  if (c.req.path.startsWith("/api/") && !c.req.path.startsWith("/api/public/"))
    c.header("Cache-Control", "no-store");
});
app.onError((e, c) => {
  if (e instanceof HTTPException) return c.json({ error: e.message }, e.status);
  if (e instanceof z.ZodError)
    return c.json({ error: "参数无效", issues: e.issues }, 400);
  if (e instanceof SyntaxError) return c.json({ error: "JSON 无效" }, 400);
  // Do not echo SQL, credentials, or private request bodies.
  console.error("Request failed", e.name);
  return c.json({ error: "服务器处理失败，请检查 Workers 日志" }, 500);
});
app.use("/admin", async (c, next) => {
  const a = await admin(c.req.raw, c.env);
  if (!a)
    return c.text("请通过 Cloudflare Access 使用授权的 GitHub 账号登录。", 403);
  await next();
});
app.use("/admin/*", async (c, next) => {
  const a = await admin(c.req.raw, c.env);
  if (!a) return c.text("Access required", 403);
  await next();
});
app.use("/api/admin/*", async (c, next) => {
  const a = await admin(c.req.raw, c.env);
  if (!a) return c.json({ error: "需要 Cloudflare Access 管理员登录" }, 403);
  if (!["GET", "HEAD"].includes(c.req.method) && !sameOrigin(c.req.raw))
    return c.json({ error: "不允许跨站写入" }, 403);
  c.set("actor", a.email);
  c.set("authExp", a.exp);
  await next();
});
app.get("/api/public/dashboard", async (c) => {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheURL = new URL(c.req.url);
  // Version the public projection so older snapshots cannot expose service names.
  cacheURL.searchParams.set("__public_schema", "2");
  const key = new Request(cacheURL);
  const hit = await cache.match(key);
  if (hit) {
    const response = new Response(hit.body, hit);
    response.headers.set("Cache-Control", "no-store");
    return response;
  }
  const [nodes, bans] = await Promise.all([
    c.env.DB.prepare(
      "SELECT id,ip,ipv4,ipv6,country,city,latitude,longitude,last_seen,observed_at,poll_interval,(token_hash IS NOT NULL) AS authenticated FROM nodes WHERE enabled=1",
    ).all<
      Pick<
        NodeRow,
        | "id"
        | "ip"
        | "ipv4"
        | "ipv6"
        | "country"
        | "city"
        | "latitude"
        | "longitude"
        | "last_seen"
        | "observed_at"
        | "poll_interval"
      > & { authenticated: number }
    >(),
    c.env.DB.prepare(
      "SELECT b.node_id,b.ip,b.country,b.city,b.latitude,b.longitude,b.observed_at FROM bans b JOIN nodes n ON b.node_id=n.id WHERE n.enabled=1 ORDER BY b.observed_at DESC LIMIT 20000",
    ).all<{
      node_id: string;
      ip: string;
      country: string | null;
      city: string | null;
      latitude: number | null;
      longitude: number | null;
      observed_at: number;
    }>(),
  ]);
  const response = Response.json(
    {
      generated_at: now(),
      nodes: nodes.results.map((n) => ({
        id: n.id,
        ip: maskIP(n.ip, true),
        ipv4: nodeAddresses(n).ipv4
          ? maskIP(nodeAddresses(n).ipv4, true)
          : null,
        ipv6: nodeAddresses(n).ipv6
          ? maskIP(nodeAddresses(n).ipv6, true)
          : null,
        country: n.country,
        city: n.city,
        latitude: n.latitude,
        longitude: n.longitude,
        last_seen: n.last_seen,
        observed_at: n.observed_at,
        online:
          !!n.authenticated &&
          !!n.last_seen &&
          n.last_seen > now() - Math.max(180, n.poll_interval * 3),
      })),
      bans: bans.results.map((b) => ({
        node_id: b.node_id,
        ip: maskIP(b.ip),
        country: b.country,
        city: b.city,
        latitude: b.latitude,
        longitude: b.longitude,
        observed_at: b.observed_at,
      })),
    },
    {
      headers: {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
  // Cache only at the edge. Zone Browser Cache TTL can lengthen max-age on hits.
  const cached = response.clone();
  cached.headers.set("Cache-Control", "public, max-age=10");
  c.executionCtx.waitUntil(cache.put(key, cached));
  return response;
});
app.get("/api/admin/dashboard", async (c) => {
  await c.env.DB.prepare(
    "UPDATE commands SET status='expired',completed_at=? WHERE status IN ('pending','running') AND expires_at<=?",
  )
    .bind(now(), now())
    .run();
  const [nodes, bans, policies, commands, logs, settings] = await Promise.all([
    c.env.DB.prepare("SELECT * FROM nodes ORDER BY created_at").all<NodeRow>(),
    c.env.DB.prepare(
      "SELECT * FROM bans ORDER BY observed_at DESC LIMIT 20000",
    ).all(),
    c.env.DB.prepare(
      "SELECT * FROM whitelist WHERE expires_at IS NULL OR expires_at>? ORDER BY created_at DESC",
    )
      .bind(now())
      .all(),
    c.env.DB.prepare(
      "SELECT * FROM commands ORDER BY created_at DESC LIMIT 200",
    ).all(),
    c.env.DB.prepare(
      "SELECT * FROM audit ORDER BY created_at DESC LIMIT 200",
    ).all(),
    c.env.DB.prepare("SELECT policy_revision FROM settings WHERE id=1").first<{
      policy_revision: number;
    }>(),
  ]);
  return c.json({
    actor: c.get("actor"),
    nodes: nodes.results.map(nodeView),
    bans: bans.results,
    policies: policies.results,
    commands: commands.results,
    audit: logs.results,
    policy_revision: settings!.policy_revision,
    generated_at: now(),
  });
});
app.get("/api/admin/ws", async (c) => {
  if (c.req.header("Upgrade")?.toLowerCase() !== "websocket")
    return c.json({ error: "WebSocket required" }, 426);
  if (!sameOrigin(c.req.raw)) return c.json({ error: "不允许跨站连接" }, 403);
  return c.env.DASHBOARD.get(c.env.DASHBOARD.idFromName("admin")).fetch(
    new Request("https://internal/connect", {
      headers: { Upgrade: "websocket", "x-auth-exp": String(c.get("authExp")) },
    }),
  );
});
app.post("/api/admin/nodes", async (c) => {
  const p = createNodeSchema.parse(await c.req.json()),
    id = crypto.randomUUID();
  await c.env.DB.prepare("INSERT INTO nodes(id,name,created_at) VALUES(?,?,?)")
    .bind(id, p.name, now())
    .run();
  const code = await enrollment(c.env, id);
  await audit(c.env, c.get("actor"), "node.create", { id, name: p.name });
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ id, enrollment: code, expires_at: now() + 600 }, 201);
});
app.patch("/api/admin/nodes/:id", async (c) => {
  const p = updateNodeSchema.parse(await c.req.json());
  const id = z.string().uuid().parse(c.req.param("id"));
  const n = await c.env.DB.prepare("SELECT * FROM nodes WHERE id=?")
    .bind(id)
    .first<NodeRow>();
  if (!n) return c.json({ error: "节点不存在" }, 404);
  await c.env.DB.prepare(
    "UPDATE nodes SET name=?,enabled=?,mode=?,poll_interval=?,config_revision=config_revision+1 WHERE id=?",
  )
    .bind(
      p.name ?? n.name,
      p.enabled === undefined ? n.enabled : Number(p.enabled),
      p.mode ?? n.mode,
      p.poll_interval ?? n.poll_interval,
      id,
    )
    .run();
  await audit(c.env, c.get("actor"), "node.update", { id, ...p });
  c.executionCtx.waitUntil(
    Promise.all([
      wakeNode(c.env, id, p.enabled === false),
      notifyDashboard(c.env),
    ]),
  );
  return c.json({ ok: true });
});
app.post("/api/admin/nodes/:id/enrollment", async (c) => {
  const id = z.string().uuid().parse(c.req.param("id"));
  const n = await c.env.DB.prepare("SELECT id FROM nodes WHERE id=?")
    .bind(id)
    .first();
  if (!n) return c.json({ error: "节点不存在" }, 404);
  // Re-enrollment immediately revokes the old bearer; a disabled node stays disabled until enabled explicitly.
  await c.env.DB.prepare(
    "UPDATE nodes SET token_hash=NULL,enroll_hash=NULL,enroll_expires=NULL WHERE id=?",
  )
    .bind(id)
    .run();
  await wakeNode(c.env, id, true);
  const code = await enrollment(c.env, id);
  await audit(c.env, c.get("actor"), "node.reenroll", { id });
  return c.json({ enrollment: code, expires_at: now() + 600 });
});
app.post("/api/admin/nodes/:id/revoke", async (c) => {
  const id = z.string().uuid().parse(c.req.param("id"));
  await c.env.DB.prepare(
    "UPDATE nodes SET token_hash=NULL,enroll_hash=NULL,enroll_expires=NULL WHERE id=?",
  )
    .bind(id)
    .run();
  await wakeNode(c.env, id, true);
  await audit(c.env, c.get("actor"), "node.revoke", { id });
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ ok: true });
});
app.delete("/api/admin/nodes/:id", async (c) => {
  const id = z.string().uuid().parse(c.req.param("id"));
  await c.env.DB.prepare("DELETE FROM nodes WHERE id=?").bind(id).run();
  await wakeNode(c.env, id, true);
  await audit(c.env, c.get("actor"), "node.delete", { id });
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ ok: true });
});
app.post("/api/admin/commands", async (c) => {
  const list = z
    .array(commandSchema)
    .min(1)
    .max(100)
    .parse(await c.req.json());
  const ids: string[] = [];
  // Validate the entire batch before writing any commands.
  for (const p of list) {
    const n = await c.env.DB.prepare(
      "SELECT jails_json FROM nodes WHERE id=? AND enabled=1 AND token_hash IS NOT NULL",
    )
      .bind(p.node_id)
      .first<{ jails_json: string }>();
    if (!n || !(JSON.parse(n.jails_json) as string[]).includes(p.jail))
      return c.json({ error: "节点不可用或 service 不存在" }, 400);
    if (
      p.kind === "ban" &&
      (await c.env.DB.prepare(
        "SELECT id FROM whitelist WHERE ip=? AND (expires_at IS NULL OR expires_at>?)",
      )
        .bind(p.ip, now())
        .first())
    )
      return c.json({ error: "IP 位于全局白名单，请先撤销加白" }, 409);
  }
  const sql = list.map((p) => {
    const id = crypto.randomUUID();
    ids.push(id);
    return c.env.DB.prepare(
      "INSERT INTO commands(id,node_id,kind,jail,ip,created_at,expires_at,actor) VALUES(?,?,?,?,?,?,?,?)",
    ).bind(
      id,
      p.node_id,
      p.kind,
      p.jail,
      p.ip,
      now(),
      now() + 600,
      c.get("actor"),
    );
  });
  await c.env.DB.batch(sql);
  await audit(c.env, c.get("actor"), "commands.create", {
    ids,
    commands: list,
  });
  c.executionCtx.waitUntil(
    Promise.all(
      [...new Set(list.map((p) => p.node_id))].map((id) => wakeNode(c.env, id)),
    ).then(() => notifyDashboard(c.env)),
  );
  return c.json({ ids }, 201);
});
app.post("/api/admin/whitelist", async (c) => {
  const p = whitelistSchema.parse(await c.req.json());
  const id = crypto.randomUUID();
  const expires = p.duration === null ? null : now() + p.duration;
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO whitelist(id,ip,expires_at,created_at,actor) VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET expires_at=excluded.expires_at,actor=excluded.actor",
    ).bind(id, p.ip, expires, now(), c.get("actor")),
    c.env.DB.prepare(
      "UPDATE settings SET policy_revision=policy_revision+1 WHERE id=1",
    ),
  ]);
  await audit(c.env, c.get("actor"), "whitelist.upsert", {
    ip: p.ip,
    expires_at: expires,
  });
  c.executionCtx.waitUntil(wakeAll(c.env));
  return c.json({ ok: true }, 201);
});
app.delete("/api/admin/whitelist/:id", async (c) => {
  const id = z.string().uuid().parse(c.req.param("id"));
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM whitelist WHERE id=?").bind(id),
    c.env.DB.prepare(
      "UPDATE settings SET policy_revision=policy_revision+1 WHERE id=1",
    ),
  ]);
  await audit(c.env, c.get("actor"), "whitelist.delete", { id });
  c.executionCtx.waitUntil(wakeAll(c.env));
  return c.json({ ok: true });
});
app.post("/api/agent/v1/enroll", async (c) => {
  const { enrollment: code } = z
    .object({ enrollment: z.string().regex(/^[a-f0-9]{64}$/) })
    .parse(await c.req.json());
  const token = secret();
  const row = await c.env.DB.prepare(
    "UPDATE nodes SET token_hash=?,enroll_hash=NULL,enroll_expires=NULL,last_seq=0,observed_at=NULL,applied_config_revision=0,applied_policy_revision=0 WHERE enroll_hash=? AND enroll_expires>? AND enabled=1 RETURNING id",
  )
    .bind(await hash(token), await hash(code), now())
    .first<{ id: string }>();
  if (!row) return c.json({ error: "安装凭据无效、已使用或已过期" }, 401);
  await wakeNode(c.env, row.id, true);
  return c.json({ node_id: row.id, token, protocol: 1 });
});
app.get("/api/agent/v1/addresses", async (c) => {
  const n = await agent(c.req.raw, c.env);
  if (!n) return c.json({ error: "节点凭据无效或已停用" }, 401);
  const addresses = splitAddress(connectingAddress(c.req.raw));
  if (!addresses.ipv4 && !addresses.ipv6)
    return c.json({ error: "无法识别连接地址" }, 503);
  const result = await c.env.DB.prepare(
    "UPDATE nodes SET ipv4=COALESCE(?,ipv4),ipv6=COALESCE(?,ipv6) WHERE id=? AND token_hash=? AND enabled=1",
  )
    .bind(addresses.ipv4, addresses.ipv6, n.id, n.token_hash)
    .run();
  if (!result.meta.changes)
    return c.json({ error: "节点凭据无效或已停用" }, 401);
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json(addresses);
});
app.all("/api/agent/v1/:action", async (c) => {
  const action = c.req.param("action");
  if (!["sync", "ws"].includes(action))
    return c.json({ error: "Not found" }, 404);
  if (
    (action === "sync" && c.req.method !== "POST") ||
    (action === "ws" && c.req.method !== "GET")
  )
    return c.json({ error: "Method not allowed" }, 405);
  const n = await agent(c.req.raw, c.env);
  if (!n) return c.json({ error: "节点凭据无效或已停用" }, 401);
  const cf = c.req.raw.cf;
  const geo = {
    ip: connectingAddress(c.req.raw),
    country: cf?.country ?? null,
    city: cf?.city ?? null,
    latitude: cf?.latitude ? Number(cf.latitude) : null,
    longitude: cf?.longitude ? Number(cf.longitude) : null,
  };
  const headers = new Headers(c.req.raw.headers);
  headers.set("x-node-id", n.id);
  headers.set("x-node-hash", n.token_hash!);
  headers.set("x-node-geo", JSON.stringify(geo));
  return c.env.NODES.get(c.env.NODES.idFromName(n.id)).fetch(
    new Request(`https://internal/${action === "ws" ? "connect" : "sync"}`, {
      method: c.req.method,
      headers,
      body: action === "sync" ? c.req.raw.body : undefined,
    }),
  );
});
app.all("/api/*", (c) => c.json({ error: "接口不存在" }, 404));
app.get("*", (c) => {
  if (c.req.path === "/admin" || c.req.path.startsWith("/admin/")) {
    const url = new URL(c.req.url);
    // Keep the authenticated application's assets behind the same Access paths.
    if (!c.req.path.startsWith("/admin/assets/")) url.pathname = "/admin/";
    return c.env.ASSETS.fetch(new Request(url, c.req.raw));
  }
  return c.env.ASSETS.fetch(c.req.raw);
});
export async function cleanup(env: Env): Promise<void> {
  const days = Math.min(3650, Math.max(1, Number(env.RETENTION_DAYS) || 30));
  const cutoff = now() - days * 86400;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM events WHERE received_at<?").bind(cutoff),
    env.DB.prepare("DELETE FROM audit WHERE created_at<?").bind(cutoff),
    env.DB.prepare(
      "DELETE FROM commands WHERE created_at<? AND status IN ('succeeded','failed','expired')",
    ).bind(cutoff),
    env.DB.prepare(
      "UPDATE commands SET status='expired',completed_at=? WHERE status IN ('pending','running') AND expires_at<=?",
    ).bind(now(), now()),
    env.DB.prepare(
      "DELETE FROM whitelist WHERE expires_at IS NOT NULL AND expires_at<=?",
    ).bind(now()),
  ]);
}
export default {
  fetch: app.fetch,
  scheduled: (_event: ScheduledController, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(cleanup(env));
  },
} satisfies ExportedHandler<Env>;
