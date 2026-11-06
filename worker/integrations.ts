import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import { hash, secret } from "./auth";
import type { AppEnv, Env } from "./env";
import { notifyDashboard, wakeAll } from "./sync";
import { ip } from "./validation";

export const integrationAPI = new Hono<AppEnv>();
export const integrationAdmin = new Hono<AppEnv>();
const keySchema = z.string().regex(/^[A-Za-z0-9_-]{1,32}$/);
const ruleSchema = z.strictObject({ ip });
const nameSchema = z.strictObject({ name: z.string().trim().min(1).max(80) });
const seconds = () => Math.floor(Date.now() / 1000);
const activeToken = "token_hash=? AND revoked_at IS NULL";
const metadata = "id,name,token_prefix,created_at,last_used_at,revoked_at";
type Rule = { id: string; key: string; ip: string; expires_at: number };
type Credential = { id: string; name: string };

async function credentialHash(header: string | undefined) {
  const token = header?.match(/^Bearer (f2bm_[a-f0-9]{64})$/i)?.[1];
  return token ? hash(token) : null;
}

function revision(env: Env) {
  // Must immediately follow the statement that changes the rules.
  return env.DB.prepare(
    "UPDATE settings SET policy_revision=policy_revision+1 WHERE id=1 AND changes()>0",
  );
}

function adminAudit(
  env: Env,
  actor: string,
  action: string,
  id: string,
  at: number,
) {
  return env.DB.prepare(
    "INSERT INTO audit(id,actor,action,detail,created_at) SELECT ?,?,?,?,? WHERE changes()>0",
  ).bind(crypto.randomUUID(), actor, action, JSON.stringify({ id }), at);
}

integrationAPI.use("/whitelist/:key", async (c, next) => {
  c.header("Cache-Control", "no-store");
  const digest = await credentialHash(c.req.header("Authorization"));
  const caller =
    digest &&
    (await c.env.DB.prepare(
      `SELECT id,name FROM integrations WHERE ${activeToken}`,
    )
      .bind(digest)
      .first<Credential>());
  if (!caller || !digest) return c.json({ error: "需要有效的接入 Token" }, 401);
  c.set("integration", { ...caller, digest });
  await next();
});

integrationAPI.get("/whitelist/:key", async (c) => {
  const { id, digest } = c.get("integration");
  const key = keySchema.parse(c.req.param("key"));
  const row = await c.env.DB.prepare(
    `SELECT w.id,w.rule_key AS key,w.ip,w.expires_at
     FROM integrations i LEFT JOIN dynamic_whitelist w
       ON w.integration_id=i.id AND w.rule_key=? AND w.expires_at>?
     WHERE i.id=? AND i.${activeToken}`,
  )
    .bind(key, seconds(), id, digest)
    .first<Rule>();
  if (!row) return c.json({ error: "需要有效的接入 Token" }, 401);
  if (!row.id)
    return c.json({ error: "规则不存在或已过期", code: "rule_not_found" }, 404);
  return c.json(row);
});

integrationAPI.put(
  "/whitelist/:key",
  bodyLimit({
    maxSize: 1024,
    onError: (c) => c.json({ error: "请求过大" }, 413),
  }),
  async (c) => {
    const { id, digest } = c.get("integration");
    const key = keySchema.parse(c.req.param("key"));
    const { ip } = ruleSchema.parse(await c.req.json());
    const at = seconds();
    const expires = at + 86400;
    const db = c.env.DB;
    const [, , update, , result] = await db.batch<
      Rule & { policy_revision: number }
    >([
      db
        .prepare(
          `INSERT INTO audit(id,actor,action,detail,created_at)
         SELECT ?, 'integration:'||i.id, 'dynamic_whitelist.upsert',
                json_object('key',?,'ip',?,'previous_ip',w.ip,'expires_at',?), ?
         FROM integrations i LEFT JOIN dynamic_whitelist w
           ON w.integration_id=i.id AND w.rule_key=?
         WHERE i.id=? AND i.${activeToken} AND (w.id IS NULL OR w.ip<>? OR w.expires_at<=?)`,
        )
        .bind(
          crypto.randomUUID(),
          key,
          ip,
          expires,
          at,
          key,
          id,
          digest,
          ip,
          at,
        ),
      db
        .prepare(
          `INSERT INTO dynamic_whitelist(id,integration_id,rule_key,ip,expires_at,created_at,synced_at)
         SELECT ?,id,?,?,?,?,? FROM integrations WHERE id=? AND ${activeToken}
         ON CONFLICT(integration_id,rule_key) DO UPDATE SET
           ip=excluded.ip, expires_at=excluded.expires_at, synced_at=excluded.synced_at
         WHERE dynamic_whitelist.ip<>excluded.ip OR dynamic_whitelist.expires_at<>excluded.expires_at`,
        )
        .bind(crypto.randomUUID(), key, ip, expires, at, at, id, digest),
      revision(c.env),
      db
        .prepare(
          `UPDATE integrations SET last_used_at=? WHERE id=? AND ${activeToken}`,
        )
        .bind(at, id, digest),
      db
        .prepare(
          `SELECT w.id,w.rule_key AS key,w.ip,w.expires_at,s.policy_revision
         FROM dynamic_whitelist w JOIN integrations i ON i.id=w.integration_id
         CROSS JOIN settings s
         WHERE s.id=1 AND i.id=? AND i.${activeToken} AND w.rule_key=?`,
        )
        .bind(id, digest, key),
    ]);
    const row = result.results[0];
    if (!row) return c.json({ error: "需要有效的接入 Token" }, 401);
    if (update.meta.changes) c.executionCtx.waitUntil(wakeAll(c.env));
    return c.json(row);
  },
);

async function deleteRule(
  env: Env,
  scope: { id: string; digest: string; key: string } | { ruleId: string },
  actor: string,
) {
  const byCaller = "digest" in scope;
  const filter = byCaller
    ? `integration_id=(SELECT id FROM integrations WHERE id=? AND ${activeToken}) AND rule_key=?`
    : "id=?";
  const args = byCaller ? [scope.id, scope.digest, scope.key] : [scope.ruleId];
  const db = env.DB;
  const [, , updated, allowed] = await db.batch([
    db
      .prepare(
        `INSERT INTO audit(id,actor,action,detail,created_at)
       SELECT ?,?,'dynamic_whitelist.delete',json_object('id',id,'key',rule_key,'ip',ip),?
       FROM dynamic_whitelist WHERE ${filter}`,
      )
      .bind(crypto.randomUUID(), actor, seconds(), ...args),
    db.prepare(`DELETE FROM dynamic_whitelist WHERE ${filter}`).bind(...args),
    revision(env),
    byCaller
      ? db
          .prepare(`SELECT id FROM integrations WHERE id=? AND ${activeToken}`)
          .bind(scope.id, scope.digest)
      : db.prepare("SELECT 1"),
  ]);
  return {
    changed: !!updated.meta.changes,
    authorized: !!allowed.results.length,
  };
}

integrationAPI.delete("/whitelist/:key", async (c) => {
  const caller = c.get("integration");
  const key = keySchema.parse(c.req.param("key"));
  const result = await deleteRule(
    c.env,
    { ...caller, key },
    "integration:" + caller.id,
  );
  if (!result.authorized) return c.json({ error: "需要有效的接入 Token" }, 401);
  if (result.changed) c.executionCtx.waitUntil(wakeAll(c.env));
  return c.json({ ok: true });
});

export async function listIntegrations(env: Env) {
  const { results } = await env.DB.prepare(
    `SELECT ${metadata} FROM integrations ORDER BY created_at DESC,id`,
  ).all();
  return results;
}

integrationAdmin.get("/", async (c) =>
  c.json({ integrations: await listIntegrations(c.env) }),
);

integrationAdmin.post("/", async (c) => {
  const { name } = nameSchema.parse(await c.req.json());
  const token = "f2bm_" + secret();
  const tokenPrefix = token.slice(0, 13);
  const id = crypto.randomUUID();
  const at = seconds();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO integrations(id,name,token_hash,token_prefix,created_at) VALUES(?,?,?,?,?)",
    ).bind(id, name, await hash(token), tokenPrefix, at),
    adminAudit(c.env, c.get("actor"), "integration.create", id, at),
  ]);
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ id, token }, 201);
});

integrationAdmin.post("/:id/rotate", async (c) => {
  const id = z.uuid().parse(c.req.param("id"));
  const token = "f2bm_" + secret();
  const at = seconds();
  const [result] = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE integrations SET token_hash=?,token_prefix=? WHERE id=? AND revoked_at IS NULL",
    ).bind(await hash(token), token.slice(0, 13), id),
    adminAudit(c.env, c.get("actor"), "integration.rotate", id, at),
  ]);
  if (!result.meta.changes) return c.json({ error: "接入不存在或已撤销" }, 404);
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ id, token });
});

integrationAdmin.post("/:id/revoke", async (c) => {
  const id = z.uuid().parse(c.req.param("id"));
  const at = seconds();
  const [result, , , updated] = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE integrations SET revoked_at=?,token_hash=NULL WHERE id=? AND revoked_at IS NULL",
    ).bind(at, id),
    adminAudit(c.env, c.get("actor"), "integration.revoke", id, at),
    c.env.DB.prepare(
      "DELETE FROM dynamic_whitelist WHERE integration_id=? AND changes()>0",
    ).bind(id),
    revision(c.env),
  ]);
  if (result.meta.changes)
    c.executionCtx.waitUntil(
      updated.meta.changes ? wakeAll(c.env) : notifyDashboard(c.env),
    );
  return c.json({ ok: true });
});

export const dynamicWhitelistAdmin = new Hono<AppEnv>();
dynamicWhitelistAdmin.delete("/:id", async (c) => {
  const ruleId = z.uuid().parse(c.req.param("id"));
  const result = await deleteRule(c.env, { ruleId }, c.get("actor"));
  if (result.changed) c.executionCtx.waitUntil(wakeAll(c.env));
  return c.json({ ok: true });
});
