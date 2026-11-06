import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";
import { agent, hash } from "./auth";
import type { AppEnv, Env, NodeRow } from "./env";
import { notifyDashboard, wakeNode } from "./sync";
import type {
  FirewallDraft,
  FirewallGroup,
  FirewallNodeDetail,
  FirewallObservation,
  FirewallPreview,
  FirewallReceipt,
  FirewallRelease,
  FirewallTarget,
} from "../shared/firewall";

import {
  uuid,
  fingerprint,
  revision,
  defaults,
  groupBody,
  draftBody,
  firewallObservation,
  blockedSSH,
} from "./firewall-schema";

type StoredGroup = Omit<FirewallGroup, "rules"> & { rules: string };
type StoredRelease = Omit<FirewallRelease, "target" | "drift"> & {
  target: string;
  drift: string | null;
};
type StoredDraft = { revision: number; config: string };
type StoredObservation = { snapshot: string | null; refresh: number };
const now = () => Math.floor(Date.now() / 1000);
const conflict = (message = "版本已变化，请刷新后重试"): never => {
  throw new HTTPException(409, { message });
};
const readGroup = (row: StoredGroup): FirewallGroup => ({
  ...row,
  rules: JSON.parse(row.rules),
});
const readRelease = (row: StoredRelease): FirewallRelease => ({
  ...row,
  target: JSON.parse(row.target),
  drift: row.drift ? JSON.parse(row.drift) : null,
});

export function firewallSyncStatements(
  env: Env,
  node: NodeRow,
  observation?: FirewallObservation,
  receipt?: FirewallReceipt,
) {
  const statements: D1PreparedStatement[] = [];
  if (observation) {
    const snapshot = observation;
    statements.push(
      env.DB.prepare(
        `INSERT INTO firewall_observations(node_id,snapshot,observed_at) VALUES(?,?,?)
       ON CONFLICT(node_id) DO UPDATE SET snapshot=excluded.snapshot,observed_at=excluded.observed_at
       WHERE excluded.observed_at>=firewall_observations.observed_at`,
      ).bind(
        node.id,
        JSON.stringify(snapshot),
        Math.min(now(), snapshot.observed_at),
      ),
    );
  }
  if (receipt?.event === "drift") {
    statements.push(
      env.DB.prepare(
        "UPDATE firewall_releases SET drift=?,updated_at=? WHERE id=? AND node_id=? AND status='applied' AND drift IS NOT ?",
      ).bind(
        JSON.stringify(receipt),
        now(),
        receipt.id,
        node.id,
        JSON.stringify(receipt),
      ),
    );
    if (receipt.event_id)
      statements.push(
        env.DB.prepare(
          `INSERT OR IGNORE INTO audit(id,actor,action,detail,created_at)
       SELECT ?,?,'firewall.drift',?,? WHERE EXISTS(
         SELECT 1 FROM firewall_releases WHERE id=? AND node_id=? AND status='applied'
       )`,
        ).bind(
          receipt.event_id,
          "node:" + node.id,
          JSON.stringify(receipt),
          now(),
          receipt.id,
          node.id,
        ),
      );
  } else if (receipt) {
    statements.push(
      env.DB.prepare(
        `UPDATE firewall_releases SET status=?,error=?,updated_at=? WHERE id=? AND node_id=?
       AND status IN ('pending','applying') AND (?<>'applied' OR (status='applying' AND confirmed_at IS NOT NULL))`,
      ).bind(
        receipt.status,
        receipt.error ?? null,
        now(),
        receipt.id,
        node.id,
        receipt.status,
      ),
    );
  }
  return statements;
}

export async function firewallFor(env: Env, node: NodeRow) {
  const state = await env.DB.prepare(
    `SELECT o.refresh, (SELECT target FROM firewall_releases r WHERE r.node_id=o.node_id
      AND r.status IN ('pending','applying') ORDER BY sequence DESC LIMIT 1) target
      FROM firewall_observations o WHERE o.node_id=? AND o.snapshot IS NOT NULL`,
  )
    .bind(node.id)
    .first<{ refresh: number; target: string | null }>();
  return state
    ? {
        firewall_refresh: state.refresh,
        firewall: state.target
          ? (JSON.parse(state.target) as FirewallTarget)
          : undefined,
      }
    : {};
}

export const firewallAgent = new Hono<AppEnv>();
firewallAgent.post("/:operation", async (c) => {
  const operation = c.req.param("operation");
  if (operation !== "claim" && operation !== "confirm") return c.notFound();
  const node = await agent(c.req.raw, c.env);
  if (!node) return c.json({ error: "节点凭据无效或已停用" }, 401);
  const release = uuid.parse(c.req.query("id"));
  const db = c.env.DB;
  const credential =
    "EXISTS(SELECT 1 FROM nodes WHERE id=firewall_releases.node_id AND enabled=1 AND token_hash=?)";
  if (operation === "claim") {
    const row = await db
      .prepare(
        `UPDATE firewall_releases SET status='applying',updated_at=? WHERE id=? AND node_id=?
       AND status IN ('pending','applying') AND ${credential}
       AND sequence=(SELECT MAX(sequence) FROM firewall_releases WHERE node_id=?) RETURNING id`,
      )
      .bind(now(), release, node.id, node.token_hash, node.id)
      .first();
    return row ? c.body(null, 204) : c.body(null, 409);
  }
  const drift = c.req.query("drift") === "1";
  const row = drift
    ? await db
        .prepare(
          `SELECT id FROM firewall_releases WHERE id=? AND node_id=? AND status='applied' AND ${credential}
         AND sequence=(SELECT MAX(sequence) FROM firewall_releases WHERE node_id=? AND status='applied')`,
        )
        .bind(release, node.id, node.token_hash, node.id)
        .first()
    : await db
        .prepare(
          `UPDATE firewall_releases SET confirmed_at=? WHERE id=? AND node_id=? AND status='applying' AND ${credential}
         AND sequence=(SELECT MAX(sequence) FROM firewall_releases WHERE node_id=?) RETURNING id`,
        )
        .bind(now(), release, node.id, node.token_hash, node.id)
        .first();
  return row ? c.body(null, 204) : c.body(null, 409);
});

export const firewallAdmin = new Hono<AppEnv>();
firewallAdmin.get("/groups", async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT * FROM firewall_groups ORDER BY name,id",
  ).all<StoredGroup>();
  return c.json(rows.results.map(readGroup));
});
firewallAdmin.post("/groups", async (c) => {
  const group = groupBody.omit({ revision: true }).parse(await c.req.json());
  const groupID = crypto.randomUUID();
  await c.env.DB.prepare(
    "INSERT INTO firewall_groups(id,name,rules) VALUES(?,?,?)",
  )
    .bind(groupID, group.name, JSON.stringify(group.rules))
    .run();
  return c.json({ ...group, id: groupID, revision: 1 }, 201);
});
firewallAdmin.put("/groups/:id", async (c) => {
  const groupID = uuid.parse(c.req.param("id"));
  const group = groupBody.parse(await c.req.json());
  const row = await c.env.DB.prepare(
    "UPDATE firewall_groups SET name=?,rules=?,revision=revision+1 WHERE id=? AND revision=? RETURNING revision",
  )
    .bind(group.name, JSON.stringify(group.rules), groupID, group.revision)
    .first<{ revision: number }>();
  if (!row) return conflict();
  return c.json({ ...group, id: groupID, revision: row.revision });
});
firewallAdmin.delete("/groups/:id", async (c) => {
  const groupID = uuid.parse(c.req.param("id"));
  const version = revision.parse(Number(c.req.query("revision")));
  const row = await c.env.DB.prepare(
    `DELETE FROM firewall_groups WHERE id=? AND revision=? AND NOT EXISTS(
       SELECT 1 FROM firewall_drafts d,json_each(d.config,'$.bindings') b WHERE b.value->>'group_id'=?
     ) RETURNING id`,
  )
    .bind(groupID, version, groupID)
    .first();
  if (!row) return conflict("请先解除草稿中的节点绑定，或刷新版本");
  return c.body(null, 204);
});
firewallAdmin.get("/nodes/:id", async (c) => {
  const nodeID = uuid.parse(c.req.param("id"));
  const db = c.env.DB;
  const [o, d, h] = await db.batch([
    db
      .prepare(
        "SELECT snapshot,refresh FROM firewall_observations WHERE node_id=?",
      )
      .bind(nodeID),
    db
      .prepare("SELECT revision,config FROM firewall_drafts WHERE node_id=?")
      .bind(nodeID),
    db
      .prepare(
        "SELECT * FROM firewall_releases WHERE node_id=? ORDER BY sequence DESC LIMIT 20",
      )
      .bind(nodeID),
  ]);
  const observation = o.results[0] as unknown as StoredObservation | undefined;
  const draft = d.results[0] as unknown as StoredDraft | undefined;
  return c.json({
    observation: observation?.snapshot
      ? JSON.parse(observation.snapshot)
      : null,
    draft: draft
      ? { ...JSON.parse(draft.config), revision: draft.revision }
      : null,
    history: h.results.map((r) => readRelease(r as unknown as StoredRelease)),
  } satisfies FirewallNodeDetail);
});
firewallAdmin.post("/nodes/:id/refresh", async (c) => {
  const nodeID = uuid.parse(c.req.param("id"));
  await c.env.DB.prepare(
    `INSERT INTO firewall_observations(node_id,refresh) SELECT id,1 FROM nodes WHERE id=?
     ON CONFLICT(node_id) DO UPDATE SET refresh=refresh+1`,
  )
    .bind(nodeID)
    .run();
  c.executionCtx.waitUntil(wakeNode(c.env, nodeID));
  return c.json({ ok: true });
});
firewallAdmin.put("/nodes/:id/draft", async (c) => {
  const nodeID = uuid.parse(c.req.param("id"));
  const { revision: version, ...config } = draftBody.parse(await c.req.json());
  const raw = JSON.stringify(config);
  const row = await c.env.DB.prepare(
    `INSERT INTO firewall_drafts(node_id,config) SELECT id,? FROM nodes WHERE id=?
       AND (?=0 OR EXISTS(SELECT 1 FROM firewall_drafts WHERE node_id=? AND revision=?))
       AND NOT EXISTS(SELECT 1 FROM json_each(?,'$.bindings') b
         WHERE NOT EXISTS(SELECT 1 FROM firewall_groups WHERE id=b.value->>'group_id'))
     ON CONFLICT(node_id) DO UPDATE SET config=excluded.config,revision=revision+1
       WHERE firewall_drafts.revision=? RETURNING revision`,
  )
    .bind(raw, nodeID, version, nodeID, version, raw, version)
    .first<{ revision: number }>();
  if (!row) return conflict();
  return c.json({ ...config, revision: row.revision });
});
firewallAdmin.post("/nodes/:id/import", async (c) => {
  const nodeID = uuid.parse(c.req.param("id"));
  const db = c.env.DB;
  const observation = await db
    .prepare(
      "SELECT o.snapshot,n.name FROM firewall_observations o JOIN nodes n ON n.id=o.node_id WHERE n.id=?",
    )
    .bind(nodeID)
    .first<{ snapshot: string | null; name: string }>();
  if (!observation?.snapshot) return conflict("等待节点上报 UFW");
  const snapshot = firewallObservation.parse(JSON.parse(observation.snapshot));
  if (snapshot.status !== "active" || snapshot.blocked?.length)
    return conflict("节点存在无法导入的 UFW 配置");
  const groupID = crypto.randomUUID();
  const config: FirewallDraft = {
    defaults: defaults.parse(snapshot.defaults),
    protection: snapshot.protection,
    bindings: [{ group_id: groupID, priority: 10 }],
  };
  // Both writes roll back if a concurrent import or draft has already won.
  try {
    await db.batch([
      db
        .prepare("INSERT INTO firewall_groups(id,name,rules) VALUES(?,?,?)")
        .bind(
          groupID,
          (observation.name + " · UFW 导入").slice(0, 80),
          JSON.stringify(snapshot.rules),
        ),
      db
        .prepare("INSERT INTO firewall_drafts(node_id,config) VALUES(?,?)")
        .bind(nodeID, JSON.stringify(config)),
    ]);
  } catch (error) {
    if (
      await db
        .prepare("SELECT 1 FROM firewall_drafts WHERE node_id=?")
        .bind(nodeID)
        .first()
    )
      return conflict("已有节点草稿");
    throw error;
  }
  return c.json({ ok: true }, 201);
});

async function preview(env: Env, nodeID: string, rollback?: string) {
  const db = env.DB;
  const [n, o, d, g, v, last, prior, affected] = await db.batch<
    Record<string, unknown>
  >([
    db.prepare("SELECT enabled FROM nodes WHERE id=?").bind(nodeID),
    db
      .prepare("SELECT snapshot FROM firewall_observations WHERE node_id=?")
      .bind(nodeID),
    db
      .prepare("SELECT revision,config FROM firewall_drafts WHERE node_id=?")
      .bind(nodeID),
    db
      .prepare(
        `SELECT g.* FROM firewall_groups g,json_each((SELECT config FROM firewall_drafts WHERE node_id=?),'$.bindings') b
      WHERE g.id=b.value->>'group_id' ORDER BY CAST(b.value->>'priority' AS INTEGER)`,
      )
      .bind(nodeID),
    db.prepare("SELECT revision FROM firewall_revision WHERE id=1"),
    db
      .prepare(
        "SELECT * FROM firewall_releases WHERE node_id=? AND status='applied' ORDER BY sequence DESC LIMIT 1",
      )
      .bind(nodeID),
    db
      .prepare(
        "SELECT * FROM firewall_releases WHERE node_id=? AND id=? AND status='applied'",
      )
      .bind(nodeID, rollback ?? ""),
    db
      .prepare(
        `SELECT DISTINCT n.id,n.name FROM nodes n JOIN firewall_drafts d ON d.node_id=n.id,
      json_each(d.config,'$.bindings') b WHERE b.value->>'group_id' IN
      (SELECT value->>'group_id' FROM json_each((SELECT config FROM firewall_drafts WHERE node_id=?),'$.bindings'))
      ORDER BY n.name`,
      )
      .bind(nodeID),
  ]);
  if (!n.results[0]?.enabled) return conflict("节点不存在或已停用");
  const observation = o.results[0]?.snapshot;
  const snapshot = observation
    ? firewallObservation.parse(JSON.parse(String(observation)))
    : null;
  const row = d.results[0] as unknown as StoredDraft | undefined;
  if (!snapshot?.fingerprint || snapshot.status !== "active")
    return conflict("等待节点上报已启用的 UFW");
  if (!row) return conflict("请先保存节点草稿或导入规则");
  if (snapshot.blocked?.length && !last.results.length)
    return conflict("节点存在未支持的 UFW 规则");
  const config = draftBody.parse({
    ...JSON.parse(row.config),
    revision: row.revision,
  });
  const historical = prior.results[0]
    ? readRelease(prior.results[0] as unknown as StoredRelease)
    : null;
  if (rollback && !historical) return conflict("找不到可回滚的历史版本");
  const groupList = g.results.map((r) =>
    readGroup(r as unknown as StoredGroup),
  );
  const rules =
    historical?.target.rules ??
    groupList.flatMap((group) =>
      [...group.rules]
        .sort((a, b) => a.priority - b.priority)
        .map((rule) => ({
          ...rule,
          id: group.id.slice(0, 18) + "_" + rule.id.slice(0, 45),
        })),
    );
  if (rules.length > 2000) return conflict("节点规则数量超过 2000 条");
  if (
    !snapshot.ipv6 &&
    rules.some((rule) => rule.enabled && rule.family !== "ipv4")
  )
    return conflict("节点未开启 UFW IPv6");
  const after: FirewallTarget = {
    id: "",
    node_id: nodeID,
    fingerprint: snapshot.fingerprint,
    rules,
    defaults: historical?.target.defaults ?? config.defaults,
    protection: config.protection,
  };
  if (!after.protection.length)
    return conflict("请至少配置一个受保护的 SSH 来源");
  const blocked = blockedSSH(after);
  if (blocked)
    return conflict(
      `规则可能阻断 SSH 管理入口 ${blocked.source} · ${blocked.port}/tcp`,
    );
  const draftRevision = Number(v.results[0].revision);
  const version = await hash(
    JSON.stringify([draftRevision, after, rollback ?? "", last.results[0]?.id]),
  );
  const result: FirewallPreview = {
    version,
    node_id: nodeID,
    before: snapshot.rules,
    baseline_changes:
      !last.results.length && snapshot.planned_baseline
        ? Object.fromEntries(
            Object.entries(snapshot.planned_baseline).map(([name, after]) => [
              name,
              { before: snapshot.baseline?.[name] ?? [], after },
            ]),
          )
        : undefined,
    before_defaults: defaults.safeParse(snapshot.defaults).data,
    after,
    affected: affected.results as { id: string; name: string }[],
  };
  return { result, draftRevision };
}

firewallAdmin.post("/nodes/:id/preview", async (c) => {
  const nodeID = uuid.parse(c.req.param("id"));
  const { rollback } = z
    .object({ rollback: uuid.optional() })
    .parse(await c.req.json());
  return c.json((await preview(c.env, nodeID, rollback)).result);
});
firewallAdmin.post("/publish", async (c) => {
  const requests = z
    .array(
      z.object({
        node_id: uuid,
        version: fingerprint,
        rollback: uuid.optional(),
      }),
    )
    .min(1)
    .max(30)
    .refine((list) => new Set(list.map((n) => n.node_id)).size === list.length)
    .parse(await c.req.json());
  const db = c.env.DB;
  const outcomes = [];
  for (const request of requests) {
    try {
      const { result, draftRevision } = await preview(
        c.env,
        request.node_id,
        request.rollback,
      );
      if (result.version !== request.version)
        conflict("预览已过期，请重新预览");
      const target = { ...result.after, id: crypto.randomUUID() };
      const [written] = await db.batch([
        db
          .prepare(
            `INSERT INTO firewall_releases(id,node_id,target,actor,created_at,updated_at)
          SELECT ?,n.id,?,?,?,? FROM nodes n JOIN firewall_observations o ON o.node_id=n.id
          WHERE n.id=? AND n.enabled=1 AND o.snapshot->>'fingerprint'=?
            AND (SELECT revision FROM firewall_revision WHERE id=1)=?
            AND NOT EXISTS(SELECT 1 FROM firewall_releases WHERE node_id=n.id AND status='applying' AND updated_at>?)
          RETURNING id`,
          )
          .bind(
            target.id,
            JSON.stringify(target),
            c.get("actor"),
            now(),
            now(),
            target.node_id,
            target.fingerprint,
            draftRevision,
            now() - 180,
          ),
        db
          .prepare(
            `UPDATE firewall_releases SET status='superseded',updated_at=?
          WHERE node_id=? AND id<>? AND status IN ('pending','applying')
          AND EXISTS(SELECT 1 FROM firewall_releases WHERE id=?)`,
          )
          .bind(now(), target.node_id, target.id, target.id),
        db
          .prepare(
            `INSERT INTO audit(id,actor,action,detail,created_at)
          SELECT ?,?,'firewall.publish',?,? WHERE EXISTS(SELECT 1 FROM firewall_releases WHERE id=?)`,
          )
          .bind(
            crypto.randomUUID(),
            c.get("actor"),
            JSON.stringify({
              node_id: target.node_id,
              id: target.id,
              rollback: request.rollback,
            }),
            now(),
            target.id,
          ),
      ]);
      if (!written.results.length) conflict("节点正在执行发布或预览已过期");
      outcomes.push({ node_id: target.node_id, id: target.id });
      c.executionCtx.waitUntil(wakeNode(c.env, target.node_id));
    } catch (error) {
      if (!(error instanceof HTTPException) || error.status !== 409)
        throw error;
      outcomes.push({ node_id: request.node_id, error: error.message });
    }
  }
  c.executionCtx.waitUntil(notifyDashboard(c.env));
  return c.json({ outcomes }, outcomes.every((o) => "error" in o) ? 409 : 200);
});
