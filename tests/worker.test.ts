import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
  evictDurableObject,
} from "cloudflare:test";
import {
  beforeAll,
  beforeEach,
  afterAll,
  describe,
  it,
  expect,
  vi,
} from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker, { cleanup } from "../worker";
import type { Data, PublicData } from "../web/types";
import { hash, secret } from "../worker/auth";
import { maskIP } from "../worker/privacy";
import { canonicalIP, syncSchema } from "../worker/validation";
import { connectingAddress } from "../worker/addresses";
import type { AgentSync, ServerSync } from "../shared/protocol";

let privateKey: CryptoKey;
let jwt: string;
const origin = "https://mate.example.com";
async function token(
  email = "admin@example.com",
  aud = "mate-tests",
  expiry = "1h",
) {
  return new SignJWT({ email })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(env.ACCESS_TEAM_DOMAIN)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(expiry)
    .sign(privateKey);
}
async function request(
  path: string,
  method = "GET",
  body?: unknown,
  bearer?: string,
  opts: {
    admin?: boolean;
    origin?: string;
    token?: string;
    ip?: string;
    ipv6?: string;
  } = {},
) {
  const headers = new Headers();
  if (body !== undefined) headers.set("Content-Type", "application/json");
  if (bearer) headers.set("Authorization", "Bearer " + bearer);
  if (opts.ip) headers.set("CF-Connecting-IP", opts.ip);
  if (opts.ipv6) headers.set("CF-Connecting-IPv6", opts.ipv6);
  if (opts.admin) headers.set("Cf-Access-Jwt-Assertion", opts.token ?? jwt);
  if (method !== "GET") headers.set("Origin", opts.origin ?? origin);
  const ctx = createExecutionContext();
  const response = await worker.fetch(
    new Request(origin + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}
async function create(name = "edge-test") {
  const res = await request("/api/admin/nodes", "POST", { name }, undefined, {
    admin: true,
  });
  expect(res.status).toBe(201);
  const n = (await res.json()) as { id: string; enrollment: string };
  const er = await request("/api/agent/v1/enroll", "POST", {
    enrollment: n.enrollment,
  });
  expect(er.status).toBe(200);
  const a = (await er.json()) as { node_id: string; token: string };
  return { ...a, code: n.enrollment };
}
function sync(extra: Partial<AgentSync> = {}): AgentSync {
  return {
    protocol: 1,
    type: "sync",
    sequence: 1,
    version: "test",
    actual_mode: "polling",
    applied_config_revision: 1,
    applied_policy_revision: 1,
    events: [],
    results: [],
    snapshot: {
      seq: 1,
      jails: [{ name: "sshd", bans: [] }],
      unavailable_jails: [],
    },
    ...extra,
  };
}
beforeAll(async () => {
  const keys = await generateKeyPair("RS256", { extractable: true });
  privateKey = keys.privateKey;
  const key = await exportJWK(keys.publicKey);
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    if (String(input) === env.ACCESS_TEAM_DOMAIN + "/cdn-cgi/access/certs")
      return Response.json({
        keys: [{ ...key, kid: "test-key", alg: "RS256", use: "sig" }],
      });
    throw new Error("Unexpected external request in test");
  });
  jwt = await token();
});
beforeEach(async () => {
  await env.DB.batch(
    [
      "commands",
      "events",
      "ban_history",
      "bans",
      "nodes",
      "whitelist",
      "dynamic_whitelist",
      "integrations",
      "audit",
    ].map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
  );
  await env.DB.prepare("UPDATE settings SET policy_revision=1").run();
});
afterAll(() => vi.unstubAllGlobals());
describe("access and enrollment", () => {
  it("returns the current visitor address only in the authenticated uncached dashboard", async () => {
    const cases = [
      { headers: { ip: "198.51.100.42" }, expected: "198.51.100.42" },
      { headers: { ip: "2001:0db8::42" }, expected: "2001:db8::42" },
      { headers: { ip: "::ffff:198.51.100.42" }, expected: "198.51.100.42" },
      {
        headers: { ip: "240.1.2.3", ipv6: "2001:db8::42" },
        expected: "2001:db8::42",
      },
      { headers: { ip: "invalid" }, expected: null },
      { headers: {}, expected: null },
    ];
    for (const { headers, expected } of cases) {
      const response = await request(
        "/api/admin/dashboard",
        "GET",
        undefined,
        undefined,
        { admin: true, ...headers },
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect((await response.json<Data>()).visitor_ip).toBe(expected);
    }
    const denied = await request(
      "/api/admin/dashboard",
      "GET",
      undefined,
      undefined,
      { ip: "198.51.100.42" },
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).not.toHaveProperty("visitor_ip");
    const publicResponse = await request(
      "/api/public/dashboard?visitor=" + crypto.randomUUID(),
      "GET",
      undefined,
      undefined,
      { ip: "198.51.100.42" },
    );
    const publicData = await publicResponse.json();
    expect(publicData).not.toHaveProperty("visitor_ip");
    expect(JSON.stringify(publicData)).not.toContain("198.51.100.42");
  });
  it("serves the separate administration page and assets only after authentication", async () => {
    const assets = {
      fetch: vi.fn(
        async (request: RequestInfo | URL) =>
          new Response(
            new URL(request instanceof Request ? request.url : String(request))
              .pathname,
          ),
      ),
    };
    const bindings = { ...env, ASSETS: { ...env.ASSETS, fetch: assets.fetch } };
    for (const path of ["/admin", "/admin/nodes", "/admin/assets/private.js"]) {
      const ctx = createExecutionContext();
      const denied = await worker.fetch(
        new Request(origin + path),
        bindings,
        ctx,
      );
      expect(denied.status).toBe(403);
      expect(assets.fetch).not.toHaveBeenCalled();
      const response = await worker.fetch(
        new Request(origin + path, {
          headers: { "Cf-Access-Jwt-Assertion": jwt },
        }),
        bindings,
        ctx,
      );
      expect(await response.text()).toBe(
        path.startsWith("/admin/assets/") ? path : "/admin/",
      );
      assets.fetch.mockClear();
      await waitOnExecutionContext(ctx);
    }
  });
  it("fails closed and validates signature, audience, expiry, and email", async () => {
    for (const t of [
      "",
      jwt.slice(0, -8) + "broken",
      await token("stranger@example.com"),
      await token("admin@example.com", "wrong"),
      await token("admin@example.com", "mate-tests", "-1h"),
    ]) {
      expect(
        (
          await request("/api/admin/dashboard", "GET", undefined, undefined, {
            admin: true,
            token: t,
          })
        ).status,
      ).toBe(403);
    }
    expect(
      (
        await request("/api/admin/dashboard", "GET", undefined, undefined, {
          admin: true,
        })
      ).status,
    ).toBe(200);
    const ctx = createExecutionContext();
    expect(
      (
        await worker.fetch(
          new Request(origin + "/api/admin/dashboard", {
            headers: { "Cf-Access-Jwt-Assertion": jwt },
          }),
          { ...env, ACCESS_AUD: "" },
          ctx,
        )
      ).status,
    ).toBe(403);
  });
  it("rejects cross-origin writes and does not let SPA routing swallow API errors", async () => {
    expect(
      (
        await request("/api/admin/nodes", "POST", { name: "bad" }, undefined, {
          admin: true,
          origin: "https://evil.example",
        })
      ).status,
    ).toBe(403);
    expect((await request("/api/missing")).status).toBe(404);
  });
  it("consumes enrollment once, hashes tokens, and rejects expired enrollment", async () => {
    const n = await create();
    expect(
      (await request("/api/agent/v1/enroll", "POST", { enrollment: n.code }))
        .status,
    ).toBe(401);
    const row = await env.DB.prepare(
      "SELECT token_hash,enroll_hash FROM nodes WHERE id=?",
    )
      .bind(n.node_id)
      .first<{ token_hash: string; enroll_hash: string | null }>();
    expect(row!.token_hash).toBe(await hash(n.token));
    expect(row!.token_hash).not.toBe(n.token);
    expect(row!.enroll_hash).toBeNull();
    const code = secret();
    await env.DB.prepare(
      "INSERT INTO nodes(id,name,enroll_hash,enroll_expires,created_at) VALUES(?,?,?,?,?)",
    )
      .bind(crypto.randomUUID(), "expired", await hash(code), 1, 1)
      .run();
    expect(
      (await request("/api/agent/v1/enroll", "POST", { enrollment: code }))
        .status,
    ).toBe(401);
  });
  it("isolates command acknowledgements by node and revokes bearer access", async () => {
    const a = await create("a"),
      b = await create("b");
    await request("/api/agent/v1/sync", "POST", sync(), a.token);
    await request("/api/agent/v1/sync", "POST", sync(), b.token);
    const cr = await request(
      "/api/admin/commands",
      "POST",
      [{ node_id: b.node_id, kind: "ban", jail: "sshd", ip: "8.8.8.8" }],
      undefined,
      { admin: true },
    );
    const { ids } = (await cr.json()) as { ids: string[] };
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({ results: [{ id: ids[0], status: "succeeded" }] }),
      a.token,
    );
    expect(
      (await env.DB.prepare("SELECT status FROM commands WHERE id=?")
        .bind(ids[0])
        .first<{ status: string }>())!.status,
    ).not.toBe("succeeded");
    await request(
      `/api/admin/nodes/${a.node_id}/revoke`,
      "POST",
      {},
      undefined,
      { admin: true },
    );
    expect(
      (await request("/api/agent/v1/sync", "POST", sync(), a.token)).status,
    ).toBe(401);
  });
});
describe("ban history", () => {
  async function dashboard() {
    const res = await request(
      "/api/admin/dashboard",
      "GET",
      undefined,
      undefined,
      { admin: true },
    );
    expect(res.status).toBe(200);
    return res.json<Data>();
  }
  const change = (seq: number, kind: "ban" | "unban", observed_at: number) => ({
    id: crypto.randomUUID(),
    seq,
    kind,
    observed_at,
    jail: "sshd",
    ip: "203.0.113.77",
    country: "United States",
    latitude: 40.7,
    longitude: -74,
  });

  it("retains separate periods after unban, reban and stale retries, including changes in the same second", async () => {
    const a = await create();
    const first = [change(1, "ban", 100), change(2, "unban", 100)];
    const send = (events: ReturnType<typeof change>[]) =>
      request(
        "/api/agent/v1/sync",
        "POST",
        sync({
          sequence: events.at(-1)!.seq,
          events,
          snapshot: undefined,
        }),
        a.token,
      );
    expect((await send(first)).status).toBe(200);
    const next = [change(3, "ban", 100), change(4, "unban", 200)];
    expect((await send(next)).status).toBe(200);
    expect((await send(first)).status).toBe(200);
    const data = await dashboard();
    expect(data.bans).toEqual([]);
    expect(data.ban_history).toHaveLength(2);
    expect(data.ban_history).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          observed_at: 100,
          unbanned_at: 100,
          ip: first[0].ip,
        }),
        expect.objectContaining({
          observed_at: 100,
          unbanned_at: 200,
          ip: first[0].ip,
        }),
      ]),
    );
    const publicRes = await request(
      "/api/public/dashboard?history=" + crypto.randomUUID(),
    );
    const publicData = await publicRes.json<PublicData>();
    expect(publicData.ban_history).toHaveLength(2);
    expect(publicData.ban_history![0]).toMatchObject({
      ip: "203.0.113.x",
      latitude: 40.7,
    });
    expect(JSON.stringify(publicData)).not.toMatch(
      /sshd|203\.0\.113\.77|edge-test/,
    );
    await request(
      `/api/admin/nodes/${a.node_id}`,
      "PATCH",
      { enabled: false },
      undefined,
      { admin: true },
    );
    const hidden = await request(
      "/api/public/dashboard?history=" + crypto.randomUUID(),
    );
    expect((await hidden.json<PublicData>()).ban_history).toEqual([]);
  });

  it("archives snapshot removals but leaves unchanged and unavailable jails active", async () => {
    const a = await create();
    const ban = { jail: "sshd", ip: "203.0.113.77", observed_at: 100 };
    const initial = sync({
      snapshot: {
        seq: 1,
        jails: [{ name: "sshd", bans: [ban] }],
        unavailable_jails: [],
      },
    });
    expect(
      (await request("/api/agent/v1/sync", "POST", initial, a.token)).status,
    ).toBe(200);
    await request("/api/agent/v1/sync", "POST", initial, a.token);
    expect((await dashboard()).ban_history).toEqual([]);
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 2,
        snapshot: { seq: 2, jails: [], unavailable_jails: ["sshd"] },
      }),
      a.token,
    );
    expect((await dashboard()).bans).toHaveLength(1);
    expect((await dashboard()).ban_history).toEqual([]);
    const removed = sync({
      sequence: 3,
      snapshot: { seq: 3, jails: [], unavailable_jails: [] },
    });
    await request("/api/agent/v1/sync", "POST", removed, a.token);
    await request("/api/agent/v1/sync", "POST", removed, a.token);
    const data = await dashboard();
    expect(data.bans).toEqual([]);
    expect(data.ban_history).toHaveLength(1);
    expect(data.ban_history![0]).toMatchObject(ban);
    expect(data.ban_history![0].unbanned_at).toBeGreaterThan(100);
  });

  it("recovers periods from an event backlog overtaken by a full snapshot", async () => {
    const a = await create();
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 100,
        snapshot: { seq: 100, jails: [], unavailable_jails: [] },
      }),
      a.token,
    );
    const events = [change(1, "ban", 100), change(2, "unban", 200)];
    expect(
      (
        await request(
          "/api/agent/v1/sync",
          "POST",
          sync({ sequence: 2, events, snapshot: undefined }),
          a.token,
        )
      ).status,
    ).toBe(200);
    const data = await dashboard();
    expect(data.bans).toEqual([]);
    expect(data.ban_history).toMatchObject([
      { observed_at: 100, unbanned_at: 200 },
    ]);
  });

  it("replaces snapshot fallback times with a late observed unban without duplicating history", async () => {
    const a = await create();
    const ban = change(1, "ban", 100);
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        snapshot: {
          seq: 1,
          jails: [{ name: "sshd", bans: [ban] }],
          unavailable_jails: [],
        },
      }),
      a.token,
    );
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 100,
        snapshot: { seq: 100, jails: [], unavailable_jails: [] },
      }),
      a.token,
    );
    expect((await dashboard()).ban_history).toHaveLength(1);
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 2,
        events: [ban, change(2, "unban", 200)],
        snapshot: undefined,
      }),
      a.token,
    );
    expect((await dashboard()).ban_history).toMatchObject([
      { observed_at: 100, unbanned_at: 200 },
    ]);
  });

  it("expires released history by release time and preserves current bans", async () => {
    const a = await create();
    const now = Math.floor(Date.now() / 1000);
    const events = [
      change(1, "ban", 1),
      change(2, "unban", now - 366 * 86400),
      change(3, "ban", 2),
      change(4, "unban", now - 1),
      change(5, "ban", 3),
    ];
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({ sequence: 5, events, snapshot: undefined }),
      a.token,
    );
    await cleanup({ ...env, RETENTION_DAYS: "365" });
    const data = await dashboard();
    expect(data.bans).toHaveLength(1);
    expect(data.ban_history).toMatchObject([
      { observed_at: 2, unbanned_at: now - 1 },
    ]);
  });
});
describe("sync and commands", () => {
  it("keeps authenticated node sockets across hibernation, pushes config and closes revoked connections", async () => {
    const a = await create();
    const ctx = createExecutionContext();
    const res = await worker.fetch(
      new Request(origin + "/api/agent/v1/ws", {
        headers: { Upgrade: "websocket", Authorization: "Bearer " + a.token },
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(101);
    const ws = res.webSocket!;
    ws.accept();
    const next = () =>
      new Promise<ServerSync>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("websocket message timeout")),
          5000,
        );
        ws.addEventListener(
          "message",
          (e) => {
            clearTimeout(timer);
            resolve(JSON.parse(e.data as string));
          },
          { once: true },
        );
      });
    let message = next();
    ws.send(JSON.stringify(sync()));
    expect((await message).protocol).toBe(1);
    await evictDurableObject(env.NODES.get(env.NODES.idFromName(a.node_id)));
    message = next();
    ws.send(
      JSON.stringify(
        sync({
          sequence: 2,
          snapshot: {
            seq: 2,
            jails: [{ name: "sshd", bans: [] }],
            unavailable_jails: [],
          },
        }),
      ),
    );
    expect((await message).ack_snapshot_seq).toBe(2);
    message = next();
    await request(
      `/api/admin/nodes/${a.node_id}`,
      "PATCH",
      { mode: "polling" },
      undefined,
      { admin: true },
    );
    expect((await message).config.mode).toBe("polling");
    const closed = new Promise<number>((resolve) =>
      ws.addEventListener("close", (e) => resolve(e.code), { once: true }),
    );
    await request(
      `/api/admin/nodes/${a.node_id}/revoke`,
      "POST",
      {},
      undefined,
      { admin: true },
    );
    ws.close();
    expect(await closed).toBe(4003);
    ws.close();
    await waitOnExecutionContext(ctx);
  });
  it("deduplicates events and stale retries cannot overwrite a newer snapshot", async () => {
    const a = await create();
    const event = {
      id: crypto.randomUUID(),
      seq: 2,
      kind: "ban" as const,
      jail: "sshd",
      ip: "8.8.8.8",
      observed_at: 100,
    };
    const first = sync({ sequence: 2, events: [event], snapshot: undefined });
    expect(
      (await request("/api/agent/v1/sync", "POST", first, a.token)).status,
    ).toBe(200);
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 3,
        snapshot: {
          seq: 3,
          jails: [{ name: "sshd", bans: [] }],
          unavailable_jails: [],
        },
      }),
      a.token,
    );
    await request("/api/agent/v1/sync", "POST", first, a.token);
    expect(
      await env.DB.prepare("SELECT COUNT(*) n FROM events").first("n"),
    ).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) n FROM bans").first("n")).toBe(
      0,
    );
  });
  it("preserves failed jail state, removes vanished jails, and acknowledges committed snapshots", async () => {
    const a = await create();
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        snapshot: {
          seq: 1,
          jails: [
            {
              name: "sshd",
              bans: [{ jail: "sshd", ip: "8.8.8.8", observed_at: 100 }],
            },
            {
              name: "old",
              bans: [{ jail: "old", ip: "1.1.1.1", observed_at: 100 }],
            },
          ],
          unavailable_jails: [],
        },
      }),
      a.token,
    );
    const res = await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        sequence: 2,
        snapshot: { seq: 2, jails: [], unavailable_jails: ["sshd"] },
      }),
      a.token,
    );
    expect(((await res.json()) as ServerSync).ack_snapshot_seq).toBe(2);
    expect(await env.DB.prepare("SELECT jail FROM bans").all()).toMatchObject({
      results: [{ jail: "sshd" }],
    });
  });
  it("delivers, retries, acknowledges, and expires commands", async () => {
    const a = await create();
    await request("/api/agent/v1/sync", "POST", sync(), a.token);
    const res = await request(
      "/api/admin/commands",
      "POST",
      [{ node_id: a.node_id, kind: "ban", jail: "sshd", ip: "8.8.8.8" }],
      undefined,
      { admin: true },
    );
    expect(res.status).toBe(201);
    const { ids } = (await res.json()) as { ids: string[] };
    const p = sync({ snapshot: undefined });
    for (let i = 0; i < 2; i++) {
      const r = await request("/api/agent/v1/sync", "POST", p, a.token);
      expect(((await r.json()) as ServerSync).commands[0].id).toBe(ids[0]);
    }
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({ results: [{ id: ids[0], status: "succeeded" }] }),
      a.token,
    );
    expect(
      await env.DB.prepare("SELECT status FROM commands WHERE id=?")
        .bind(ids[0])
        .first("status"),
    ).toBe("succeeded");
    const cmd = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO commands(id,node_id,kind,jail,ip,created_at,expires_at,actor) VALUES(?,?,?,?,?,?,?,?)",
    )
      .bind(cmd, a.node_id, "unban", "sshd", "1.1.1.1", 1, 2, "test")
      .run();
    await request("/api/agent/v1/sync", "POST", p, a.token);
    expect(
      await env.DB.prepare("SELECT status FROM commands WHERE id=?")
        .bind(cmd)
        .first("status"),
    ).toBe("expired");
  });
  it("propagates global whitelist to two nodes and new nodes and blocks bans", async () => {
    const a = await create("a"),
      b = await create("b");
    await request("/api/agent/v1/sync", "POST", sync(), a.token);
    expect(
      (
        await request(
          "/api/admin/whitelist",
          "POST",
          { ip: "8.8.8.8", duration: null },
          undefined,
          { admin: true },
        )
      ).status,
    ).toBe(201);
    const c = await create("c");
    for (const n of [a, b, c]) {
      const res = await request("/api/agent/v1/sync", "POST", sync(), n.token);
      expect(((await res.json()) as ServerSync).policies).toMatchObject([
        { ip: "8.8.8.8", expires_at: null },
      ]);
    }
    expect(
      (
        await request(
          "/api/admin/commands",
          "POST",
          [{ node_id: a.node_id, kind: "ban", jail: "sshd", ip: "8.8.8.8" }],
          undefined,
          { admin: true },
        )
      ).status,
    ).toBe(409);
    await env.DB.prepare("UPDATE whitelist SET expires_at=1").run();
    const r = await request("/api/agent/v1/sync", "POST", sync(), a.token);
    expect(((await r.json()) as ServerSync).policies).toEqual([]);
  });
  it("switches config and prevents validation/command injection", async () => {
    const a = await create();
    await request(
      `/api/admin/nodes/${a.node_id}`,
      "PATCH",
      { mode: "polling", poll_interval: 5 },
      undefined,
      { admin: true },
    );
    const r = await request("/api/agent/v1/sync", "POST", sync(), a.token);
    expect(((await r.json()) as ServerSync).config).toMatchObject({
      revision: 2,
      mode: "polling",
      poll_interval: 5,
    });
    expect(
      (
        await request(
          "/api/admin/commands",
          "POST",
          [
            {
              node_id: a.node_id,
              kind: "ban",
              jail: "sshd; touch /tmp/evil",
              ip: "8.8.8.8",
            },
          ],
          undefined,
          { admin: true },
        )
      ).status,
    ).toBe(400);
    expect(
      syncSchema.safeParse(
        sync({
          sequence: 1,
          events: [
            {
              id: crypto.randomUUID(),
              seq: 2,
              kind: "ban",
              jail: "sshd",
              ip: "1.1.1.1",
              observed_at: 1,
            },
          ],
        }),
      ).success,
    ).toBe(false);
  });
});
describe("public privacy", () => {
  it("keeps dashboard snapshots at the edge without caching them in browsers", async () => {
    const a = await create();
    await env.DB.prepare(
      "INSERT INTO bans(node_id,jail,ip,observed_at) VALUES(?,?,?,?)",
    )
      .bind(a.node_id, "sshd", "203.0.113.77", 100)
      .run();
    const path = "/api/public/dashboard?cache-test=" + crypto.randomUUID();
    const legacyKey = new Request(origin + path);
    const cacheURL = new URL(origin + path);
    cacheURL.searchParams.set("__public_schema", "3");
    const key = new Request(cacheURL);
    const cache = (caches as unknown as { default: Cache }).default;
    try {
      await cache.put(
        legacyKey,
        Response.json(
          { bans: [{ jail: "private-service" }] },
          {
            headers: { "Cache-Control": "public, max-age=10" },
          },
        ),
      );
      const first = await request(path);
      expect(first.headers.get("Cache-Control")).toBe("no-store");
      const firstData = await first.json<{ bans: Record<string, unknown>[] }>();
      expect(firstData).toMatchObject({ bans: [{ ip: "203.0.113.x" }] });
      expect(firstData.bans[0]).not.toHaveProperty("jail");
      expect(JSON.stringify(firstData)).not.toMatch(/sshd|private-service/);
      const stored = await cache.match(key);
      expect(stored?.headers.get("Cache-Control")).toBe("public, max-age=10");

      await env.DB.prepare(
        "INSERT INTO bans(node_id,jail,ip,observed_at) VALUES(?,?,?,?)",
      )
        .bind(a.node_id, "sshd", "198.51.100.88", 101)
        .run();
      const warm = await request(path);
      expect(warm.headers.get("Cache-Control")).toBe("no-store");
      const warmData = await warm.json<{ bans: Record<string, unknown>[] }>();
      expect(warmData.bans).toHaveLength(1);
      expect(warmData.bans[0]).not.toHaveProperty("jail");
      expect(JSON.stringify(warmData)).not.toMatch(/sshd|private-service/);
      // Serving the hit must not change the cached response's edge TTL.
      expect((await cache.match(key))?.headers.get("Cache-Control")).toBe(
        "public, max-age=10",
      );

      await cache.delete(key);
      const fresh = await request(path);
      expect(fresh.headers.get("Cache-Control")).toBe("no-store");
      expect((await fresh.json<{ bans: unknown[] }>()).bans).toHaveLength(2);
    } finally {
      await cache.delete(key);
      await cache.delete(legacyKey);
    }
  });
  it("records both observed address families without overwriting one with the other", async () => {
    const a = await create();
    const b = await create("other-node");
    expect((await request("/api/agent/v1/addresses")).status).toBe(401);
    for (const ip of ["2001:db8:1::99", "192.0.2.99", "::ffff:192.0.2.99"]) {
      expect(
        (
          await request("/api/agent/v1/addresses", "GET", undefined, a.token, {
            ip,
          })
        ).status,
      ).toBe(200);
    }
    // Normal synchronization also learns its transport's family and keeps the other.
    await request("/api/agent/v1/sync", "POST", sync(), a.token, {
      ip: "2001:db8:2::88",
    });
    expect(
      await env.DB.prepare("SELECT ipv4,ipv6 FROM nodes WHERE id=?")
        .bind(a.node_id)
        .first(),
    ).toEqual({ ipv4: "192.0.2.99", ipv6: "2001:db8:2::88" });
    expect(
      await env.DB.prepare("SELECT ipv4,ipv6 FROM nodes WHERE id=?")
        .bind(b.node_id)
        .first(),
    ).toEqual({ ipv4: null, ipv6: null });
    expect(
      (
        await request("/api/agent/v1/addresses", "GET", undefined, a.token, {
          ip: "invalid",
        })
      ).status,
    ).toBe(503);
    const publicResponse = await request(
      "/api/public/dashboard?dual-stack=" + crypto.randomUUID(),
    );
    const data = (await publicResponse.json()) as {
      nodes: { id: string; ipv4: string | null; ipv6: string | null }[];
    };
    expect(data.nodes.find((n) => n.id === a.node_id)).toMatchObject({
      ipv4: "192.0.x.x",
      ipv6: "2001:db8:x:x:x:x:x:x",
    });
    const publicText = JSON.stringify(data);
    expect(publicText).not.toContain("192.0.2.99");
    expect(publicText).not.toContain("2001:db8:2::88");
    const privateData = (await (
      await request("/api/admin/dashboard", "GET", undefined, undefined, {
        admin: true,
      })
    ).json()) as { nodes: { id: string; ipv4: string; ipv6: string }[] };
    expect(privateData.nodes.find((n) => n.id === a.node_id)).toMatchObject({
      ipv4: "192.0.2.99",
      ipv6: "2001:db8:2::88",
    });
    await request(
      `/api/admin/nodes/${a.node_id}/revoke`,
      "POST",
      {},
      undefined,
      { admin: true },
    );
    expect(
      (
        await request("/api/agent/v1/addresses", "GET", undefined, a.token, {
          ip: "192.0.2.100",
        })
      ).status,
    ).toBe(401);
  });
  it("preserves real IPv6 when Cloudflare supplies a Pseudo IPv4 hash", async () => {
    const headers = {
      "CF-Connecting-IP": "240.1.2.3",
      "CF-Connecting-IPv6": "2001:db8::99",
    };
    expect(connectingAddress(new Request(origin, { headers }))).toBe(
      "2001:db8::99",
    );
    expect(
      connectingAddress(
        new Request(origin, {
          headers: {
            "CF-Connecting-IP": "192.0.2.9",
            "CF-Connecting-IPv6": "2001:db8::99",
          },
        }),
      ),
    ).toBe("192.0.2.9");
    const a = await create();
    await request("/api/agent/v1/addresses", "GET", undefined, a.token, {
      ip: headers["CF-Connecting-IP"],
      ipv6: headers["CF-Connecting-IPv6"],
    });
    expect(
      await env.DB.prepare("SELECT ipv4,ipv6 FROM nodes WHERE id=?")
        .bind(a.node_id)
        .first(),
    ).toEqual({ ipv4: null, ipv6: "2001:db8::99" });
  });
  it("masks IPv4, mapped IPv4, compressed IPv6 and rejects non-addresses", () => {
    expect(maskIP("1.2.3.4")).toBe("1.2.3.x");
    expect(maskIP("1.2.3.4", true)).toBe("1.2.x.x");
    expect(maskIP("::ffff:1.2.3.4")).toBe("1.2.3.x");
    expect(maskIP("2001:db8::1")).toBe("2001:db8:0:x:x:x:x:x");
    expect(maskIP("2001:db8::1", true)).toBe("2001:db8:x:x:x:x:x:x");
    for (const value of [
      "127.1",
      "012.1.1.1",
      "8.8.8.8/24",
      "fe80::1%eth0",
      "x",
    ])
      expect(() => canonicalIP(value)).toThrow();
  });
  it("only returns explicit public fields, including empty and unknown geography", async () => {
    const a = await create("PRIVATE-HOST");
    await env.DB.prepare(
      "UPDATE nodes SET ip='192.0.2.99',city='Singapore' WHERE id=?",
    )
      .bind(a.node_id)
      .run();
    await request(
      "/api/agent/v1/sync",
      "POST",
      sync({
        snapshot: {
          seq: 1,
          jails: [
            {
              name: "sshd",
              bans: [{ jail: "sshd", ip: "203.0.113.77", observed_at: 100 }],
            },
          ],
          unavailable_jails: [],
        },
      }),
      a.token,
    );
    const res = await request(
      "/api/public/dashboard?privacy-test=" + crypto.randomUUID(),
    );
    const text = await res.text();
    for (const value of [
      "192.0.2.99",
      "203.0.113.77",
      "PRIVATE-HOST",
      a.token,
      "token_hash",
      "enroll_hash",
      "sshd",
      "jail",
    ])
      expect(text).not.toContain(value);
    expect(text).toContain("203.0.113.x");
    expect(text).toContain("192.0.x.x");
  });
});

describe("dynamic whitelist integrations", () => {
  const manage = "/api/admin/integrations";
  const rule = "/api/integrations/v1/whitelist/home";
  const adminOptions = { admin: true };
  const a = "198.51.100.13";
  const b = "198.51.100.14";
  const status = (method: string, bearer?: string, ip = a) =>
    request(rule, method, method === "PUT" ? { ip } : undefined, bearer);
  async function issue(name = "CDSG") {
    const res = await request(
      manage,
      "POST",
      { name },
      undefined,
      adminOptions,
    );
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    return res.json<{ id: string; token: string }>();
  }

  it("requires scoped credentials, keeps metadata private, and validates addresses", async () => {
    const c = await issue();
    const node = await create();
    expect(c.token).toMatch(/^f2bm_[0-9a-f]{64}$/);
    for (const bearer of [undefined, "invalid", node.token]) {
      expect((await status("PUT", bearer)).status).toBe(401);
    }
    expect((await request(manage, "GET", undefined, c.token)).status).toBe(403);
    expect(
      (await request("/api/agent/v1/addresses", "GET", undefined, c.token))
        .status,
    ).toBe(401);
    expect(
      (
        await request(manage, "POST", { name: "x" }, undefined, {
          ...adminOptions,
          origin: "https://untrusted.example",
        })
      ).status,
    ).toBe(403);
    expect((await status("PUT", c.token, a + "/32")).status).toBe(400);
    expect((await status("PUT", c.token, "2001:0db8::1")).status).toBe(200);
    expect(
      (await (await status("GET", c.token)).json<{ ip: string }>()).ip,
    ).toBe("2001:db8::1");
    const list = await (
      await request(manage, "GET", undefined, undefined, adminOptions)
    ).text();
    expect(list).toContain(c.token.slice(0, 13));
    expect(list).not.toContain(c.token);
    expect(list).not.toContain(await hash(c.token));
    const publicData = await (
      await request("/api/public/dashboard?integration-test=1")
    ).json();
    expect(publicData).not.toHaveProperty("integrations");
    expect(publicData).not.toHaveProperty("policies");
  });

  it("renews and replaces a single rule while keeping other sources and syncing nodes", async () => {
    const c = await issue();
    const other = await issue("Other");
    const node = await create();
    const clock = vi.spyOn(Date, "now");
    const at = Math.floor(Date.now() / 1000);
    clock.mockReturnValue(at * 1000);
    try {
      const put = async (bearer: string, ip: string) => {
        const res = await status("PUT", bearer, ip);
        expect(res.status).toBe(200);
        return res.json<{
          id: string;
          key: string;
          ip: string;
          expires_at: number;
          policy_revision: number;
        }>();
      };
      const first = await put(c.token, a);
      expect(first).toMatchObject({
        ip: a,
        key: "home",
        expires_at: at + 86400,
        policy_revision: 2,
      });
      expect((await status("GET", other.token)).status).toBe(404);
      clock.mockReturnValue((at + 60) * 1000);
      const renewal = await put(c.token, a);
      expect(renewal).toMatchObject({
        id: first.id,
        expires_at: at + 60 + 86400,
        policy_revision: 3,
      });
      expect(
        await env.DB.prepare(
          "SELECT count(*) AS n FROM audit WHERE action='dynamic_whitelist.upsert'",
        ).first("n"),
      ).toBe(1);

      await put(other.token, a);
      await request(
        "/api/admin/whitelist",
        "POST",
        { ip: a, duration: null },
        undefined,
        adminOptions,
      );
      const replaced = await put(c.token, b);
      expect(replaced).toMatchObject({ id: first.id, ip: b });

      const state = await (
        await request("/api/agent/v1/sync", "POST", sync(), node.token)
      ).json<ServerSync>();
      expect(state.policies.map((p) => p.ip).sort()).toEqual([a, a, b]);
      expect(state.policy_revision).toBe(replaced.policy_revision);
      const ban = await request(
        "/api/admin/commands",
        "POST",
        [{ node_id: node.node_id, jail: "sshd", kind: "ban", ip: b }],
        undefined,
        adminOptions,
      );
      expect(ban.status).toBe(409);

      expect((await status("DELETE", other.token)).status).toBe(200);
      expect((await status("DELETE", other.token)).status).toBe(200);
      expect((await status("GET", c.token)).status).toBe(200);
      clock.mockReturnValue(replaced.expires_at * 1000);
      expect((await status("GET", c.token)).status).toBe(404);
      await cleanup(env);
      expect(
        await env.DB.prepare(
          "SELECT count(*) AS n FROM dynamic_whitelist",
        ).first("n"),
      ).toBe(0);
      const after = await (
        await request("/api/agent/v1/sync", "POST", sync(), node.token)
      ).json<ServerSync>();
      expect(after.policies.map((p) => p.ip)).toEqual([a]);
    } finally {
      clock.mockRestore();
    }
  });

  it("rotates credentials without removing rules and rejects a PUT racing with revocation", async () => {
    const c = await issue();
    const first = await (await status("PUT", c.token)).json<{ id: string }>();
    const rotated = await request(
      `${manage}/${c.id}/rotate`,
      "POST",
      undefined,
      undefined,
      adminOptions,
    );
    expect(rotated.status).toBe(200);
    const { token } = await rotated.json<{ token: string }>();
    expect((await status("PUT", c.token)).status).toBe(401);
    expect((await (await status("GET", token)).json<{ id: string }>()).id).toBe(
      first.id,
    );
    const ctx = createExecutionContext();
    const req = new Request(origin + rule, {
      method: "PUT",
      headers: { Authorization: "Bearer " + token },
    });
    // Revoke after request authentication and before its write batch.
    const readBody = vi.spyOn(req, "text").mockImplementation(async () => {
      expect(
        (
          await request(
            `${manage}/${c.id}/revoke`,
            "POST",
            undefined,
            undefined,
            adminOptions,
          )
        ).status,
      ).toBe(200);
      return JSON.stringify({ ip: b });
    });
    expect((await worker.fetch(req, env, ctx)).status).toBe(401);
    await waitOnExecutionContext(ctx);
    expect(readBody).toHaveBeenCalledOnce();
    expect((await status("GET", token)).status).toBe(401);
    expect(
      await env.DB.prepare("SELECT count(*) AS n FROM dynamic_whitelist").first(
        "n",
      ),
    ).toBe(0);
    expect(
      await env.DB.prepare(
        "SELECT count(*) AS n FROM audit WHERE action='dynamic_whitelist.upsert'",
      ).first("n"),
    ).toBe(1);
    expect(
      await env.DB.prepare("SELECT policy_revision FROM settings").first(
        "policy_revision",
      ),
    ).toBe(3);
  });

  it("rolls back the rule and audit if the revision cannot be written", async () => {
    const c = await issue();
    await env.DB.prepare(
      "CREATE TRIGGER fail_revision BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT,'test failure'); END",
    ).run();
    try {
      expect((await status("PUT", c.token)).status).toBe(500);
      expect((await status("GET", c.token)).status).toBe(404);
      expect(
        await env.DB.prepare(
          "SELECT count(*) AS n FROM audit WHERE action='dynamic_whitelist.upsert'",
        ).first("n"),
      ).toBe(0);
      expect(
        await env.DB.prepare("SELECT last_used_at FROM integrations").first(
          "last_used_at",
        ),
      ).toBeNull();
    } finally {
      await env.DB.prepare("DROP TRIGGER fail_revision").run();
    }
  });
});

describe("UFW rule group publishing", () => {
  const root = "/api/admin/firewall";
  const admin = { admin: true };
  const rule = (priority: number, action: "allow" | "deny" = "allow") => ({
    id: crypto.randomUUID(),
    priority,
    enabled: true,
    direction: "in" as const,
    action,
    family: "ipv4" as const,
    protocol: "tcp" as const,
    source: "192.0.2.10",
    destination: "",
    source_port: "",
    destination_port: "22",
    in_interface: "",
    out_interface: "",
    comment: "SSH",
  });
  const snapshot = () => ({
    status: "active" as const,
    observed_at: Math.floor(Date.now() / 1000),
    fingerprint: "a".repeat(64),
    ipv6: true,
    defaults: {
      in: "deny" as const,
      out: "allow" as const,
      route: "deny" as const,
    },
    rules: [rule(10)],
    protection: [{ source: "192.0.2.10", port: 22 }],
  });

  it("isolates drafts, orders bindings and rules, and tracks per-node results", async () => {
    const a = await create("UFW A");
    const b = await create("UFW B");
    const obs = snapshot();
    const draftPath = (nodeID: string) => root + "/nodes/" + nodeID;
    const syncNode = async (n: typeof a, extra: Partial<AgentSync> = {}) => {
      const response = await request(
        "/api/agent/v1/sync",
        "POST",
        sync(extra),
        n.token,
      );
      expect(response.status).toBe(200);
      return response.json<ServerSync>();
    };
    expect((await request(root + "/groups")).status).toBe(403);
    expect(
      (
        await request(
          root + "/groups",
          "POST",
          { name: "bad", rules: [] },
          undefined,
          { ...admin, origin: "https://other.example" },
        )
      ).status,
    ).toBe(403);
    expect((await syncNode(a)).firewall).toBeUndefined();
    await syncNode(a, { firewall: obs });
    await syncNode(b, { firewall: obs });
    const imported = await request(
      draftPath(a.node_id) + "/import",
      "POST",
      {},
      undefined,
      admin,
    );
    expect(imported.status).toBe(201);
    expect(
      (
        await request(
          draftPath(a.node_id) + "/import",
          "POST",
          {},
          undefined,
          admin,
        )
      ).status,
    ).toBe(409);
    const group = await (
      await request(
        root + "/groups",
        "POST",
        {
          name: "Main",
          rules: [rule(20, "deny"), rule(10)],
        },
        undefined,
        admin,
      )
    ).json<{ id: string; revision: number; rules: unknown[] }>();
    const earlier = await (
      await request(
        root + "/groups",
        "POST",
        {
          name: "Earlier",
          rules: [{ ...rule(30), comment: "group first" }],
        },
        undefined,
        admin,
      )
    ).json<{ id: string }>();
    const config = {
      defaults: obs.defaults,
      protection: obs.protection,
      bindings: [
        { group_id: group.id, priority: 20 },
        { group_id: earlier.id, priority: 10 },
      ],
    };
    expect(
      (
        await request(
          draftPath(a.node_id) + "/draft",
          "PUT",
          { ...config, revision: 1 },
          undefined,
          admin,
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await request(
          draftPath(a.node_id) + "/draft",
          "PUT",
          { ...config, revision: 1 },
          undefined,
          admin,
        )
      ).status,
    ).toBe(409);
    expect(
      (
        await request(
          draftPath(b.node_id) + "/draft",
          "PUT",
          { ...config, revision: 0 },
          undefined,
          admin,
        )
      ).status,
    ).toBe(200);
    expect((await syncNode(a)).firewall).toBeUndefined();
    const getPreview = async () => {
      const r = await request(
        draftPath(a.node_id) + "/preview",
        "POST",
        {},
        undefined,
        admin,
      );
      expect(r.status).toBe(200);
      return r.json<{
        version: string;
        after: { rules: { comment: string; action: string }[] };
        affected: { id: string }[];
      }>();
    };
    const initial = await getPreview();
    expect(initial.affected.map((n) => n.id)).toEqual([a.node_id, b.node_id]);
    expect(initial.after.rules.map((r) => [r.comment, r.action])).toEqual([
      ["group first", "allow"],
      ["SSH", "allow"],
      ["SSH", "deny"],
    ]);
    const update = await request(
      root + "/groups/" + group.id,
      "PUT",
      { ...group, name: "Updated" },
      undefined,
      admin,
    );
    expect(update.status).toBe(200);
    expect(
      (
        await request(
          root + "/publish",
          "POST",
          [{ node_id: a.node_id, version: initial.version }],
          undefined,
          admin,
        )
      ).status,
    ).toBe(409);
    const version = (await getPreview()).version;
    const publish = await request(
      root + "/publish",
      "POST",
      [
        { node_id: a.node_id, version },
        { node_id: b.node_id, version: "0".repeat(64) },
      ],
      undefined,
      admin,
    );
    expect(publish.status).toBe(200);
    const queued = await publish.json<{
      outcomes: { id?: string; error?: string }[];
    }>();
    expect(queued.outcomes[0].id).toBeTruthy();
    expect(queued.outcomes[1].error).toBeTruthy();
    const job = (await syncNode(a)).firewall!;
    expect(job.node_id).toBe(a.node_id);
    expect((await syncNode(b)).firewall).toBeUndefined();
    const claim = "/api/agent/v1/firewall/claim?id=" + job.id;
    const confirm = "/api/agent/v1/firewall/confirm?id=" + job.id;
    expect((await request(claim, "POST", undefined, b.token)).status).toBe(409);
    expect((await request(confirm, "POST", undefined, a.token)).status).toBe(
      409,
    );
    expect((await request(claim, "POST", undefined, a.token)).status).toBe(204);
    expect((await request(confirm, "POST", undefined, a.token)).status).toBe(
      204,
    );
    await syncNode(b, { firewall_receipt: { id: job.id, status: "applied" } });
    expect((await syncNode(a)).firewall?.id).toBe(job.id);
    expect(
      (
        await syncNode(a, {
          firewall_receipt: { id: job.id, status: "applied" },
        })
      ).firewall,
    ).toBeUndefined();
    await syncNode(a, { firewall_receipt: { id: job.id, status: "failed" } });
    const detail = await (
      await request(draftPath(a.node_id), "GET", undefined, undefined, admin)
    ).json<{ history: { status: string }[] }>();
    expect(detail.history[0].status).toBe("applied");
    const publicBody = await (await request("/api/public/dashboard")).text();
    expect(publicBody).not.toContain(job.id);
    expect(publicBody).not.toContain("group first");
  });
});
