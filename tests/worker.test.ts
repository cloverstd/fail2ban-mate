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
import worker from "../worker";
import { hash, secret } from "../worker/auth";
import { maskIP } from "../worker/privacy";
import { canonicalIP, syncSchema } from "../worker/validation";
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
  opts: { admin?: boolean; origin?: string; token?: string } = {},
) {
  const headers = new Headers();
  if (body !== undefined) headers.set("Content-Type", "application/json");
  if (bearer) headers.set("Authorization", "Bearer " + bearer);
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
    ["commands", "events", "bans", "nodes", "whitelist", "audit"].map((t) =>
      env.DB.prepare(`DELETE FROM ${t}`),
    ),
  );
  await env.DB.prepare("UPDATE settings SET policy_revision=1").run();
});
afterAll(() => vi.unstubAllGlobals());
describe("access and enrollment", () => {
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
    ])
      expect(text).not.toContain(value);
    expect(text).toContain("203.0.113.x");
    expect(text).toContain("192.0.x.x");
  });
});
