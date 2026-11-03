import { DurableObject } from "cloudflare:workers";
import type { Env, NodeRow } from "./env";
import { syncSchema } from "./validation";
import { ingest, notifyDashboard, responseFor } from "./sync";

interface AgentAttachment {
  id: string;
  hash: string;
  geo: Record<string, unknown>;
}
export class NodeConnection extends DurableObject<Env> {
  private queue: Promise<unknown> = Promise.resolve();
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.catch(() => {}).then(fn);
    this.queue = p;
    return p;
  }
  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/close") {
      for (const ws of this.ctx.getWebSockets())
        ws.close(4003, "Node credentials revoked");
      return new Response("ok");
    }
    if (path === "/wake")
      return this.serial(async () => {
        const node = await this.env.DB.prepare(
          "SELECT * FROM nodes WHERE id=? AND enabled=1",
        )
          .bind(request.headers.get("x-node-id"))
          .first<NodeRow>();
        if (node) {
          const msg = JSON.stringify(await responseFor(this.env, node));
          for (const ws of this.ctx.getWebSockets())
            try {
              ws.send(msg);
            } catch {
              ws.close(1011, "Delivery failed");
            }
        }
        return new Response("ok");
      });
    const id = request.headers.get("x-node-id"),
      hash = request.headers.get("x-node-hash");
    const node = await this.env.DB.prepare(
      "SELECT * FROM nodes WHERE id=? AND token_hash=? AND enabled=1",
    )
      .bind(id, hash)
      .first<NodeRow>();
    if (!node) return new Response("Unauthorized", { status: 401 });
    const geo = JSON.parse(request.headers.get("x-node-geo") ?? "{}") as Record<
      string,
      unknown
    >;
    if (path === "/connect") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
        return new Response("WebSocket required", { status: 426 });
      for (const old of this.ctx.getWebSockets())
        old.close(4001, "Replaced by a new connection");
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({
        id: node.id,
        hash: node.token_hash!,
        geo,
      } satisfies AgentAttachment);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (path === "/sync") {
      const body = syncSchema.safeParse(await request.json());
      if (!body.success)
        return Response.json(
          { error: "Invalid sync message", issues: body.error.issues },
          { status: 400 },
        );
      return this.serial(async () => {
        const current = await this.env.DB.prepare(
          "SELECT * FROM nodes WHERE id=? AND token_hash=? AND enabled=1",
        )
          .bind(id, hash)
          .first<NodeRow>();
        if (!current) return new Response("Unauthorized", { status: 401 });
        const msg = await ingest(this.env, current, body.data, geo);
        await notifyDashboard(this.env);
        return Response.json(msg);
      });
    }
    return new Response("Not found", { status: 404 });
  }
  async webSocketMessage(
    ws: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    await this.serial(async () => {
      const a = ws.deserializeAttachment() as AgentAttachment;
      const node = await this.env.DB.prepare(
        "SELECT * FROM nodes WHERE id=? AND token_hash=? AND enabled=1",
      )
        .bind(a.id, a.hash)
        .first<NodeRow>();
      if (!node) {
        ws.close(4003, "Unauthorized");
        return;
      }
      if (typeof message !== "string" || message.length > 8 * 1024 * 1024) {
        ws.close(1009, "Message too large");
        return;
      }
      let data: unknown;
      try {
        data = JSON.parse(message);
      } catch {
        ws.close(1007, "Invalid JSON");
        return;
      }
      const p = syncSchema.safeParse(data);
      if (!p.success) {
        ws.close(1008, "Invalid sync message");
        return;
      }
      try {
        const msg = await ingest(this.env, node, p.data, a.geo);
        ws.send(JSON.stringify(msg));
        await notifyDashboard(this.env);
      } catch {
        ws.close(1011, "Sync failed; retry pending messages");
      }
    });
  }
  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
  ): Promise<void> {
    ws.close(code, reason);
  }
  async webSocketError(ws: WebSocket): Promise<void> {
    ws.close(1011, "Connection error");
  }
}

export class Dashboard extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === "/notify") {
      for (const ws of this.ctx.getWebSockets()) {
        const { exp } = ws.deserializeAttachment() as { exp: number };
        if (exp * 1000 <= Date.now()) ws.close(4003, "Session expired");
        else
          try {
            ws.send(JSON.stringify({ type: "invalidate" }));
          } catch {
            ws.close(1011, "Disconnected");
          }
      }
      return new Response("ok");
    }
    const exp = Number(request.headers.get("x-auth-exp"));
    if (!exp || exp * 1000 <= Date.now())
      return new Response("Unauthorized", { status: 401 });
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ exp });
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > exp * 1000)
      await this.ctx.storage.setAlarm(exp * 1000);
    return new Response(null, { status: 101, webSocket: client });
  }
  async alarm(): Promise<void> {
    let next = Infinity;
    for (const ws of this.ctx.getWebSockets()) {
      const { exp } = ws.deserializeAttachment() as { exp: number };
      if (exp * 1000 <= Date.now()) ws.close(4003, "Session expired");
      else next = Math.min(next, exp * 1000);
    }
    if (Number.isFinite(next)) await this.ctx.storage.setAlarm(next);
  }
  async webSocketMessage(): Promise<void> {
    /* invalidation-only connection */
  }
  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
  ): Promise<void> {
    ws.close(code, reason);
  }
}
