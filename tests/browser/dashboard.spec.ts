import { test, expect, type Page } from "@playwright/test";
import { createServer } from "node:http";
import type { Data } from "../../web/types";
const now = Math.floor(Date.now() / 1000);
const fixture: Data = {
  generated_at: now,
  actor: "admin@example.com",
  policy_revision: 1,
  nodes: [
    {
      id: "a",
      name: "Singapore · edge-01",
      ip: "192.0.2.9",
      ipv4: "192.0.2.9",
      ipv6: "2001:db8:1::9",
      country: "Singapore",
      city: "Singapore",
      latitude: 1.35,
      longitude: 103.8,
      online: true,
      last_seen: now,
      observed_at: now,
      enabled: 1,
      has_token: true,
      jails: ["sshd", "nginx-auth"],
      mode: "websocket",
      actual_mode: "websocket",
      poll_interval: 30,
      config_revision: 1,
      applied_config_revision: 1,
      applied_policy_revision: 1,
      version: "v0.1.0",
    },
    {
      id: "b",
      name: "Frankfurt · edge-02",
      ip: "198.51.100.8",
      ipv4: "198.51.100.8",
      ipv6: null,
      country: "Germany",
      city: "Frankfurt",
      latitude: 50.1,
      longitude: 8.7,
      online: false,
      last_seen: now - 600,
      observed_at: now - 600,
      enabled: 1,
      has_token: true,
      jails: ["sshd"],
      mode: "polling",
      actual_mode: "polling",
      poll_interval: 30,
      config_revision: 2,
      applied_config_revision: 1,
      applied_policy_revision: 0,
      version: "v0.1.0",
    },
  ],
  bans: [
    {
      node_id: "a",
      jail: "sshd",
      ip: "203.0.113.77",
      country: "United States",
      city: "New York",
      latitude: 40.7,
      longitude: -74,
      observed_at: now,
    },
    {
      node_id: "a",
      jail: "nginx-auth",
      ip: "203.0.113.78",
      country: "China",
      city: "Beijing",
      latitude: 39.9,
      longitude: 116.4,
      observed_at: now - 30,
    },
    {
      node_id: "b",
      jail: "sshd",
      ip: "203.0.113.79",
      country: "Brazil",
      city: "São Paulo",
      latitude: -23.5,
      longitude: -46.6,
      observed_at: now - 50,
    },
  ],
  policies: [],
  commands: [],
  audit: [],
};
async function setup(
  page: Page,
  admin = false,
  data: Data = structuredClone(fixture),
) {
  await page.routeWebSocket("**/api/admin/ws", () => {});
  await page.route("**/api/**", async (route) => {
    const req = route.request(),
      u = new URL(req.url());
    if (req.method() === "GET") {
      if (!admin) {
        const publicData = {
          generated_at: data.generated_at,
          nodes: data.nodes.map((n) => ({
            id: n.id,
            ip: n.id === "a" ? "192.0.x.x" : "198.51.x.x",
            ipv4: n.id === "a" ? "192.0.x.x" : "198.51.x.x",
            ipv6: n.ipv6 ? "2001:db8:x:x:x:x:x:x" : null,
            country: n.country,
            city: n.city,
            latitude: n.latitude,
            longitude: n.longitude,
            online: n.online,
            last_seen: n.last_seen,
            observed_at: n.observed_at,
          })),
          bans: data.bans.map((b) => ({ ...b, ip: "203.0.113.x" })),
        };
        return route.fulfill({ json: publicData });
      }
      return route.fulfill({ json: data });
    }
    if (u.pathname === "/api/admin/nodes") {
      return route.fulfill({
        status: 201,
        json: { id: "new", enrollment: "a".repeat(64), expires_at: now + 600 },
      });
    }
    return route.fulfill({
      status: 201,
      json: { ok: true, ids: ["test-command"] },
    });
  });
}
test("public map displays masked data, target links, filters, and offline state", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "全球防护，实时可见" }),
  ).toBeVisible();
  await expect(page.locator(".connection")).toHaveCount(3);
  await expect(page.getByText("最后已知状态")).toBeVisible();
  await expect(page.getByText("203.0.113.77", { exact: true })).toHaveCount(0);
  await expect(page.getByText("PRIVATE-HOST")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "管理后台" })).toHaveCount(0);
  await expect(
    page.locator('a[href*="admin"], form[action*="admin"]'),
  ).toHaveCount(0);
  await expect(page.locator("tbody tr").first()).toContainText("192.0.x.x");
  await expect(page.locator("tbody tr").first()).toContainText(
    "2001:db8:x:x:x:x:x:x",
  );
  await expect(
    page.locator(".summary-node").filter({ hasText: "192.0.x.x" }),
  ).toContainText("2001:db8:x:x:x:x:x:x");
  await expect(
    page.locator(".summary-node").filter({ hasText: "198.51.x.x" }),
  ).toContainText("IPv6未探测到");
  await expect(page.getByText("2001:db8:1::9", { exact: true })).toHaveCount(0);
  await page.getByLabel("筛选节点").selectOption("a");
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByLabel("搜索 IP 或城市").fill("Beijing");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByRole("button", { name: "放大地图" }).click();
  await expect(page.locator(".world-map>g")).toHaveAttribute(
    "transform",
    /scale\(1.4\)/,
  );
});
test("public refresh and polling bypass long-lived browser cache", async ({
  page,
  baseURL,
}) => {
  let count = 1;
  let requests = 0;
  // Playwright routing disables HTTP caching, so use a real HTTP fixture here.
  const server = createServer((req, res) => {
    void (async () => {
      if (req.url === "/api/public/dashboard") {
        requests++;
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=14400",
        });
        res.end(
          JSON.stringify({
            ...fixture,
            generated_at: now + count,
            bans: fixture.bans.slice(0, count),
          }),
        );
        return;
      }
      const upstream = await fetch(new URL(req.url ?? "/", baseURL));
      res.writeHead(upstream.status, {
        "Content-Type":
          upstream.headers.get("Content-Type") ?? "application/octet-stream",
        "Cache-Control": "no-store",
      });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    })().catch((error) => {
      res.writeHead(500);
      res.end(String(error));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No port");
    await page.clock.install();
    await page.goto(`http://127.0.0.1:${address.port}/`);
    const total = page.locator(".stat").filter({ hasText: "当前封禁" });
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await expect(total.locator("strong")).toHaveText("1");

    count = 2;
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    await expect(page.locator("tbody tr")).toHaveCount(2);
    await expect(total.locator("strong")).toHaveText("2");

    count = 3;
    const beforePoll = requests;
    await page.clock.fastForward(10_000);
    await expect(page.locator("tbody tr")).toHaveCount(3);
    await expect(total.locator("strong")).toHaveText("3");
    expect(requests).toBeGreaterThan(beforePoll);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
test("node creation generates a one-time installation command", async ({
  page,
}) => {
  await setup(page, true);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "节点管理", exact: true }).click();
  await page.getByRole("button", { name: "添加节点", exact: true }).click();
  await page.getByLabel("节点名称").fill("Tokyo");
  await page.getByRole("button", { name: "创建并生成安装命令" }).click();
  await expect(page.getByRole("dialog")).toContainText("10 分钟后过期");
  await expect(page.locator(".install-command")).toContainText(
    "--enrollment " + "a".repeat(64),
  );
});
test("ban, release, and permanent global whitelist submit correct targets", async ({
  page,
}) => {
  await setup(page, true);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "封禁列表", exact: true }).click();
  await page.getByRole("button", { name: "手动封禁", exact: true }).click();
  await page.getByLabel("IP 地址", { exact: true }).fill("8.8.8.8");
  const ban = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/commands") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "下发封禁命令" }).click();
  expect((await ban).postDataJSON()).toEqual([
    { node_id: "a", jail: "sshd", ip: "8.8.8.8", kind: "ban" },
  ]);
  const unban = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/commands") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "解封", exact: true }).first().click();
  expect((await unban).postDataJSON()[0]).toMatchObject({
    node_id: "a",
    jail: "sshd",
    ip: "203.0.113.77",
    kind: "unban",
  });
  await page.getByRole("button", { name: "放行 / 加白" }).first().click();
  await page.getByLabel("有效时间").selectOption("permanent");
  const allow = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/whitelist") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "应用全局规则" }).click();
  expect((await allow).postDataJSON()).toEqual({
    ip: "203.0.113.77",
    duration: null,
  });
});
test("mobile layout and empty/unknown geography states remain usable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page, false, { ...structuredClone(fixture), bans: [] });
  await page.goto("/");
  await expect(page.getByText("防护网络已就绪")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "暂无封禁记录" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/public-mobile.png",
    fullPage: true,
  });
});
test("desktop map preview has no runtime errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.setViewportSize({ width: 1440, height: 1050 });
  await setup(page);
  await page.goto("/");
  await expect(page.locator(".connection")).toHaveCount(3);
  await page.screenshot({
    path: "test-results/public-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});
