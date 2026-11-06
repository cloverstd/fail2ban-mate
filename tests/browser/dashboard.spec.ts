import { test, expect, type Page } from "@playwright/test";
import { createServer } from "node:http";
import type { Data, PublicData } from "../../web/types";
import { maskIP } from "../../worker/privacy";
const now = Math.floor(Date.now() / 1000);
const fixture: Data = {
  generated_at: now,
  actor: "admin@example.com",
  visitor_ip: "198.51.100.42",
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
function publicFixture(data: Data): PublicData {
  return {
    generated_at: data.generated_at,
    nodes: data.nodes.map((node) => ({
      id: node.id,
      ip: maskIP(node.ip, true),
      ipv4:
        node.ipv4 === undefined
          ? undefined
          : node.ipv4
            ? maskIP(node.ipv4, true)
            : null,
      ipv6:
        node.ipv6 === undefined
          ? undefined
          : node.ipv6
            ? maskIP(node.ipv6, true)
            : null,
      country: node.country,
      city: node.city,
      latitude: node.latitude,
      longitude: node.longitude,
      online: node.online,
      last_seen: node.last_seen,
      observed_at: node.observed_at,
    })),
    bans: data.bans.map(({ jail: _jail, ...ban }) => ({
      ...ban,
      ip: maskIP(ban.ip),
    })),
    ban_history: data.ban_history?.map(({ jail: _jail, ...ban }) => ({
      ...ban,
      ip: maskIP(ban.ip),
    })),
  };
}
async function setup(
  page: Page,
  admin = false,
  data: Data = structuredClone(fixture),
) {
  let notify = () => {};
  await page.routeWebSocket("**/api/admin/ws", (socket) => {
    notify = () => socket.send("refresh");
  });
  await page.route("**/api/**", async (route) => {
    const req = route.request(),
      u = new URL(req.url());
    if (req.method() === "GET") {
      if (!admin) {
        return route.fulfill({ json: publicFixture(data) });
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
  return () => notify();
}
test("public page contains only navigation and the map with private fields removed", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/");
  await expect(page.locator(".connection")).toHaveCount(3);
  await expect(
    page.locator(
      ".stats, .page-heading, .node-summary, .filters, table, footer",
    ),
  ).toHaveCount(0);
  await expect(
    page.locator('a[href*="admin"], form[action*="admin"]'),
  ).toHaveCount(0);
  await page.getByRole("button", { name: /^受保护节点 192\.0/ }).click();
  const popup = page.getByRole("dialog", { name: "地图节点信息" });
  await expect(popup).toContainText("192.0.x.x");
  await expect(popup).toContainText("2001:db8:x:x:x:x:x:x");
  await expect(popup).toContainText("在线");
  await expect(popup).toContainText("最近上报");
  await expect(popup).not.toContainText(/IPv4|IPv6|未探测到/);
  await page.getByRole("button", { name: "关闭节点信息" }).click();
  await expect(popup).toHaveCount(0);
  await page.getByRole("button", { name: /^受保护节点 198\.51/ }).click();
  await expect(popup).toContainText("离线 · 最后已知状态");
  await expect(popup.locator(".node-addresses code")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await page
    .getByRole("button", { name: /^封禁来源/ })
    .first()
    .click();
  await expect(popup).toContainText("203.0.113.x");
  await expect(popup).toContainText("目标节点");
  await expect(popup).toContainText("观测时间");
  await expect(page.locator("body")).not.toContainText(
    /203\.0\.113\.77|192\.0\.2\.9|2001:db8:1::9|edge-01|sshd|nginx-auth|Service/,
  );
  await expect(
    page.getByRole("link", { name: "IP Geolocation by DB-IP" }),
  ).toBeVisible();
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
            ...publicFixture(fixture),
            generated_at: now + count,
            bans: publicFixture(fixture).bans.slice(0, count),
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
    await expect(page.locator(".connection")).toHaveCount(1);

    count = 2;
    await page.getByRole("button", { name: "刷新", exact: true }).click();
    await expect(page.locator(".connection")).toHaveCount(2);

    count = 3;
    const beforePoll = requests;
    await page.clock.fastForward(10_000);
    await expect(page.locator(".connection")).toHaveCount(3);
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
test("whitelist defaults to the visitor IP and submits it unchanged", async ({
  page,
}) => {
  await setup(page, true);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "全局白名单", exact: true }).click();
  await page.getByRole("button", { name: "添加规则", exact: true }).click();
  await expect(page.getByLabel("IP 来源", { exact: true })).toHaveValue(
    "visitor",
  );
  await expect(page.getByLabel("IP 地址", { exact: true })).toHaveValue(
    fixture.visitor_ip!,
  );
  const request = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/whitelist") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "应用全局规则" }).click();
  expect((await request).postDataJSON()).toEqual({
    ip: fixture.visitor_ip,
    duration: 3600,
  });
});

test("whitelist selects node IPv4 or IPv6 and allows editing or restoring the visitor IP", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page, true);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "全局白名单", exact: true }).click();
  await page.getByRole("button", { name: "添加规则", exact: true }).click();
  const source = page.getByLabel("IP 来源", { exact: true });
  const address = page.getByLabel("IP 地址", { exact: true });
  await source.selectOption({ label: "Singapore · edge-01 · 192.0.2.9" });
  await expect(address).toHaveValue("192.0.2.9");
  await source.selectOption({ label: "Singapore · edge-01 · 2001:db8:1::9" });
  await expect(address).toHaveValue("2001:db8:1::9");
  await source.selectOption({ label: "Frankfurt · edge-02 · 198.51.100.8" });
  await expect(address).toHaveValue("198.51.100.8");
  await address.fill("2001:db8::123");
  await expect(source).toHaveValue("manual");
  await source.selectOption("visitor");
  await expect(address).toHaveValue(fixture.visitor_ip!);
  await source.selectOption("manual");
  await expect(address).toHaveValue(fixture.visitor_ip!);
  await address.fill("2001:db8::123");
  const request = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/whitelist") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "应用全局规则" }).click();
  expect((await request).postDataJSON()).toEqual({
    ip: "2001:db8::123",
    duration: 3600,
  });
});

test("whitelist receives a late visitor IP but preserves manually edited and cleared values on refresh", async ({
  page,
}) => {
  await page.clock.install();
  const data = structuredClone(fixture);
  data.visitor_ip = null;
  data.nodes[0].ipv4 = undefined;
  data.nodes[0].ipv6 = undefined;
  data.nodes[1].ip = null;
  data.nodes[1].ipv4 = null;
  const notify = await setup(page, true, data);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "全局白名单", exact: true }).click();
  await page.getByRole("button", { name: "添加规则", exact: true }).click();
  const source = page.getByLabel("IP 来源", { exact: true });
  const address = page.getByLabel("IP 地址", { exact: true });
  await expect(address).toHaveValue("");
  await expect(
    page.getByText("未获取到访问者 IP，请选择节点地址或手动输入。"),
  ).toBeVisible();
  await expect(source.locator("optgroup option")).toHaveCount(1);
  data.visitor_ip = "2001:db8::42";
  notify();
  await page.clock.runFor(1000);
  await expect(address).toHaveValue("2001:db8::42");
  await address.fill("8.8.8.8");
  data.visitor_ip = "198.51.100.45";
  notify();
  await page.clock.runFor(1000);
  await expect(address).toHaveValue("8.8.8.8");
  await address.clear();
  data.visitor_ip = "198.51.100.46";
  notify();
  await page.clock.runFor(1000);
  await expect(address).toHaveValue("");
  await source.selectOption({ label: "Singapore · edge-01 · 192.0.2.9" });
  await expect(address).toHaveValue("192.0.2.9");
});

test("ban list includes released history, filters by status and only selects active bans", async ({
  page,
}) => {
  const data = structuredClone(fixture);
  data.ban_history = [
    {
      ...data.bans[0],
      id: "history",
      jail: "retired-service",
      observed_at: now - 300,
      unbanned_at: now - 60,
    },
  ];
  await setup(page, true, data);
  await page.goto("/admin/");
  const activeStat = page.locator(".stat").filter({ hasText: "当前封禁" });
  await expect(activeStat.locator("strong")).toHaveText("3");
  await page.getByRole("button", { name: "封禁列表", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(4);
  const history = page
    .locator("tbody tr")
    .filter({ hasText: "retired-service" });
  await expect(history).toContainText("已解禁");
  await expect(history.getByRole("checkbox")).toBeDisabled();
  await expect(
    history.getByRole("button", { name: "解封", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("选择本页封禁").check();
  await expect(page.locator(".selection-bar")).toContainText("已选择 3 条");
  const submitted = page.waitForRequest(
    (r) => r.url().endsWith("/api/admin/commands") && r.method() === "POST",
  );
  await page.getByRole("button", { name: "批量解除封禁", exact: true }).click();
  expect((await submitted).postDataJSON()).toHaveLength(3);
  await page.getByLabel("筛选封禁状态").selectOption("unbanned");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.getByLabel("选择本页封禁")).toBeDisabled();
  await page.getByLabel("筛选 service").selectOption("retired-service");
  await expect(history).toBeVisible();
  await page.getByLabel("筛选 service").selectOption("");
  await page.getByLabel("筛选封禁状态").selectOption("banned");
  await expect(page.locator("tbody tr")).toHaveCount(3);
});

test("a selected ban stays in the list as released history after a live refresh", async ({
  page,
}) => {
  await page.clock.install();
  const data = structuredClone(fixture);
  const notify = await setup(page, true, data);
  await page.goto("/admin/");
  await page.getByRole("button", { name: "封禁列表", exact: true }).click();
  await page.getByLabel("选择 203.0.113.77", { exact: true }).check();
  const released = data.bans.shift()!;
  data.ban_history = [{ ...released, id: "released", unbanned_at: now }];
  notify();
  await page.clock.runFor(1000);
  const row = page.locator("tbody tr").filter({ hasText: "203.0.113.77" });
  await expect(row).toContainText("已解禁");
  await expect(row.getByRole("checkbox")).toBeDisabled();
  await expect(page.locator(".selection-bar")).toHaveCount(0);
  await expect(page.locator("tbody tr")).toHaveCount(3);
});

for (const admin of [false, true]) {
  test(`map shows red active bans and yellow released history with age fading in ${admin ? "admin" : "public"} view`, async ({
    page,
  }) => {
    await page.clock.install({ time: now * 1000 });
    const data = structuredClone(fixture);
    data.bans[1].observed_at = now - 86400;
    data.ban_history = [
      {
        ...data.bans[0],
        id: "recent-release",
        observed_at: now - 100000,
        unbanned_at: now - 60,
      },
      {
        ...data.bans[2],
        id: "old-release",
        observed_at: now - 10 * 86400,
        unbanned_at: now - 7 * 86400,
      },
    ];
    await setup(page, admin, data);
    await page.goto(admin ? "/admin/" : "/");
    await expect(page.locator(".connection")).toHaveCount(5);
    await expect(page.locator(".source-active")).toHaveCount(3);
    await expect(page.locator(".source-released")).toHaveCount(2);
    const recentRed = page
      .locator(".map-connection[data-status='banned']")
      .first();
    const oldRed = page.locator(".map-connection[data-status='banned']").nth(1);
    const recentYellow = page
      .locator(".map-connection[data-status='unbanned']")
      .first();
    const oldYellow = page
      .locator(".map-connection[data-status='unbanned']")
      .nth(1);
    await expect(recentRed).toHaveCSS("color", "rgb(239, 68, 68)");
    await expect(recentYellow).toHaveCSS("color", "rgb(250, 204, 21)");
    const opacity = (locator: typeof recentRed) =>
      locator.evaluate((e) => Number(getComputedStyle(e).opacity));
    expect(await opacity(recentRed)).toBeGreaterThan(await opacity(oldRed));
    expect(await opacity(recentYellow)).toBeGreaterThan(
      await opacity(oldYellow),
    );
    expect(await opacity(oldYellow)).toBeGreaterThan(0);
    // A shared location preserves both its active center and released ring.
    const marker = page
      .getByRole("button", { name: /^封禁来源/ })
      .filter({ has: page.locator(".source-active") })
      .filter({ has: page.locator(".source-released") })
      .first();
    await marker.click();
    const popup = page.getByRole("dialog", { name: "地图节点信息" });
    await expect(popup).toContainText("封禁中");
    await expect(popup).toContainText("已解禁");
    await expect(popup).toContainText("解禁时间");
    if (!admin)
      await expect(popup).not.toContainText(/203\.0\.113\.77|sshd|edge-01/);
    const before = await opacity(recentRed);
    await page.clock.fastForward(60000);
    expect(await opacity(recentRed)).toBeLessThan(before);
    if (!admin)
      await page.screenshot({
        path: "test-results/ban-history-map.png",
        fullPage: true,
      });
  });
}

test("map includes sources beyond the previous 200-location limit", async ({
  page,
}) => {
  const data = structuredClone(fixture);
  data.bans = Array.from({ length: 201 }, (_, index) => ({
    ...fixture.bans[0],
    ip: `203.0.${Math.floor(index / 256)}.${index % 256}`,
    latitude: 20,
    longitude: -100 + index * 0.5,
  }));
  await setup(page, true, data);
  await page.goto("/admin/");
  await expect(page.locator(".connection")).toHaveCount(201);
  await expect(page.locator(".source-active")).toHaveCount(201);
});

test("mobile layout and empty/unknown geography states remain usable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page, false, { ...structuredClone(fixture), bans: [] });
  await page.goto("/");
  await expect(page.getByText("防护网络已就绪")).toBeVisible();
  await expect(page.locator("table")).toHaveCount(0);
  await expectViewportMap(page);
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
  await expectViewportMap(page);
  await page.screenshot({
    path: "test-results/public-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

async function expectViewportMap(page: Page) {
  const dimensions = await page.evaluate(() => ({
    viewport: { width: innerWidth, height: innerHeight },
    document: {
      width: document.documentElement.scrollWidth,
      height: document.documentElement.scrollHeight,
    },
    map: document.querySelector(".world-map")!.getBoundingClientRect().toJSON(),
    nav: document.querySelector(".topbar")!.getBoundingClientRect().toJSON(),
  }));
  expect(dimensions.document.width).toBeLessThanOrEqual(
    dimensions.viewport.width,
  );
  expect(dimensions.document.height).toBeLessThanOrEqual(
    dimensions.viewport.height,
  );
  expect(dimensions.map.width).toBeCloseTo(dimensions.viewport.width, 0);
  expect(dimensions.map.top).toBeCloseTo(dimensions.nav.bottom, 0);
  expect(dimensions.map.bottom).toBeCloseTo(dimensions.viewport.height, 0);
}

async function mapTransform(page: Page) {
  return page.locator(".map-geography").evaluate((element) => {
    const matrix = (element as SVGGraphicsElement).getScreenCTM()!;
    return { a: matrix.a, e: matrix.e, f: matrix.f };
  });
}

for (const admin of [false, true]) {
  test(`map gestures, pointer anchoring and drag work in ${admin ? "admin" : "public"} view`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await setup(page, admin);
    await page.goto(admin ? "/admin/" : "/");
    await expect(page.locator(".connection")).toHaveCount(3);
    const map = page.locator(".world-map");
    const bounds = (await map.boundingBox())!;
    const anchor = {
      x: Math.round(bounds.x + bounds.width * 0.35),
      y: Math.round(bounds.y + bounds.height * 0.4),
    };
    const before = await mapTransform(page);
    const canceled = await map.evaluate(
      (element, anchor) =>
        !element.dispatchEvent(
          new WheelEvent("wheel", {
            clientX: anchor.x,
            clientY: anchor.y,
            deltaY: -40,
            ctrlKey: true,
            bubbles: true,
            cancelable: true,
          }),
        ),
      anchor,
    );
    expect(canceled).toBe(true);
    await expect
      .poll(async () => (await mapTransform(page)).a)
      .toBeGreaterThan(before.a);
    const after = await mapTransform(page);
    const ratio = after.a / before.a;
    expect(after.e + (anchor.x - before.e) * ratio).toBeCloseTo(anchor.x, 3);
    expect(after.f + (anchor.y - before.f) * ratio).toBeCloseTo(anchor.y, 3);
    for (const delta of [-10000, 10000]) {
      for (let i = 0; i < 15; i++)
        await map.evaluate(
          (element, deltaY) =>
            element.dispatchEvent(
              new WheelEvent("wheel", {
                deltaY,
                ctrlKey: true,
                bubbles: true,
                cancelable: true,
              }),
            ),
          delta,
        );
      await expect
        .poll(async () => (await mapTransform(page)).a)
        .toBeCloseTo(delta < 0 ? 5 : 1, 4);
    }
    await page.getByRole("button", { name: "重置地图" }).click();
    const reset = await mapTransform(page);
    await page.mouse.move(bounds.x + 50, bounds.y + bounds.height - 90);
    await page.mouse.down();
    await page.mouse.move(bounds.x + 110, bounds.y + bounds.height - 60, {
      steps: 5,
    });
    await page.mouse.up();
    const dragged = await mapTransform(page);
    expect(dragged.e - reset.e).toBeCloseTo(60, 1);
    expect(dragged.f - reset.f).toBeCloseTo(30, 1);
    await expect(
      page.getByRole("dialog", { name: "地图节点信息" }),
    ).toHaveCount(0);
    await page.getByRole("button", { name: "重置地图" }).click();
    expect(await mapTransform(page)).toEqual(reset);
    await page.getByRole("button", { name: "放大地图" }).click();
    await expect
      .poll(async () => (await mapTransform(page)).a)
      .toBeCloseTo(1.4, 4);
    await page.getByRole("button", { name: "缩小地图" }).click();
    await expect
      .poll(async () => (await mapTransform(page)).a)
      .toBeCloseTo(1, 4);
  });
}

test("overlapping nodes and sources share a popup and keyboard activation", async ({
  page,
}) => {
  const data = structuredClone(fixture);
  data.nodes[1].latitude = data.nodes[0].latitude;
  data.nodes[1].longitude = data.nodes[0].longitude;
  data.bans[0].latitude = data.nodes[0].latitude;
  data.bans[0].longitude = data.nodes[0].longitude;
  data.bans.push({ ...data.bans[0], jail: "other", observed_at: now - 300 });
  await setup(page, false, data);
  await page.goto("/");
  const marker = page.getByRole("button", { name: /^受保护节点 192\.0/ });
  await marker.focus();
  await page.keyboard.press("Enter");
  const popup = page.getByRole("dialog", { name: "地图节点信息" });
  await expect(popup.locator(".map-popup-item")).toHaveCount(3);
  await expect(popup).toContainText("198.51.x.x");
  await expect(popup).toContainText("203.0.113.x");
  await page.keyboard.press("Escape");
  await expect(popup).toHaveCount(0);
  await marker.focus();
  await page.keyboard.press("Space");
  await expect(popup).toBeVisible();
  await page.locator(".world-map").click({ position: { x: 30, y: 60 } });
  await expect(popup).toHaveCount(0);
});

test("selected popup follows map movement, refreshes, and closes when its node disappears", async ({
  page,
}) => {
  await page.clock.install();
  const data = structuredClone(fixture);
  await setup(page, false, data);
  await page.goto("/");
  const marker = page.getByRole("button", { name: /^受保护节点 192\.0/ });
  await marker.click();
  const popup = page.getByRole("dialog", { name: "地图节点信息" });
  const before = (await popup.boundingBox())!;
  const map = page.locator(".world-map");
  const bounds = (await map.boundingBox())!;
  await page.mouse.move(bounds.x + 30, bounds.y + 100);
  await page.mouse.down();
  await page.mouse.move(bounds.x, bounds.y + 120, { steps: 3 });
  await page.mouse.up();
  await expect(popup).toBeVisible();
  await expect
    .poll(async () => (await popup.boundingBox())!.x)
    .toBeCloseTo(before.x - 30, 0);
  data.nodes[0].online = false;
  await page.clock.fastForward(10000);
  await expect(popup).toContainText("离线 · 最后已知状态");
  data.nodes.splice(0, 1);
  data.bans = data.bans.filter((ban) => ban.node_id !== "a");
  await page.clock.fastForward(10000);
  await expect(popup).toHaveCount(0);
});

for (const [name, addresses, expected] of [
  ["IPv4", { ip: "192.0.2.9", ipv4: "192.0.2.9", ipv6: null }, ["192.0.2.9"]],
  [
    "IPv6",
    { ip: "2001:db8::9", ipv4: null, ipv6: "2001:db8::9" },
    ["2001:db8::9"],
  ],
  [
    "dual stack",
    { ip: "192.0.2.9", ipv4: "192.0.2.9", ipv6: "2001:db8::9" },
    ["192.0.2.9", "2001:db8::9"],
  ],
  ["unknown", { ip: null, ipv4: null, ipv6: null }, ["未知 IP"]],
  [
    "legacy IPv4",
    { ip: "192.0.2.9", ipv4: undefined, ipv6: undefined },
    ["192.0.2.9"],
  ],
  [
    "legacy IPv6",
    { ip: "2001:db8::9", ipv4: undefined, ipv6: undefined },
    ["2001:db8::9"],
  ],
] as const) {
  test(`address display only shows available addresses: ${name}`, async ({
    page,
  }) => {
    const data = structuredClone(fixture);
    Object.assign(data.nodes[0], addresses);
    await setup(page, true, data);
    await page.goto("/admin/");
    await page.getByRole("button", { name: /^受保护节点 Singapore/ }).click();
    const popup = page.getByRole("dialog", { name: "地图节点信息" });
    await expect(popup.locator(".node-addresses code")).toHaveText([
      ...expected,
    ]);
    await expect(popup).not.toContainText(/IPv4|IPv6|未探测到/);
    await page.getByRole("button", { name: "节点管理", exact: true }).click();
    await expect(
      page.locator(".node-card").first().locator(".node-addresses code"),
    ).toHaveText([...expected]);
  });
}

test("mobile popup stays in bounds after resize and marker dragging does not open it", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/");
  await page.setViewportSize({ width: 390, height: 844 });
  await expectViewportMap(page);
  const marker = page.getByRole("button", { name: /^受保护节点 192\.0/ });
  const markerBox = (await marker.boundingBox())!;
  await page.mouse.move(
    markerBox.x + markerBox.width / 2,
    markerBox.y + markerBox.height / 2,
  );
  await page.mouse.down();
  await page.mouse.move(
    markerBox.x + markerBox.width / 2 + 15,
    markerBox.y + markerBox.height / 2 + 10,
    { steps: 3 },
  );
  await page.mouse.up();
  const popup = page.getByRole("dialog", { name: "地图节点信息" });
  await expect(popup).toHaveCount(0);
  await marker.click();
  await expect(popup).toBeVisible();
  const box = (await popup.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(390);
  expect(box.y + box.height).toBeLessThanOrEqual(844);
});

test("unknown geography and network failure display map notices and allow retry", async ({
  page,
}) => {
  const data = structuredClone(fixture);
  data.bans.forEach((ban) => {
    ban.latitude = null;
    ban.longitude = null;
  });
  let fail = true;
  await page.route("**/api/public/dashboard", (route) =>
    route.fulfill(
      fail
        ? { status: 503, json: { error: "暂时无法连接控制端" } }
        : { json: publicFixture(data) },
    ),
  );
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText("暂时无法连接控制端");
  await expectViewportMap(page);
  fail = false;
  await page.getByRole("button", { name: "重试" }).click();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText("等待具有地理坐标的封禁记录")).toBeVisible();
  await expect(page.locator(".map-marker")).toHaveCount(2);
  await expect(page.getByText(/下方列表/)).toHaveCount(0);
});

test("manages integration Tokens once and deletes dynamic rules from the whitelist", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const data = structuredClone(fixture);
  await setup(page, true, data);
  const id = "a5d63f36-d409-4c7e-8253-6d8d67ab27d5";
  const token = "f2bm_" + "a".repeat(64);
  const rotated = "f2bm_" + "b".repeat(64);
  await page.route("**/api/admin/integrations**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/rotate")) {
      data.integrations![0].token_prefix = rotated.slice(0, 13);
      return route.fulfill({ json: { id, token: rotated } });
    }
    if (path.endsWith("/revoke")) {
      data.integrations![0].revoked_at = now;
      return route.fulfill({ json: { ok: true } });
    }
    const { name } = route.request().postDataJSON() as { name: string };
    data.integrations = [
      {
        id,
        name,
        token_prefix: token.slice(0, 13),
        last_used_at: null,
        revoked_at: null,
      },
    ];
    return route.fulfill({ status: 201, json: { id, token } });
  });
  await page.route("**/api/admin/dynamic-whitelist/*", async (route) => {
    expect(route.request().method()).toBe("DELETE");
    data.policies = [];
    await route.fulfill({ json: { ok: true } });
  });

  await page.goto("/admin/");
  await page.getByRole("button", { name: "接口接入" }).click();
  await page.getByLabel("调用方名称").fill("Home CDSG");
  await page.getByRole("button", { name: "创建 Token" }).click();
  const secret = page.getByRole("group", { name: "新接入 Token" });
  await expect(secret).toContainText(token);
  await page.getByRole("button", { name: "复制 Token" }).click();
  await expect(secret).toHaveCount(0);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(token);
  await expect(page.getByRole("row", { name: /Home CDSG/ })).toContainText(
    token.slice(0, 13) + "…",
  );
  await expect(page.locator("body")).not.toContainText(token);
  await page.reload();
  await page.getByRole("button", { name: "接口接入" }).click();
  await expect(page.getByRole("row", { name: /Home CDSG/ })).toBeVisible();
  await expect(secret).toHaveCount(0);
  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "轮换 Token" }).click();
  await expect(secret).toContainText(rotated);
  await page.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByRole("button", { name: "撤销 Token" }).click();
  await expect(page.getByRole("row", { name: /Home CDSG/ })).toContainText(
    "已撤销",
  );

  data.policies = [
    {
      id: "rule",
      ip: "198.51.100.51",
      expires_at: now + 86400,
      actor: "Home CDSG",
      created_at: now,
      source: "integration",
      owner_id: "home",
      synced_at: now,
    },
  ];
  await page.reload();
  await page.getByRole("button", { name: "全局白名单" }).click();
  const rule = page.getByRole("row", { name: /198\.51\.100\.51/ });
  await expect(rule).toContainText("接口 · Home CDSG / home");
  await rule.getByRole("button", { name: "撤销" }).click();
  await expect(rule).toHaveCount(0);
});

test("firewall rule groups can be edited and reordered before publishing a node", async ({
  page,
}) => {
  await setup(page, true);
  const node = fixture.nodes[0];
  let groups: Record<string, unknown>[] = [];
  let published = false;
  const defaults = { in: "deny", out: "allow", route: "deny" };
  await page.route("**/api/admin/firewall/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/groups")) {
      if (request.method() === "POST")
        groups = [{ ...request.postDataJSON(), id: "group-1", revision: 1 }];
      return route.fulfill({
        json: request.method() === "POST" ? groups[0] : groups,
      });
    }
    if (path.endsWith("/preview"))
      return route.fulfill({
        json: {
          version: "test-preview",
          node_id: node.id,
          before: [],
          before_defaults: defaults,
          after: { defaults, rules: groups[0].rules },
          affected: [{ id: node.id, name: node.name }],
        },
      });
    if (path.endsWith("/publish")) {
      expect(request.postDataJSON()).toEqual([
        { node_id: node.id, version: "test-preview" },
      ]);
      published = true;
      return route.fulfill({
        json: { outcomes: [{ node_id: node.id, id: "test-release" }] },
      });
    }
    return route.fulfill({
      json: {
        observation: {
          status: "active",
          defaults,
          rules: [],
          observed_at: now,
          protection: [],
          ipv6: true,
        },
        draft: groups.length
          ? {
              revision: 1,
              defaults,
              bindings: [{ group_id: "group-1", priority: 10 }],
              protection: [],
            }
          : null,
        history: [],
      },
    });
  });
  await page.goto("/admin/");
  await page.getByRole("button", { name: "防火墙", exact: true }).click();
  await page.getByRole("button", { name: "创建规则组" }).click();
  await page.getByLabel("规则组名称").fill("SSH 策略");
  await page.getByRole("button", { name: "添加规则", exact: true }).click();
  await page.getByRole("button", { name: "添加规则", exact: true }).click();
  await page.getByLabel("动作", { exact: true }).nth(1).selectOption("deny");
  await page.getByRole("button", { name: "上移", exact: true }).nth(1).click();
  await page.getByRole("button", { name: "保存规则组草稿" }).click();
  await expect(page.getByText("已保存规则组草稿")).toBeVisible();
  expect(groups[0].rules).toMatchObject([
    { action: "deny", priority: 10 },
    { action: "allow", priority: 20 },
  ]);
  expect(published).toBe(false);
  await page.getByRole("button", { name: "节点规则", exact: true }).click();
  await expect(page.getByText("草稿合并顺序（基础规则之后）")).toBeVisible();
  await page.getByRole("button", { name: "预览发布", exact: true }).click();
  await expect(page.getByText("发布后的顺序")).toBeVisible();
  await page.getByRole("button", { name: "发布到所选节点" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "已提交发布" }),
  ).toBeVisible();
  expect(published).toBe(true);
});
