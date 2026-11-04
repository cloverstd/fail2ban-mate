import { test, expect, type Page } from "@playwright/test";
import { createServer } from "node:http";
import type { Data, PublicData } from "../../web/types";
import { maskIP } from "../../worker/privacy";
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
  };
}
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
