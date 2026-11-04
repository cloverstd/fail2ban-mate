import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Globe2,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  LockKeyhole,
  Plus,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
import type { Mode } from "../shared/protocol";
import type { BanRow, Data, Node, PublicData } from "./types";
import { WorldMap } from "./Map";
import { NodeAddresses, nodeAddressLabel } from "./NodeAddresses";
import "./style.css";

// Production builds expose only the URLs needed by their audience.
declare const __ADMIN__: boolean;
const admin = import.meta.env.DEV
  ? location.pathname.startsWith("/admin")
  : __ADMIN__;
const empty: Data = { nodes: [], bans: [], generated_at: 0 };
const time = (t: number | null | undefined) =>
  t
    ? new Date(t * 1000).toLocaleString("zh-CN", { hour12: false })
    : "尚未同步";
const place = (g: { city?: string | null; country?: string | null }) =>
  [g.city, g.country].filter(Boolean).join(", ") || "未知位置";
const statusName: Record<string, string> = {
  pending: "等待下发",
  running: "执行中",
  succeeded: "成功",
  failed: "失败",
  expired: "已过期",
};
const actionName: Record<string, string> = {
  "node.create": "新增节点",
  "node.update": "更新节点",
  "node.delete": "删除节点",
  "node.reenroll": "重新注册节点",
  "node.revoke": "撤销凭据",
  "commands.create": "下发命令",
  "whitelist.upsert": "全局加白 / 限时放行",
  "whitelist.delete": "撤销全局加白",
};
type Page = "overview" | "nodes" | "bans" | "whitelist" | "logs";
type Modal =
  | { kind: "node" }
  | { kind: "ban"; node?: string; jail?: string; ip?: string }
  | { kind: "allow"; ip?: string }
  | { kind: "install"; code: string; name: string };
async function api<T = unknown>(
  path: string,
  body?: unknown,
  method?: string,
): Promise<T> {
  const res = await fetch("/api/admin" + path, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers:
      body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = (await res.json()) as { error?: string };
  if (!res.ok) throw new Error(json.error || `请求失败 (${res.status})`);
  return json as T;
}
function PublicApp() {
  const [data, setData] = useState<PublicData>(empty);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const response = await fetch("/api/public/dashboard", {
        cache: "no-store",
      });
      const body = (await response.json()) as PublicData & { error?: string };
      if (!response.ok) throw new Error(body.error || "暂时无法连接控制端");
      setData(body);
      setError("");
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);
  return (
    <div className="public-app">
      <header className="topbar">
        <a className="brand" href="/">
          <span className="brand-mark">
            <Shield size={22} />
          </span>
          <span>
            fail2ban<span className="brand-light"> mate</span>
          </span>
          <span className="version">v0.1</span>
        </a>
        <div className="top-actions">
          <span className="network-status" role="status">
            <i className={error ? "status-error" : "live-dot"} />
            {error ? "连接异常" : loading ? "正在同步" : "防护网络"}
          </span>
          <span className="last-update">
            更新于{" "}
            {data.generated_at
              ? new Date(data.generated_at * 1000).toLocaleTimeString("zh-CN", {
                  hour12: false,
                })
              : "—"}
          </span>
          <button
            className="icon-btn"
            aria-label="刷新"
            disabled={refreshing}
            onClick={() => void refresh()}
          >
            <RefreshCw size={16} className={refreshing ? "spin" : ""} />
          </button>
          <a
            className="subtle-link"
            href="https://github.com/cloverstd/fail2ban-mate"
            target="_blank"
            rel="noreferrer"
          >
            GitHub <ExternalLink size={13} />
          </a>
        </div>
      </header>
      <main className="public-map">
        <WorldMap
          nodes={data.nodes}
          bans={data.bans}
          publicView
          loading={loading}
          error={error}
          onRetry={() => void refresh()}
        />
      </main>
    </div>
  );
}
function App() {
  const [data, setData] = useState<Data>(empty),
    [page, setPage] = useState<Page>("overview"),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [live, setLive] = useState(false),
    [busy, setBusy] = useState(false),
    [toast, setToast] = useState("");
  const [nodeFilter, setNodeFilter] = useState(""),
    [query, setQuery] = useState(""),
    [service, setService] = useState(""),
    [since, setSince] = useState(""),
    [selected, setSelected] = useState<Set<string>>(new Set()),
    [listPage, setListPage] = useState(0),
    [modal, setModal] = useState<Modal | null>(null);
  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/dashboard", { cache: "no-store" });
      const body = (await res.json()) as Data & { error?: string };
      if (!res.ok) throw new Error(body.error || "暂时无法连接控制端");
      setData(body);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    let ws: WebSocket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let connected = false;
    let throttle: ReturnType<typeof setTimeout> | undefined;
    function connect() {
      if (stopped || !admin) return;
      ws = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/admin/ws`,
      );
      ws.onopen = () => {
        connected = true;
        setLive(true);
        void refresh();
      };
      ws.onmessage = () => {
        if (!throttle)
          throttle = setTimeout(() => {
            throttle = undefined;
            void refresh();
          }, 300);
      };
      ws.onerror = () => ws?.close();
      ws.onclose = () => {
        connected = false;
        setLive(false);
        if (!stopped) timer = setTimeout(connect, 15000);
      };
    }
    if (admin) connect();
    const poll = setInterval(
      () => {
        if (!admin || !connected) void refresh();
      },
      admin ? 5000 : 10000,
    );
    return () => {
      stopped = true;
      clearInterval(poll);
      clearTimeout(timer);
      clearTimeout(throttle);
      ws?.close();
    };
  }, [refresh]);
  useEffect(() => {
    setSelected(new Set());
    setListPage(0);
  }, [nodeFilter, query, service, since, page]);
  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(""), 5000);
      return () => clearTimeout(t);
    }
  }, [toast]);
  const run = async (fn: () => Promise<unknown>, message = "操作已提交") => {
    setBusy(true);
    try {
      await fn();
      setToast(message);
      await refresh();
    } catch (e) {
      setToast((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const key = (b: BanRow) => `${b.node_id}|${b.jail}|${b.ip}`;
  const nodeName = (id: string) => {
    const n = data.nodes.find((n) => n.id === id);
    return n?.name || (n ? nodeAddressLabel(n) : "未知节点");
  };
  const filtered = data.bans.filter(
    (b) =>
      (!nodeFilter || b.node_id === nodeFilter) &&
      (!service || b.jail === service) &&
      (!query ||
        `${b.ip} ${place(b)}`.toLowerCase().includes(query.toLowerCase())) &&
      (!since || b.observed_at >= new Date(since).getTime() / 1000),
  );
  const visibleNodes = data.nodes.filter(
    (n) => !nodeFilter || n.id === nodeFilter,
  );
  const services = [...new Set(data.bans.map((b) => b.jail))].sort();
  const commands = (rows: BanRow[]) =>
    run(
      () =>
        api(
          "/commands",
          rows.map((b) => ({
            node_id: b.node_id,
            jail: b.jail,
            ip: b.ip,
            kind: "unban",
          })),
        ),
      "解封命令已提交，请查看执行结果",
    );
  const enroll = (n: Node) =>
    run(async () => {
      const r = await api<{ enrollment: string }>(
        `/nodes/${n.id}/enrollment`,
        {},
      );
      setModal({ kind: "install", code: r.enrollment, name: n.name || "节点" });
    });
  const changeNode = (n: Node, patch: object) =>
    run(() => api(`/nodes/${n.id}`, patch, "PATCH"));
  const banList = (
    <section className="panel list-panel">
      <div className="section-header">
        <div>
          <h2>{admin ? "封禁记录" : "当前封禁"}</h2>
          <p>
            {admin
              ? "按节点与 service 管理已观测到的封禁"
              : "IP 已脱敏处理，地理位置仅供参考"}
          </p>
        </div>
        <span className="count-label">
          {filtered.length.toLocaleString()} 条记录
        </span>
      </div>
      <div className="filters">
        <label className="search">
          <Search size={16} />
          <input
            aria-label="搜索 IP 或城市"
            placeholder="搜索 IP 或城市…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <select
          aria-label="筛选节点"
          value={nodeFilter}
          onChange={(e) => setNodeFilter(e.target.value)}
        >
          <option value="">所有节点</option>
          {data.nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.name || nodeAddressLabel(n)}
            </option>
          ))}
        </select>
        <select
          aria-label="筛选 service"
          value={service}
          onChange={(e) => setService(e.target.value)}
        >
          <option value="">所有 service</option>
          {services.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        {admin && (
          <input
            type="datetime-local"
            aria-label="起始观测时间"
            value={since}
            onChange={(e) => setSince(e.target.value)}
          />
        )}
      </div>
      {admin && selected.size > 0 && (
        <div className="selection-bar">
          已选择 {selected.size} 条{" "}
          <button
            disabled={busy || selected.size > 100}
            onClick={() =>
              void commands(filtered.filter((b) => selected.has(key(b))))
            }
          >
            批量解除封禁{selected.size > 100 ? "（最多 100 条）" : ""}
          </button>
        </div>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {admin && (
                <th>
                  <input
                    aria-label="选择本页封禁"
                    type="checkbox"
                    checked={
                      filtered.slice(listPage * 50, listPage * 50 + 50).length >
                        0 &&
                      filtered
                        .slice(listPage * 50, listPage * 50 + 50)
                        .every((b) => selected.has(key(b)))
                    }
                    onChange={(e) =>
                      setSelected((s) => {
                        const next = new Set(s);
                        filtered
                          .slice(listPage * 50, listPage * 50 + 50)
                          .forEach((b) =>
                            e.target.checked
                              ? next.add(key(b))
                              : next.delete(key(b)),
                          );
                        return next;
                      })
                    }
                  />
                </th>
              )}
              <th>来源 IP</th>
              <th>地理位置</th>
              <th>目标节点</th>
              <th>Service</th>
              <th>观测时间</th>
              {admin && <th className="right">操作</th>}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(listPage * 50, listPage * 50 + 50).map((b, i) => (
              <tr key={key(b) + i}>
                {admin && (
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`选择 ${b.ip}`}
                      checked={selected.has(key(b))}
                      onChange={(e) =>
                        setSelected((s) => {
                          const n = new Set(s);
                          e.target.checked ? n.add(key(b)) : n.delete(key(b));
                          return n;
                        })
                      }
                    />
                  </td>
                )}
                <td>
                  <span className="ip-cell">
                    <i className="legend-source" />
                    <code>{b.ip}</code>
                  </span>
                </td>
                <td>{place(b)}</td>
                <td>
                  {admin ? (
                    <span className="node-cell">{nodeName(b.node_id)}</span>
                  ) : (
                    <NodeAddresses
                      node={data.nodes.find((n) => n.id === b.node_id)}
                    />
                  )}
                  {!data.nodes.find((n) => n.id === b.node_id)?.online && (
                    <small className="stale">最后已知状态</small>
                  )}
                </td>
                <td>
                  <span className="tag">{b.jail}</span>
                </td>
                <td className="muted nowrap">{time(b.observed_at)}</td>
                {admin && (
                  <td className="row-actions">
                    <button disabled={busy} onClick={() => void commands([b])}>
                      解封
                    </button>
                    <button
                      onClick={() => setModal({ kind: "allow", ip: b.ip })}
                    >
                      放行 / 加白
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!filtered.length && (
        <Empty
          icon={<ShieldCheck />}
          title={loading ? "正在连接防护网络…" : "暂无封禁记录"}
          text={
            query || nodeFilter || service
              ? "尝试调整筛选条件"
              : "节点上报的封禁记录会自动显示在这里"
          }
        />
      )}
      {filtered.length > 50 && (
        <div className="pagination">
          <span>
            第 {listPage + 1} / {Math.ceil(filtered.length / 50)} 页
          </span>
          <button
            disabled={listPage === 0}
            onClick={() => setListPage((p) => p - 1)}
          >
            <ArrowLeft size={14} />
            上一页
          </button>
          <button
            disabled={(listPage + 1) * 50 >= filtered.length}
            onClick={() => setListPage((p) => p + 1)}
          >
            下一页
            <ArrowRight size={14} />
          </button>
        </div>
      )}
    </section>
  );
  return (
    <>
      <header className="topbar">
        <a className="brand" href="/">
          <span className="brand-mark">
            <Shield size={22} />
          </span>
          <span>
            fail2ban<span className="brand-light"> mate</span>
          </span>
          <span className="version">v0.1</span>
        </a>
        <div className="top-actions">
          <span className="network-status">
            <i className={error ? "status-error" : "live-dot"} />
            {error
              ? "连接异常"
              : admin
                ? live
                  ? "实时连接"
                  : "轮询同步"
                : "防护网络"}
          </span>
          <a
            className="subtle-link"
            href="https://github.com/cloverstd/fail2ban-mate"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
            <ExternalLink size={13} />
          </a>
          {admin && (
            <a className="btn small" href="/">
              <Globe2 size={15} />
              <span>公开看板</span>
            </a>
          )}
        </div>
      </header>
      <div className={admin ? "app-shell" : "public-shell"}>
        {admin && (
          <aside className="sidebar">
            <div className="nav-label">WORKSPACE</div>
            <nav>
              {(
                [
                  {
                    id: "overview",
                    label: "防护总览",
                    icon: <LayoutDashboard />,
                  },
                  { id: "nodes", label: "节点管理", icon: <Server /> },
                  { id: "bans", label: "封禁列表", icon: <Shield /> },
                  {
                    id: "whitelist",
                    label: "全局白名单",
                    icon: <ShieldCheck />,
                  },
                  { id: "logs", label: "操作记录", icon: <Terminal /> },
                ] as const
              ).map((item) => (
                <button
                  key={item.id}
                  aria-label={item.label}
                  className={page === item.id ? "active" : ""}
                  onClick={() => setPage(item.id)}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  {item.id === "nodes" && <small>{data.nodes.length}</small>}
                </button>
              ))}
            </nav>
            <div className="sidebar-bottom">
              <LockKeyhole size={17} />
              <span>
                Cloudflare Access<small>{data.actor || "等待身份验证"}</small>
              </span>
            </div>
          </aside>
        )}
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                {admin ? "CONTROL CENTER" : "NETWORK OBSERVATORY"}{" "}
                <span>/ FAIL2BAN MATE</span>
              </div>
              <h1>
                {!admin
                  ? "全球防护，实时可见"
                  : {
                      overview: "防护总览",
                      nodes: "节点管理",
                      bans: "封禁列表",
                      whitelist: "全局白名单",
                      logs: "操作记录",
                    }[page]}
              </h1>
              <p>
                {!admin
                  ? "连接每一个节点，洞察每一次拦截。"
                  : {
                      overview: "你的所有节点，一处掌握。",
                      nodes: "连接 Linux 节点，管理传输与防护状态。",
                      bans: "查看完整 IP，精确控制每一条封禁。",
                      whitelist:
                        "规则同步至全部节点与 service，包括以后新增的节点。",
                      logs: "追踪远程命令与管理操作。",
                    }[page]}
              </p>
            </div>
            <div className="heading-actions">
              {admin && page === "nodes" ? (
                <button
                  className="btn primary"
                  onClick={() => setModal({ kind: "node" })}
                >
                  <Plus size={16} />
                  添加节点
                </button>
              ) : admin && page === "bans" ? (
                <button
                  className="btn primary"
                  onClick={() => setModal({ kind: "ban" })}
                >
                  <Plus size={16} />
                  手动封禁
                </button>
              ) : admin && page === "whitelist" ? (
                <button
                  className="btn primary"
                  onClick={() => setModal({ kind: "allow" })}
                >
                  <Plus size={16} />
                  添加规则
                </button>
              ) : (
                <>
                  <span className="last-update">
                    更新于{" "}
                    {data.generated_at
                      ? new Date(data.generated_at * 1000).toLocaleTimeString(
                          "zh-CN",
                          { hour12: false },
                        )
                      : "—"}
                  </span>
                  <button
                    className="icon-btn"
                    aria-label="刷新"
                    onClick={() => void refresh()}
                  >
                    <RefreshCw size={16} />
                  </button>
                </>
              )}
            </div>
          </div>
          {error && (
            <div className="error-banner" role="alert">
              <Activity size={17} />
              {error}
              {admin && (
                <span>
                  请确认 Access 的 GitHub 身份、管理员邮箱及 Worker 配置。
                </span>
              )}
              <button onClick={() => void refresh()}>重试</button>
            </div>
          )}
          {(page === "overview" || !admin) && (
            <>
              <div className="stats">
                <Stat
                  label="受保护节点"
                  value={data.nodes.length}
                  icon={<Server size={19} />}
                  note={`${data.nodes.filter((n) => n.online).length} 个节点在线`}
                  tone="mint"
                />
                <Stat
                  label="当前封禁"
                  value={data.bans.length}
                  icon={<Shield size={19} />}
                  note="按节点与 service 计数"
                  tone="orange"
                />
                <Stat
                  label="来源国家 / 地区"
                  value={
                    new Set(data.bans.map((b) => b.country).filter(Boolean))
                      .size
                  }
                  icon={<Globe2 size={19} />}
                  note="基于 IP 地理位置"
                  tone="blue"
                />
                <Stat
                  label="防护服务"
                  value={services.length}
                  icon={<Activity size={19} />}
                  note="已观测到封禁的 service"
                  tone="purple"
                />
              </div>
              <div className="map-layout">
                <section className="panel map-panel">
                  <WorldMap nodes={visibleNodes} bans={filtered} />
                </section>
                <section className="panel node-summary">
                  <div className="section-header">
                    <h2>防护节点</h2>
                    <span className="count-label">{data.nodes.length}</span>
                  </div>
                  <button
                    className={
                      !nodeFilter ? "summary-node selected" : "summary-node"
                    }
                    onClick={() => setNodeFilter("")}
                  >
                    <span className="summary-icon">
                      <Globe2 size={17} />
                    </span>
                    <span>
                      全部节点<small>显示全球防护网络</small>
                    </span>
                    <ChevronRight size={15} />
                  </button>
                  {data.nodes.map((n) => (
                    <button
                      key={n.id}
                      className={
                        nodeFilter === n.id
                          ? "summary-node selected"
                          : "summary-node"
                      }
                      onClick={() => setNodeFilter(n.id)}
                    >
                      <i className={n.online ? "live-dot" : "offline-dot"} />
                      <span>
                        {n.name && <code>{n.name}</code>}
                        <NodeAddresses node={n} />
                        <small>{place(n)}</small>
                      </span>
                      <span className="node-ban-count">
                        {data.bans.filter((b) => b.node_id === n.id).length}
                      </span>
                    </button>
                  ))}
                  {!data.nodes.length && (
                    <div className="mini-empty">
                      {admin ? "添加第一个节点以开始防护" : "暂无接入节点"}
                    </div>
                  )}
                  <div className="privacy-note">
                    <LockKeyhole size={14} />
                    <span>
                      {admin
                        ? "节点完整信息仅管理员可见"
                        : "节点 IPv4 保留前两段，IPv6 保留前两组"}
                    </span>
                  </div>
                </section>
              </div>
              {banList}
            </>
          )}
          {admin && page === "bans" && banList}
          {admin && page === "nodes" && (
            <div className="node-grid">
              {data.nodes.map((n) => (
                <section className="panel node-card" key={n.id}>
                  <div className="node-card-header">
                    <span className="node-symbol">
                      <Server size={22} />
                    </span>
                    <div>
                      <h2>{n.name}</h2>
                      <NodeAddresses node={n} />
                    </div>
                    <span className={`badge ${n.online ? "success" : ""}`}>
                      <i className={n.online ? "live-dot" : "offline-dot"} />
                      {n.enabled === 0 ? "已停用" : n.online ? "在线" : "离线"}
                    </span>
                  </div>
                  <div className="node-details">
                    <span>
                      地理位置<strong>{place(n)}</strong>
                    </span>
                    <span>
                      客户端版本<strong>{n.version || "尚未连接"}</strong>
                    </span>
                    <span>
                      最后同步<strong>{time(n.last_seen)}</strong>
                    </span>
                    <span>
                      实际传输
                      <strong>
                        {n.actual_mode === "websocket"
                          ? "WebSocket"
                          : n.actual_mode === "polling"
                            ? "HTTP 轮询"
                            : "等待连接"}
                      </strong>
                    </span>
                  </div>
                  {n.error && <p className="node-error">{n.error}</p>}
                  {n.fallback_reason && (
                    <p className="node-warning">{n.fallback_reason}</p>
                  )}
                  <div className="transport">
                    <label>
                      传输方式
                      <select
                        aria-label={`${n.name} 传输方式`}
                        disabled={busy}
                        value={n.mode}
                        onChange={(e) =>
                          void changeNode(n, { mode: e.target.value as Mode })
                        }
                      >
                        <option value="websocket">
                          优先 WebSocket · 自动降级
                        </option>
                        <option value="polling">HTTP 轮询</option>
                      </select>
                    </label>
                    <label>
                      轮询间隔
                      <select
                        aria-label={`${n.name} 轮询间隔`}
                        disabled={busy}
                        value={n.poll_interval}
                        onChange={(e) =>
                          void changeNode(n, {
                            poll_interval: Number(e.target.value),
                          })
                        }
                      >
                        {[5, 10, 15, 30, 60, 120, 300].map((v) => (
                          <option key={v} value={v}>
                            {v} 秒
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <div className="config-status">
                    {n.applied_config_revision === n.config_revision ? (
                      <>
                        <Check size={13} />
                        配置已应用
                      </>
                    ) : (
                      <>
                        <RefreshCw size={13} />
                        等待节点应用配置
                      </>
                    )}
                  </div>
                  <div className="jails">
                    <span className="muted">SERVICES</span>
                    {n.jails?.length ? (
                      n.jails.map((j) => (
                        <button
                          className="tag"
                          key={j}
                          onClick={() => {
                            setNodeFilter(n.id);
                            setService(j);
                            setPage("bans");
                          }}
                        >
                          {j}
                        </button>
                      ))
                    ) : (
                      <small>
                        {n.has_token
                          ? "尚未配置 service，请在节点启用 jail"
                          : "安装客户端后自动发现"}
                      </small>
                    )}
                  </div>
                  <div className="node-card-actions">
                    <button
                      disabled={busy}
                      onClick={() => {
                        if (
                          n.has_token &&
                          !confirm("重新安装将立即撤销旧 token，继续？")
                        )
                          return;
                        void enroll(n);
                      }}
                    >
                      <ArrowDownToLine size={14} />
                      安装命令
                    </button>
                    <button
                      disabled={busy}
                      onClick={() => {
                        const name = prompt("节点名称", n.name);
                        if (name?.trim()) void changeNode(n, { name });
                      }}
                    >
                      改名
                    </button>
                    <button
                      disabled={busy}
                      onClick={() =>
                        void changeNode(n, { enabled: !n.enabled })
                      }
                    >
                      {n.enabled ? "停用" : "启用"}
                    </button>
                    <button
                      disabled={busy || !n.has_token}
                      onClick={() => {
                        if (
                          confirm(
                            "撤销后客户端会立即失去连接权限，需要重新安装注册。",
                          )
                        )
                          void run(() => api(`/nodes/${n.id}/revoke`, {}));
                      }}
                    >
                      撤销 token
                    </button>
                    <button
                      className="danger"
                      aria-label={`删除 ${n.name}`}
                      disabled={busy}
                      onClick={() => {
                        if (
                          confirm(
                            "删除节点和其关联记录？本机 fail2ban 会继续运行。",
                          )
                        )
                          void run(() =>
                            api(`/nodes/${n.id}`, undefined, "DELETE"),
                          );
                      }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </section>
              ))}
              {!data.nodes.length && (
                <section className="panel full-width">
                  <Empty
                    icon={<Server />}
                    title="连接你的第一个节点"
                    text="创建节点后，复制一行安装命令到 Linux 主机执行。"
                  />
                  <div className="empty-action">
                    <button
                      className="btn primary"
                      onClick={() => setModal({ kind: "node" })}
                    >
                      <Plus size={16} />
                      添加节点
                    </button>
                  </div>
                </section>
              )}
            </div>
          )}
          {admin && page === "whitelist" && (
            <>
              <div className="info-banner">
                <ShieldCheck size={20} />
                <span>
                  永久加白和限时放行会解除所有节点上该 IP
                  的当前封禁。到期后恢复正常检测，客户端离线时也会执行到期恢复。
                </span>
              </div>
              <section className="panel">
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>IP 地址</th>
                        <th>有效期</th>
                        <th>创建者</th>
                        <th>同步进度</th>
                        <th className="right">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.policies?.map((p) => (
                        <tr key={p.id}>
                          <td>
                            <code>{p.ip}</code>
                          </td>
                          <td>
                            {p.expires_at ? (
                              time(p.expires_at)
                            ) : (
                              <span className="badge success">永久白名单</span>
                            )}
                          </td>
                          <td>{p.actor}</td>
                          <td>
                            {
                              data.nodes.filter(
                                (n) =>
                                  n.enabled &&
                                  n.has_token &&
                                  !n.error &&
                                  n.applied_policy_revision ===
                                    data.policy_revision,
                              ).length
                            }{" "}
                            /{" "}
                            {
                              data.nodes.filter((n) => n.enabled && n.has_token)
                                .length
                            }{" "}
                            节点已应用
                          </td>
                          <td className="right">
                            <button
                              className="text-btn danger"
                              disabled={busy}
                              onClick={() =>
                                void run(() =>
                                  api(
                                    `/whitelist/${p.id}`,
                                    undefined,
                                    "DELETE",
                                  ),
                                )
                              }
                            >
                              撤销
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!data.policies?.length && (
                  <Empty
                    icon={<ShieldCheck />}
                    title="暂无全局白名单"
                    text="可以永久加白，或为一个 IP 设置限时放行。"
                  />
                )}
              </section>
              <section className="panel policy-nodes">
                <div className="section-header">
                  <h2>逐节点应用状态</h2>
                  <span className="count-label">
                    规则版本 {data.policy_revision}
                  </span>
                </div>
                {data.nodes.map((n) => (
                  <div className="policy-node" key={n.id}>
                    <span>{n.name}</span>
                    <span className="muted">
                      {!n.enabled
                        ? "已停用"
                        : !n.has_token
                          ? "等待安装"
                          : n.error
                            ? `异常：${n.error}`
                            : n.applied_policy_revision === data.policy_revision
                              ? "已应用"
                              : "等待同步"}
                    </span>
                  </div>
                ))}
              </section>
            </>
          )}
          {admin && page === "logs" && (
            <>
              <section className="panel">
                <div className="section-header">
                  <h2>远程命令</h2>
                  <span className="count-label">最近 200 条</span>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>操作 / IP</th>
                        <th>目标</th>
                        <th>执行状态</th>
                        <th>创建时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.commands?.map((c) => (
                        <tr key={c.id}>
                          <td>
                            <span className="tag">
                              {c.kind === "ban" ? "封禁" : "解封"}
                            </span>{" "}
                            <code>{c.ip}</code>
                          </td>
                          <td>
                            {nodeName(c.node_id)} / {c.jail}
                          </td>
                          <td>
                            <span
                              className={`badge ${c.status === "succeeded" ? "success" : c.status === "failed" ? "failure" : ""}`}
                            >
                              {statusName[c.status] || c.status}
                            </span>
                            {c.error && (
                              <small className="stale">{c.error}</small>
                            )}
                          </td>
                          <td className="muted">{time(c.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!data.commands?.length && (
                  <Empty
                    icon={<Terminal />}
                    title="暂无远程命令"
                    text="封禁和解封操作的执行结果会显示在这里。"
                  />
                )}
              </section>
              <section className="panel audit-panel">
                <div className="section-header">
                  <h2>管理审计</h2>
                </div>
                {data.audit?.map((a) => (
                  <details key={a.id} className="audit-item">
                    <summary>
                      <span>
                        {actionName[a.action] || a.action}
                        <small>{a.actor}</small>
                      </span>
                      <time>{time(a.created_at)}</time>
                    </summary>
                    <pre>{JSON.stringify(JSON.parse(a.detail), null, 2)}</pre>
                  </details>
                ))}
              </section>
            </>
          )}
          <footer>
            <span>
              <Shield size={13} /> FAIL2BAN MATE{" "}
              <span className="footer-divider">/</span> BUILT ON CLOUDFLARE
            </span>
            <a href="https://db-ip.com" target="_blank" rel="noreferrer">
              IP Geolocation by DB-IP <ExternalLink size={11} />
            </a>
          </footer>
        </main>
      </div>
      {admin && modal && (
        <Dialog
          modal={modal}
          nodes={data.nodes}
          busy={busy}
          close={() => setModal(null)}
          submit={async (path, body) => {
            setBusy(true);
            try {
              const r = await api<{ enrollment?: string }>(path, body);
              if (r.enrollment)
                setModal({
                  kind: "install",
                  code: r.enrollment,
                  name: (body as { name: string }).name,
                });
              else {
                setModal(null);
                setToast("操作已提交");
              }
              await refresh();
            } catch (e) {
              setToast((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          {toast}
          <button aria-label="关闭提示" onClick={() => setToast("")}>
            <X size={15} />
          </button>
        </div>
      )}
    </>
  );
}
function Stat({
  label,
  value,
  icon,
  note,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  note: string;
  tone: string;
}) {
  return (
    <section className={`panel stat ${tone}`}>
      <div>
        <span>{label}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <strong>{value.toLocaleString()}</strong>
      <small>{note}</small>
    </section>
  );
}
function Empty({
  icon,
  title,
  text,
}: {
  icon: React.ReactNode;
  title: string;
  text: string;
}) {
  return (
    <div className="empty">
      <span>{icon}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
function Dialog({
  modal,
  nodes,
  busy,
  close,
  submit,
}: {
  modal: Modal;
  nodes: Node[];
  busy: boolean;
  close: () => void;
  submit: (path: string, body: unknown) => Promise<void>;
}) {
  const [name, setName] = useState(""),
    [ip, setIP] = useState("ip" in modal ? modal.ip || "" : ""),
    [node, setNode] = useState(
      "node" in modal
        ? modal.node ||
            nodes.find((n) => n.enabled && n.jails?.length)?.id ||
            ""
        : nodes.find((n) => n.enabled && n.jails?.length)?.id || "",
    ),
    [jail, setJail] = useState("jail" in modal ? modal.jail || "" : ""),
    [duration, setDuration] = useState("3600"),
    [custom, setCustom] = useState("60"),
    [copied, setCopied] = useState(false);
  const n = nodes.find((n) => n.id === node);
  const actualJail = n?.jails?.includes(jail) ? jail : n?.jails?.[0] || "";
  const title = {
    node: "添加防护节点",
    ban: "手动封禁 IP",
    allow: "全局放行与加白",
    install: "安装节点客户端",
  }[modal.kind];
  useEffect(() => {
    const fn = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("keydown", fn);
    const old = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", fn);
      document.body.style.overflow = old;
    };
  }, [close]);
  const install =
    modal.kind === "install"
      ? `curl -fsSL ${location.origin}/install.sh | sudo sh -s -- --server ${location.origin} --enrollment ${modal.code}`
      : "";
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) close();
      }}
    >
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            className="icon-btn"
            aria-label="关闭"
            disabled={busy}
            onClick={close}
          >
            <X size={19} />
          </button>
        </div>
        {modal.kind === "install" ? (
          <>
            <p>
              在 <strong>{modal.name}</strong> 上执行。凭据仅可使用一次，10
              分钟后过期。
            </p>
            <div className="install-command">
              <code>{install}</code>
            </div>
            <button
              className="btn primary"
              onClick={() => {
                void navigator.clipboard
                  .writeText(install)
                  .then(() => setCopied(true));
              }}
            >
              {copied ? <Check size={15} /> : <Copy size={15} />}{" "}
              {copied ? "已复制" : "复制安装命令"}
            </button>
            <p className="modal-note">
              自动安装 fail2ban 和客户端，并注册 systemd 服务。现有 jail
              配置会保留；新主机需要自行启用相应 jail。
            </p>
          </>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (modal.kind === "node") void submit("/nodes", { name });
              if (modal.kind === "allow")
                void submit("/whitelist", {
                  ip,
                  duration:
                    duration === "permanent"
                      ? null
                      : duration === "custom"
                        ? Number(custom) * 60
                        : Number(duration),
                });
              if (modal.kind === "ban")
                void submit("/commands", [
                  { node_id: node, jail: actualJail, ip, kind: "ban" },
                ]);
            }}
          >
            {modal.kind === "node" ? (
              <label>
                节点名称
                <input
                  autoFocus
                  required
                  maxLength={80}
                  placeholder="例如：Singapore · edge-01"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
            ) : (
              <>
                <label>
                  IP 地址
                  <input
                    autoFocus
                    required
                    placeholder="IPv4 或 IPv6"
                    value={ip}
                    onChange={(e) => setIP(e.target.value)}
                  />
                </label>
                {modal.kind === "ban" ? (
                  <>
                    <label>
                      目标节点
                      <select
                        value={node}
                        onChange={(e) => setNode(e.target.value)}
                        required
                      >
                        <option value="">选择节点</option>
                        {nodes
                          .filter((n) => n.enabled && n.has_token)
                          .map((n) => (
                            <option key={n.id} value={n.id}>
                              {n.name}
                              {n.online ? "" : "（离线，等待下发）"}
                            </option>
                          ))}
                      </select>
                    </label>
                    <label>
                      Service
                      <select
                        value={actualJail}
                        onChange={(e) => setJail(e.target.value)}
                        required
                      >
                        <option value="">选择 service</option>
                        {n?.jails?.map((j) => (
                          <option key={j}>{j}</option>
                        ))}
                      </select>
                    </label>
                    <p className="modal-note">
                      封禁时长沿用 jail 配置。命令等待执行超过 10 分钟会过期。
                    </p>
                  </>
                ) : (
                  <>
                    <label>
                      有效时间
                      <select
                        value={duration}
                        onChange={(e) => setDuration(e.target.value)}
                      >
                        <option value="600">10 分钟</option>
                        <option value="3600">1 小时</option>
                        <option value="86400">24 小时</option>
                        <option value="custom">自定义</option>
                        <option value="permanent">永久加白</option>
                      </select>
                    </label>
                    {duration === "custom" && (
                      <label>
                        有效分钟数
                        <input
                          required
                          type="number"
                          min="1"
                          max="43200"
                          value={custom}
                          onChange={(e) => setCustom(e.target.value)}
                        />
                      </label>
                    )}
                    <div className="info-banner">
                      <Globe2 size={18} />
                      <span>作用于所有节点和 service，并解除当前封禁。</span>
                    </div>
                  </>
                )}
              </>
            )}
            <div className="modal-actions">
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={close}
              >
                取消
              </button>
              <button type="submit" className="btn primary" disabled={busy}>
                {busy ? (
                  <LoaderCircle className="spin" size={15} />
                ) : (
                  <Plus size={15} />
                )}{" "}
                {modal.kind === "node"
                  ? "创建并生成安装命令"
                  : modal.kind === "ban"
                    ? "下发封禁命令"
                    : "应用全局规则"}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>{admin ? <App /> : <PublicApp />}</React.StrictMode>,
);
