import React, { useEffect, useState } from "react";
import type {
  FirewallDraft,
  FirewallGroup,
  FirewallNodeDetail,
  FirewallPreview,
  FirewallRule,
} from "../shared/firewall";
import type { Node } from "./types";

type API = <T>(path: string, body?: unknown, method?: string) => Promise<T>;
const actionNames = { allow: "放行", deny: "丢弃", reject: "拒绝" };
const directions = { in: "入站", out: "出站", route: "转发" };
const releaseNames = {
  pending: "等待节点",
  applying: "执行中",
  applied: "已生效",
  failed: "失败",
  rolled_back: "已回滚",
  superseded: "已替代",
};
const newRule = (priority: number): FirewallRule => ({
  id: crypto.randomUUID(),
  priority,
  enabled: true,
  direction: "in",
  action: "allow",
  family: "any",
  protocol: "any",
  source: "",
  destination: "",
  source_port: "",
  destination_port: "",
  in_interface: "",
  out_interface: "",
  comment: "",
});
const newDraft = (): FirewallDraft & { revision: number } => ({
  revision: 0,
  bindings: [],
  defaults: { in: "deny", out: "allow", route: "deny" },
  protection: [],
});
const byPriority = <T extends { priority: number }>(items: T[]) =>
  [...items].sort((a, b) => a.priority - b.priority);
function reorder<T extends { priority: number }>(
  items: T[],
  from: number,
  to: number,
) {
  const next = [...items];
  if (from < 0 || to < 0 || from >= next.length || to >= next.length)
    return next;
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next.map((value, index) => ({ ...value, priority: (index + 1) * 10 }));
}

function diffRules(before: FirewallRule[], after: FirewallRule[]) {
  const normalize = (rule: FirewallRule) => {
    const { id: _id, priority: _priority, ...rest } = rule;
    return JSON.stringify({
      ...rest,
      source: rest.source.replace(/\/(32|128)$/, (suffix) =>
        suffix === (rest.family === "ipv4" ? "/32" : "/128") ? "" : suffix,
      ),
      destination: rest.destination.replace(/\/(32|128)$/, (suffix) =>
        suffix === (rest.family === "ipv4" ? "/32" : "/128") ? "" : suffix,
      ),
    });
  };
  const keys = (rules: FirewallRule[]) =>
    rules
      .filter((r) => r.enabled)
      .flatMap((r) =>
        r.family === "any"
          ? [
              normalize({ ...r, family: "ipv4" }),
              normalize({ ...r, family: "ipv6" }),
            ]
          : [normalize(r)],
      );
  const old = keys(before);
  const next = keys(after);
  const previous = new Map<string, number[]>();
  old.forEach((key, index) => {
    const occurrences = previous.get(key) ?? [];
    occurrences.push(index);
    previous.set(key, occurrences);
  });
  let added = 0;
  let moved = 0;
  let lastIndex = -1;
  for (const key of next) {
    const position = previous.get(key)?.shift();
    if (position === undefined) added++;
    else if (position < lastIndex) moved++;
    else lastIndex = position;
  }
  return { added, moved, removed: old.length - next.length + added };
}

function RuleTable({
  rules,
  caption,
}: {
  rules: FirewallRule[];
  caption?: string;
}) {
  return (
    <div className="table-scroll">
      <table className="firewall-table">
        {caption && <caption>{caption}</caption>}
        <thead>
          <tr>
            <th>顺序</th>
            <th>方向</th>
            <th>动作</th>
            <th>协议</th>
            <th>来源</th>
            <th>目标</th>
            <th>网卡</th>
            <th>备注</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r, i) => (
            <tr
              key={r.id + "_" + i}
              className={r.enabled ? "" : "firewall-disabled"}
            >
              <td>{i + 1}</td>
              <td>{directions[r.direction]}</td>
              <td>
                {actionNames[r.action]}
                {r.enabled ? "" : "（停用）"}
              </td>
              <td>
                {r.family === "any" ? "双栈" : r.family} ·{" "}
                {r.protocol.toUpperCase()}
              </td>
              <td>
                {r.source || "任意"}
                {r.source_port && " · " + r.source_port}
              </td>
              <td>
                {r.destination || "任意"}
                {r.destination_port && " · " + r.destination_port}
              </td>
              <td>
                {[r.in_interface, r.out_interface]
                  .filter(Boolean)
                  .join(" → ") || "任意"}
              </td>
              <td>{r.comment || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rules.length === 0 && <p>没有业务规则</p>}
    </div>
  );
}

function RuleEditor({
  rule,
  onChange,
  remove,
}: {
  rule: FirewallRule;
  onChange: (r: FirewallRule) => void;
  remove: () => void;
}) {
  const choices = <K extends "direction" | "action" | "family" | "protocol">(
    key: K,
    title: string,
    options: [FirewallRule[K], string][],
  ) => (
    <label>
      {title}
      <select
        aria-label={title}
        value={rule[key]}
        onChange={(e) => {
          const value = e.target.value as FirewallRule[K];
          const next = { ...rule, [key]: value };
          if (key === "direction") {
            if (value === "in") next.out_interface = "";
            if (value === "out") next.in_interface = "";
          }
          if (key === "protocol" && value !== "tcp" && value !== "udp") {
            next.source_port = "";
            next.destination_port = "";
          }
          if (key === "family" && value === "any") {
            next.source = "";
            next.destination = "";
          }
          onChange(next);
        }}
      >
        {options.map(([value, label]) => (
          <option value={value} key={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
  const field = (
    key:
      | "source"
      | "destination"
      | "source_port"
      | "destination_port"
      | "in_interface"
      | "out_interface"
      | "comment",
    label: string,
    disabled = false,
  ) => (
    <label>
      {label}
      <input
        value={rule[key]}
        disabled={disabled}
        onChange={(e) => onChange({ ...rule, [key]: e.target.value })}
      />
    </label>
  );
  const noPorts = rule.protocol !== "tcp" && rule.protocol !== "udp";
  return (
    <div className="firewall-rule-fields">
      <label>
        规则优先级
        <input
          type="number"
          min={1}
          max={1000000}
          value={rule.priority || ""}
          onChange={(e) =>
            onChange({ ...rule, priority: Number(e.target.value) })
          }
        />
      </label>
      {choices("direction", "方向", [
        ["in", "入站"],
        ["out", "出站"],
        ["route", "转发"],
      ])}
      {choices("action", "动作", [
        ["allow", "放行"],
        ["deny", "丢弃"],
        ["reject", "拒绝"],
      ])}
      {choices("family", "地址族", [
        ["any", "双栈（任意来源和目标）"],
        ["ipv4", "IPv4"],
        ["ipv6", "IPv6"],
      ])}
      {choices("protocol", "协议", [
        ["any", "全部"],
        ["tcp", "TCP"],
        ["udp", "UDP"],
        ["icmp", "ICMP"],
      ])}
      {field("source", "来源 IP / CIDR", rule.family === "any")}
      {field("destination", "目标 IP / CIDR", rule.family === "any")}
      {field("source_port", "来源端口或范围（如 1000:2000）", noPorts)}
      {field("destination_port", "目标端口或范围", noPorts)}
      {field("in_interface", "入站网卡", rule.direction === "out")}
      {field("out_interface", "出站网卡", rule.direction === "in")}
      {field("comment", "备注")}
      <label className="firewall-check">
        <input
          type="checkbox"
          checked={rule.enabled}
          onChange={(e) => onChange({ ...rule, enabled: e.target.checked })}
        />
        启用规则
      </label>
      <button className="btn small" onClick={remove}>
        删除规则
      </button>
    </div>
  );
}

export function Firewall({
  nodes,
  api,
  time,
  initialNode,
}: {
  nodes: Node[];
  api: API;
  time: (t: number | undefined) => string;
  initialNode?: string;
}) {
  const [groups, setGroups] = useState<FirewallGroup[]>([]);
  const [editor, setEditor] = useState<FirewallGroup | null>(null);
  const [nodeID, setNodeID] = useState(initialNode ?? nodes[0]?.id ?? "");
  const [detail, setDetail] = useState<FirewallNodeDetail | null>(null);
  const [draft, setDraft] = useState<
    (FirewallDraft & { revision: number }) | null
  >(null);
  const [view, setView] = useState<"groups" | "nodes">(
    initialNode ? "nodes" : "groups",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [previews, setPreviews] = useState<FirewallPreview[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [rollback, setRollback] = useState<string>();
  const activeNode = nodes.find((n) => n.id === nodeID);
  const path = "/firewall/nodes/" + nodeID;
  const refreshGroups = async () => {
    const result = await api<FirewallGroup[]>("/firewall/groups");
    setGroups(result);
    return result;
  };
  useEffect(() => {
    void refreshGroups().catch((e: Error) => setError(e.message));
  }, [api]);
  useEffect(() => {
    if (!nodeID && nodes.length) setNodeID(nodes[0].id);
  }, [nodes, nodeID]);
  useEffect(() => {
    if (view !== "nodes" || !nodeID) return;
    let active = true;
    let request = 0;
    setDetail(null);
    const refresh = async () => {
      const current = ++request;
      try {
        const result = await api<FirewallNodeDetail>(path);
        if (active && current === request) setDetail(result);
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [api, path, nodeID, view]);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const selectNode = (value: string) => {
    setNodeID(value);
    setDraft(null);
    setPreviews([]);
    setSelected([]);
    setRollback(undefined);
    setError("");
  };
  const saveGroup = async () => {
    if (!editor) return;
    if (editor.id) await api("/firewall/groups/" + editor.id, editor, "PUT");
    else await api("/firewall/groups", editor);
    await refreshGroups();
    setEditor(null);
    setNotice("已保存规则组草稿");
  };
  const previewNode = async (id: string, old?: string) =>
    api<FirewallPreview>(
      "/firewall/nodes/" + id + "/preview",
      old ? { rollback: old } : {},
    );
  const openPreview = async (old?: string) => {
    const preview = await previewNode(nodeID, old);
    setPreviews([preview]);
    setSelected([nodeID]);
    setRollback(old);
  };
  const togglePreview = async (id: string) => {
    if (selected.includes(id)) {
      setSelected(selected.filter((n) => n !== id));
      return;
    }
    const other = await previewNode(id);
    setPreviews([...previews.filter((p) => p.node_id !== id), other]);
    setSelected([...selected, id]);
  };
  const publish = async () => {
    const result = await api<{
      outcomes: { node_id: string; id?: string; error?: string }[];
    }>(
      "/firewall/publish",
      previews
        .filter((p) => selected.includes(p.node_id))
        .map((p) => ({
          node_id: p.node_id,
          version: p.version,
          rollback: p.node_id === nodeID ? rollback : undefined,
        })),
    );
    setNotice(
      result.outcomes
        .map(
          (r) =>
            (nodes.find((n) => n.id === r.node_id)?.name || r.node_id) +
            " · " +
            (r.error || "已提交发布"),
        )
        .join("，"),
    );
    setPreviews([]);
    setSelected([]);
    setDetail(await api<FirewallNodeDetail>(path));
  };
  const observe = detail?.observation;
  const activeDraft = draft ?? detail?.draft;
  const orderedBindings = byPriority(activeDraft?.bindings ?? []);
  const applied = detail?.history.find((r) => r.status === "applied");
  const rulesForDraft = orderedBindings.flatMap(({ group_id }) =>
    byPriority(groups.find((g) => g.id === group_id)?.rules ?? []),
  );
  return (
    <div className="firewall-layout">
      <div className="toolbar">
        <button
          className={"btn " + (view === "groups" ? "primary" : "")}
          onClick={() => setView("groups")}
        >
          规则组
        </button>
        <button
          className={"btn " + (view === "nodes" ? "primary" : "")}
          onClick={() => setView("nodes")}
        >
          节点规则
        </button>
      </div>
      {error && (
        <p role="alert" className="info-banner">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="info-banner">
          {notice}
        </p>
      )}
      {view === "groups" && (
        <section className="panel firewall-panel">
          <div className="firewall-bar">
            <h2>规则组</h2>
            <button
              className="btn primary"
              disabled={busy}
              onClick={() =>
                setEditor({ id: "", name: "", revision: 0, rules: [] })
              }
            >
              创建规则组
            </button>
          </div>
          {groups.map((g) => (
            <div className="firewall-bar" key={g.id}>
              <span>
                {g.name} · {g.rules.length} 条规则 · 版本 {g.revision}
              </span>
              <div className="toolbar">
                <button
                  className="btn small"
                  onClick={() =>
                    setEditor({ ...g, rules: byPriority(g.rules) })
                  }
                >
                  编辑
                </button>
                <button
                  className="btn small"
                  onClick={() =>
                    setEditor({
                      ...g,
                      id: "",
                      revision: 0,
                      name: g.name + " 副本",
                      rules: byPriority(g.rules).map((r) => ({
                        ...r,
                        id: crypto.randomUUID(),
                      })),
                    })
                  }
                >
                  复制
                </button>
                <button
                  className="btn small"
                  disabled={busy}
                  onClick={() => {
                    if (window.confirm("删除规则组 " + g.name + "？"))
                      void run(async () => {
                        await api(
                          "/firewall/groups/" +
                            g.id +
                            "?revision=" +
                            g.revision,
                          undefined,
                          "DELETE",
                        );
                        await refreshGroups();
                        if (editor?.id === g.id) setEditor(null);
                      });
                  }}
                >
                  删除
                </button>
              </div>
            </div>
          ))}
          {editor && (
            <div className="firewall-editor">
              <label>
                规则组名称
                <input
                  value={editor.name}
                  maxLength={80}
                  onChange={(e) =>
                    setEditor({ ...editor, name: e.target.value })
                  }
                />
              </label>
              {editor.rules.map((r, index) => (
                <div
                  className="firewall-rule"
                  key={r.id}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    const from = e.dataTransfer.getData(
                      "application/x-firewall-rule",
                    );
                    if (from)
                      setEditor({
                        ...editor,
                        rules: reorder(editor.rules, Number(from), index),
                      });
                  }}
                >
                  <div className="toolbar">
                    <span
                      draggable
                      onDragStart={(e) =>
                        e.dataTransfer.setData(
                          "application/x-firewall-rule",
                          String(index),
                        )
                      }
                    >
                      ⠿ 拖动排序
                    </span>
                    <button
                      className="btn small"
                      disabled={index === 0}
                      onClick={() =>
                        setEditor({
                          ...editor,
                          rules: reorder(editor.rules, index, index - 1),
                        })
                      }
                    >
                      上移
                    </button>
                    <button
                      className="btn small"
                      disabled={index === editor.rules.length - 1}
                      onClick={() =>
                        setEditor({
                          ...editor,
                          rules: reorder(editor.rules, index, index + 1),
                        })
                      }
                    >
                      下移
                    </button>
                  </div>
                  <RuleEditor
                    rule={r}
                    onChange={(rule) =>
                      setEditor({
                        ...editor,
                        rules: editor.rules.map((v) =>
                          v.id === r.id ? rule : v,
                        ),
                      })
                    }
                    remove={() =>
                      setEditor({
                        ...editor,
                        rules: editor.rules.filter((v) => v.id !== r.id),
                      })
                    }
                  />
                </div>
              ))}
              <div className="toolbar">
                <button
                  className="btn"
                  onClick={() =>
                    setEditor({
                      ...editor,
                      rules: [
                        ...editor.rules,
                        newRule(
                          Math.max(0, ...editor.rules.map((r) => r.priority)) +
                            10,
                        ),
                      ],
                    })
                  }
                >
                  添加规则
                </button>
                <button
                  className="btn primary"
                  disabled={busy || !editor.name.trim()}
                  onClick={() => void run(saveGroup)}
                >
                  保存规则组草稿
                </button>
                <button className="btn" onClick={() => setEditor(null)}>
                  取消
                </button>
              </div>
            </div>
          )}
        </section>
      )}
      {view === "nodes" && (
        <section className="panel firewall-panel">
          <div className="firewall-bar">
            <label>
              节点
              <select
                value={nodeID}
                onChange={(e) => selectNode(e.target.value)}
              >
                {nodes.map((n) => (
                  <option value={n.id} key={n.id}>
                    {n.name ?? n.id}
                    {n.online ? "" : "（离线）"}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="btn small"
              disabled={!nodeID || busy}
              onClick={() =>
                void run(async () => {
                  await api(path + "/refresh", {});
                  setNotice("已请求刷新节点快照");
                })
              }
            >
              刷新节点规则
            </button>
          </div>
          {detail && !observe && (
            <p>尚未收到 UFW 快照。请升级客户端并等待同步。</p>
          )}
          {observe && (
            <>
              <p>
                UFW{" "}
                {observe.status === "active"
                  ? "已启用"
                  : observe.status === "inactive"
                    ? "未启用"
                    : "不可用"}{" "}
                · 最后观测 {time(observe.observed_at)}
                {activeNode?.online ? "" : " · 节点离线，显示最后上报"} ·{" "}
                {applied ? "已接管" : "采集模式"}
              </p>
              <p>
                当前默认策略{" "}
                {Object.entries(observe.defaults)
                  .map(
                    ([key, value]) =>
                      directions[key as keyof typeof directions] +
                      " " +
                      (value ? actionNames[value] : "未知"),
                  )
                  .join(" · ")}
              </p>
              {observe.blocked?.map((reason, i) => (
                <p key={i} className="info-banner">
                  {reason}
                </p>
              ))}
              <RuleTable
                rules={observe.rules}
                caption="节点观测到的 UFW 用户规则"
              />
              {Object.entries({
                "基础链（先于用户规则）和后置链": observe.baseline,
                内核实际执行规则: observe.live,
                "Fail2ban / Docker 外部链": observe.external,
              }).map(
                ([title, entries]) =>
                  entries && (
                    <details key={title}>
                      <summary>{title}</summary>
                      {Object.entries(entries).map(([name, lines]) => (
                        <div key={name}>
                          <strong>{name}</strong>
                          <pre>{lines.join("\n")}</pre>
                        </div>
                      ))}
                    </details>
                  ),
              )}
              {!activeDraft && (
                <div className="toolbar">
                  <button
                    className="btn primary"
                    disabled={
                      busy ||
                      observe.status !== "active" ||
                      Boolean(observe.blocked?.length)
                    }
                    onClick={() =>
                      void run(async () => {
                        await api(path + "/import", {});
                        await refreshGroups();
                        setDetail(await api<FirewallNodeDetail>(path));
                        setNotice("已导入节点草稿");
                      })
                    }
                  >
                    导入现有规则
                  </button>
                  <button
                    className="btn"
                    onClick={() =>
                      setDraft({
                        ...newDraft(),
                        protection: observe.protection,
                      })
                    }
                  >
                    创建节点草稿
                  </button>
                </div>
              )}
            </>
          )}
          {activeDraft && (
            <div className="firewall-editor">
              <h3>节点草稿 · 版本 {activeDraft.revision}</h3>
              <div className="firewall-rule-fields">
                {(["in", "out", "route"] as const).map((direction) => (
                  <label key={direction}>
                    {directions[direction]}默认策略
                    <select
                      value={activeDraft.defaults[direction]}
                      onChange={(e) =>
                        setDraft({
                          ...activeDraft,
                          defaults: {
                            ...activeDraft.defaults,
                            [direction]: e.target.value,
                          },
                        })
                      }
                    >
                      {Object.entries(actionNames).map(([key, value]) => (
                        <option key={key} value={key}>
                          {value}
                        </option>
                      ))}
                    </select>
                  </label>
                ))}
              </div>
              <h4>绑定规则组</h4>
              {orderedBindings.map((b, index) => (
                <div
                  className="firewall-bar"
                  key={b.group_id}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    const from = e.dataTransfer.getData(
                      "application/x-firewall-binding",
                    );
                    if (from)
                      setDraft({
                        ...activeDraft,
                        bindings: reorder(orderedBindings, Number(from), index),
                      });
                  }}
                >
                  <span
                    draggable
                    onDragStart={(e) =>
                      e.dataTransfer.setData(
                        "application/x-firewall-binding",
                        String(index),
                      )
                    }
                  >
                    ⠿{" "}
                    {groups.find((g) => g.id === b.group_id)?.name ??
                      b.group_id}
                  </span>
                  <div className="toolbar">
                    <label>
                      组优先级
                      <input
                        type="number"
                        min={1}
                        value={b.priority || ""}
                        onChange={(e) =>
                          setDraft({
                            ...activeDraft,
                            bindings: activeDraft.bindings.map((v) =>
                              v.group_id === b.group_id
                                ? { ...v, priority: Number(e.target.value) }
                                : v,
                            ),
                          })
                        }
                      />
                    </label>
                    <button
                      className="btn small"
                      disabled={index === 0}
                      onClick={() =>
                        setDraft({
                          ...activeDraft,
                          bindings: reorder(orderedBindings, index, index - 1),
                        })
                      }
                    >
                      上移
                    </button>
                    <button
                      className="btn small"
                      disabled={index === orderedBindings.length - 1}
                      onClick={() =>
                        setDraft({
                          ...activeDraft,
                          bindings: reorder(orderedBindings, index, index + 1),
                        })
                      }
                    >
                      下移
                    </button>
                    <button
                      className="btn small"
                      onClick={() =>
                        setDraft({
                          ...activeDraft,
                          bindings: activeDraft.bindings.filter(
                            (v) => v.group_id !== b.group_id,
                          ),
                        })
                      }
                    >
                      解除绑定
                    </button>
                  </div>
                </div>
              ))}
              <label>
                添加绑定
                <select
                  value=""
                  onChange={(e) =>
                    e.target.value &&
                    setDraft({
                      ...activeDraft,
                      bindings: [
                        ...activeDraft.bindings,
                        {
                          group_id: e.target.value,
                          priority:
                            Math.max(
                              0,
                              ...activeDraft.bindings.map((b) => b.priority),
                            ) + 10,
                        },
                      ],
                    })
                  }
                >
                  <option value="">选择规则组</option>
                  {groups
                    .filter(
                      (g) =>
                        !activeDraft.bindings.some((b) => b.group_id === g.id),
                    )
                    .map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                </select>
              </label>
              <RuleTable
                rules={rulesForDraft}
                caption="草稿合并顺序（基础规则之后）"
              />
              <details>
                <summary>受保护的 SSH 入口</summary>
                {activeDraft.protection.map((p, i) => (
                  <div className="toolbar" key={i}>
                    <label>
                      来源
                      <input
                        value={p.source}
                        onChange={(e) =>
                          setDraft({
                            ...activeDraft,
                            protection: activeDraft.protection.map((v, j) =>
                              j === i ? { ...v, source: e.target.value } : v,
                            ),
                          })
                        }
                      />
                    </label>
                    <label>
                      端口
                      <input
                        type="number"
                        min={1}
                        max={65535}
                        value={p.port}
                        onChange={(e) =>
                          setDraft({
                            ...activeDraft,
                            protection: activeDraft.protection.map((v, j) =>
                              j === i
                                ? { ...v, port: Number(e.target.value) }
                                : v,
                            ),
                          })
                        }
                      />
                    </label>
                    <button
                      className="btn small"
                      onClick={() =>
                        setDraft({
                          ...activeDraft,
                          protection: activeDraft.protection.filter(
                            (_, j) => j !== i,
                          ),
                        })
                      }
                    >
                      移除入口
                    </button>
                  </div>
                ))}
                <button
                  className="btn small"
                  onClick={() =>
                    setDraft({
                      ...activeDraft,
                      protection: [
                        ...activeDraft.protection,
                        { source: "", port: 22 },
                      ],
                    })
                  }
                >
                  添加受保护入口
                </button>
              </details>
              <div className="toolbar">
                <button
                  className="btn"
                  disabled={busy || !draft}
                  onClick={() =>
                    void run(async () => {
                      await api(path + "/draft", activeDraft, "PUT");
                      setDetail(await api<FirewallNodeDetail>(path));
                      setDraft(null);
                      setPreviews([]);
                      setNotice("已保存节点草稿");
                    })
                  }
                >
                  保存节点草稿
                </button>
                <button
                  className="btn primary"
                  disabled={busy || !!draft}
                  onClick={() => void run(() => openPreview())}
                >
                  预览发布
                </button>
              </div>
            </div>
          )}
          {!!previews.length && (
            <div className="firewall-editor">
              <h3>{rollback ? "回滚预览" : "发布预览"}</h3>
              {!rollback && (
                <div className="toolbar">
                  {Array.from(
                    new Map(
                      [
                        { id: nodeID, name: activeNode?.name ?? nodeID },
                        ...previews[0].affected,
                      ].map((n) => [n.id, n]),
                    ).values(),
                  ).map((n) => (
                    <label key={n.id} className="firewall-check">
                      <input
                        type="checkbox"
                        checked={selected.includes(n.id)}
                        disabled={busy}
                        onChange={() => void run(() => togglePreview(n.id))}
                      />
                      {n.name}
                    </label>
                  ))}
                </div>
              )}
              {previews
                .filter((p) => selected.includes(p.node_id))
                .map((p) => (
                  <div key={p.node_id}>
                    <h4>
                      {nodes.find((n) => n.id === p.node_id)?.name || p.node_id}
                    </h4>
                    <p>
                      {(["in", "out", "route"] as const)
                        .map(
                          (direction) =>
                            directions[direction] +
                            " " +
                            (p.before_defaults
                              ? actionNames[p.before_defaults[direction]]
                              : "未知") +
                            " → " +
                            actionNames[p.after.defaults[direction]],
                        )
                        .join(" · ")}
                    </p>
                    <p>
                      {(() => {
                        const { added, removed, moved } = diffRules(
                          p.before,
                          p.after.rules,
                        );
                        return `规则差异（按地址族展开） · 新增 ${added} · 移除 ${removed} · 顺序调整 ${moved}`;
                      })()}
                    </p>
                    <RuleTable rules={p.before} caption="当前顺序" />
                    <RuleTable rules={p.after.rules} caption="发布后的顺序" />
                    {Object.entries(p.baseline_changes ?? {}).map(
                      ([name, change]) => (
                        <details key={name}>
                          <summary>{name} · 接管时转换前置规则</summary>
                          <p>当前</p>
                          <pre>{change.before.join("\n")}</pre>
                          <p>发布后</p>
                          <pre>{change.after.join("\n")}</pre>
                        </details>
                      ),
                    )}
                  </div>
                ))}
              <div className="toolbar">
                <button
                  className="btn primary"
                  disabled={busy || !selected.length}
                  onClick={() => void run(publish)}
                >
                  发布到所选节点
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    setPreviews([]);
                    setSelected([]);
                  }}
                >
                  关闭预览
                </button>
              </div>
            </div>
          )}
          {!!detail?.history.length && (
            <div className="firewall-editor">
              <h3>发布和回滚记录</h3>
              {detail.history.map((r) => (
                <div className="firewall-bar" key={r.id}>
                  <span>
                    {time(r.created_at)} · {releaseNames[r.status]} ·{" "}
                    {r.id.slice(0, 8)} · {r.actor}
                    {r.error && " · " + r.error}
                    {r.drift &&
                      " · 本机漂移恢复 " +
                        releaseNames[r.drift.status] +
                        (r.drift.changed?.length
                          ? " · " + r.drift.changed.join("、")
                          : "") +
                        (r.drift.error ? " · " + r.drift.error : "")}
                  </span>
                  {r.status === "applied" && (
                    <button
                      className="btn small"
                      disabled={busy}
                      onClick={() => void run(() => openPreview(r.id))}
                    >
                      {r.id === applied?.id && r.drift?.status !== "applied"
                        ? "预览重新应用"
                        : "预览回滚到此版本"}
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
