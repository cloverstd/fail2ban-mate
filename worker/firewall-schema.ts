import { z } from "zod";
import ipaddr from "ipaddr.js";

export const uuid = z.string().uuid();
const id = z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/);
export const fingerprint = z.string().regex(/^[a-f0-9]{64}$/);
export const revision = z.number().int().nonnegative();
const priority = z.number().int().min(1).max(1000000);
const action = z.enum(["allow", "deny", "reject"]);
export const defaults = z.object({ in: action, out: action, route: action });
const iface = z.string().regex(/^(?:[a-zA-Z0-9_.-]{1,15})?$/);
const port = z
  .string()
  .regex(/^(?:[0-9]{1,5}(?::[0-9]{1,5})?)?$/)
  .refine((s) => {
    if (!s) return true;
    const [low, high = low] = s.split(":").map(Number);
    return low >= 1 && high >= low && high <= 65535;
  }, "无效的端口范围");
function family(address: string) {
  const [ip] = address.split("/");
  if (
    address.includes("%") ||
    (!ip.includes(":") &&
      !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(ip))
  )
    return null;
  try {
    const parsed = address.includes("/")
      ? ipaddr.parseCIDR(address)[0]
      : ipaddr.parse(address);
    if (parsed instanceof ipaddr.IPv6 && parsed.isIPv4MappedAddress())
      return null;
    return parsed.kind();
  } catch {
    return null;
  }
}
const address = z
  .string()
  .max(64)
  .refine((s) => !s || family(s) !== null, "无效的 IP 或 CIDR");
export const firewallRule = z
  .object({
    id,
    priority,
    enabled: z.boolean(),
    direction: z.enum(["in", "out", "route"]),
    action,
    family: z.enum(["any", "ipv4", "ipv6"]),
    protocol: z.enum(["any", "tcp", "udp", "icmp"]),
    source: address,
    destination: address,
    source_port: port,
    destination_port: port,
    in_interface: iface,
    out_interface: iface,
    comment: z.string().max(256),
  })
  .refine(
    (r) =>
      (!r.source || family(r.source) === r.family) &&
      (!r.destination || family(r.destination) === r.family) &&
      (!(r.source_port || r.destination_port) ||
        r.protocol === "tcp" ||
        r.protocol === "udp") &&
      (r.direction !== "in" || !r.out_interface) &&
      (r.direction !== "out" || !r.in_interface),
    "地址族、协议或网卡与规则方向不匹配",
  );
const protection = z
  .array(
    z.object({
      source: address.refine(Boolean),
      port: z.number().int().min(1).max(65535),
    }),
  )
  .max(128);
const groupRules = z
  .array(firewallRule)
  .max(500)
  .refine(
    (rules) =>
      new Set(rules.map((r) => r.id)).size === rules.length &&
      new Set(rules.map((r) => r.priority)).size === rules.length,
    "规则 ID 或优先级重复",
  );
export const groupBody = z.object({
  name: z.string().trim().min(1).max(80),
  rules: groupRules,
  revision,
});
export const draftBody = z.object({
  revision,
  defaults,
  protection,
  bindings: z
    .array(z.object({ group_id: uuid, priority }))
    .max(50)
    .refine(
      (list) =>
        new Set(list.map((r) => r.group_id)).size === list.length &&
        new Set(list.map((r) => r.priority)).size === list.length,
      "规则组或优先级重复",
    ),
});
const chains = z.record(
  z.string().max(120),
  z.array(z.string().max(2048)).max(6000),
);
export const firewallObservation = z
  .object({
    status: z.enum(["active", "inactive", "unavailable"]),
    fingerprint: fingerprint.optional(),
    observed_at: revision,
    defaults: z.object({
      in: action.or(z.literal("")),
      out: action.or(z.literal("")),
      route: action.or(z.literal("")),
    }),
    rules: z.array(firewallRule).max(4000),
    protection,
    baseline: chains.optional(),
    planned_baseline: chains.optional(),
    live: chains.optional(),
    external: chains.optional(),
    blocked: z.array(z.string().max(2048)).max(200).optional(),
    ipv6: z.boolean(),
  })
  .refine((o) => JSON.stringify(o).length <= 900000, "防火墙快照过大");
export const firewallReceipt = z.object({
  id: uuid,
  status: z.enum(["applied", "failed", "rolled_back"]),
  error: z.string().max(2048).optional(),
  event: z.literal("drift").optional(),
  event_id: uuid.optional(),
  changed: z.array(z.string().max(80)).max(16).optional(),
});

function prefix(value: string) {
  const [host, mask] = value.split("/");
  const bytes = ipaddr.parse(host).toByteArray();
  return { bytes, bits: mask === undefined ? bytes.length * 8 : Number(mask) };
}
function matches(a: number[], b: number[], bits: number) {
  for (let i = 0; bits > 0; i++, bits -= 8) {
    const shift = Math.max(0, 8 - bits);
    if (a[i] >> shift !== b[i] >> shift) return false;
  }
  return true;
}
export function blockedSSH(
  target: import("../shared/firewall").FirewallTarget,
) {
  return target.protection.find((protection) => {
    const source = prefix(protection.source);
    const family = source.bytes.length === 4 ? "ipv4" : "ipv6";
    for (const rule of target.rules) {
      if (
        !rule.enabled ||
        rule.direction !== "in" ||
        !["any", "tcp"].includes(rule.protocol) ||
        (rule.family !== "any" && rule.family !== family)
      )
        continue;
      if (rule.destination_port) {
        const [lo, hi = lo] = rule.destination_port.split(":").map(Number);
        if (protection.port < lo || protection.port > hi) continue;
      }
      const range = rule.source ? prefix(rule.source) : null;
      if (
        range &&
        !matches(source.bytes, range.bytes, Math.min(source.bits, range.bits))
      )
        continue;
      if (rule.action !== "allow") return true;
      if (
        (!range || range.bits <= source.bits) &&
        !rule.destination &&
        !rule.source_port &&
        !rule.in_interface
      )
        return false;
    }
    return target.defaults.in !== "allow";
  });
}
