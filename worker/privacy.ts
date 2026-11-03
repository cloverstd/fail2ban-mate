import ipaddr from "ipaddr.js";
export function maskIP(value: string | null, node = false): string {
  if (!value) return "未知 IP";
  try {
    const a = ipaddr.process(value);
    if (a.kind() === "ipv4") {
      const p = a.toString().split(".");
      return node ? `${p[0]}.${p[1]}.x.x` : `${p[0]}.${p[1]}.${p[2]}.x`;
    }
    const parts = (a as ipaddr.IPv6).parts.map((p) => p.toString(16));
    const n = node ? 2 : 3;
    return [...parts.slice(0, n), ...Array(8 - n).fill("x")].join(":");
  } catch {
    return "未知 IP";
  }
}
