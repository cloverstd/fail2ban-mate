import { canonicalIP } from "./validation";

export function splitAddress(value: unknown): {
  ipv4: string | null;
  ipv6: string | null;
} {
  const result: {
    ipv4: string | null;
    ipv6: string | null;
  } = { ipv4: null, ipv6: null };
  if (typeof value !== "string") return result;
  try {
    const address = canonicalIP(value);
    result[address.includes(":") ? "ipv6" : "ipv4"] = address;
  } catch {
    // Missing or invalid edge metadata must never replace a known address.
  }
  return result;
}

export function connectingAddress(request: Request): string | null {
  const address = splitAddress(request.headers.get("CF-Connecting-IP"));
  // Pseudo IPv4 overwrites CF-Connecting-IP with a Class E hash. It is not
  // the node's IPv4 address; Cloudflare preserves the real IPv6 separately.
  if (address.ipv4 && Number(address.ipv4.split(".")[0]) >= 240) {
    return splitAddress(request.headers.get("CF-Connecting-IPv6")).ipv6;
  }
  return address.ipv4 ?? address.ipv6;
}

export function nodeAddresses(node: {
  ip: string | null;
  ipv4: string | null;
  ipv6: string | null;
}) {
  const legacy = splitAddress(node.ip);
  return {
    ipv4: splitAddress(node.ipv4).ipv4 ?? legacy.ipv4,
    ipv6: splitAddress(node.ipv6).ipv6 ?? legacy.ipv6,
  };
}
