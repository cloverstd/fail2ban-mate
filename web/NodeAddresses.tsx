import type { Node } from "./types";

function addresses(node?: Node) {
  return {
    ipv4:
      node?.ipv4 ??
      (node?.ip?.includes(".") && !node.ip.includes(":") ? node.ip : null),
    ipv6: node?.ipv6 ?? (node?.ip?.includes(":") ? node.ip : null),
  };
}

export function nodeAddressLabel(node: Node): string {
  const { ipv4, ipv6 } = addresses(node);
  return (
    [ipv4 && `IPv4 ${ipv4}`, ipv6 && `IPv6 ${ipv6}`]
      .filter(Boolean)
      .join(" · ") || "未知节点"
  );
}

export function NodeAddresses({ node }: { node?: Node }) {
  const { ipv4, ipv6 } = addresses(node);
  return (
    <span className="node-addresses">
      <span>
        <span className="address-family">IPv4</span>
        <code>{ipv4 || "未探测到"}</code>
      </span>
      <span>
        <span className="address-family">IPv6</span>
        <code>{ipv6 || "未探测到"}</code>
      </span>
    </span>
  );
}
