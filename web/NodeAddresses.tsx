import type { Node } from "./types";

type AddressNode = Pick<Node, "ip" | "ipv4" | "ipv6">;

function addresses(node?: AddressNode) {
  return {
    ipv4:
      node?.ipv4 ??
      (node?.ip?.includes(".") && !node.ip.includes(":") ? node.ip : null),
    ipv6: node?.ipv6 ?? (node?.ip?.includes(":") ? node.ip : null),
  };
}

export function nodeAddressLabel(node: AddressNode): string {
  const { ipv4, ipv6 } = addresses(node);
  return [ipv4, ipv6].filter(Boolean).join(" · ") || "未知 IP";
}

export function NodeAddresses({ node }: { node?: AddressNode }) {
  const { ipv4, ipv6 } = addresses(node);
  return (
    <span className="node-addresses">
      {[ipv4, ipv6].filter(Boolean).map((ip) => (
        <span key={ip}>
          <code>{ip}</code>
        </span>
      ))}
      {!ipv4 && !ipv6 && (
        <span>
          <code>未知 IP</code>
        </span>
      )}
    </span>
  );
}
