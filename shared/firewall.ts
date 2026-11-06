export interface FirewallRule {
  id: string;
  priority: number;
  enabled: boolean;
  direction: "in" | "out" | "route";
  action: "allow" | "deny" | "reject";
  family: "any" | "ipv4" | "ipv6";
  protocol: "any" | "tcp" | "udp" | "icmp";
  source: string;
  destination: string;
  source_port: string;
  destination_port: string;
  in_interface: string;
  out_interface: string;
  comment: string;
}

export type FirewallDefaults = Record<
  FirewallRule["direction"],
  FirewallRule["action"]
>;
export interface SSHProtection {
  source: string;
  port: number;
}
export interface FirewallGroup {
  id: string;
  name: string;
  revision: number;
  rules: FirewallRule[];
}
export interface FirewallDraft {
  bindings: { group_id: string; priority: number }[];
  defaults: FirewallDefaults;
  protection: SSHProtection[];
}
export interface FirewallObservation {
  status: "active" | "inactive" | "unavailable";
  fingerprint?: string;
  observed_at: number;
  defaults: Record<FirewallRule["direction"], FirewallRule["action"] | "">;
  rules: FirewallRule[];
  protection: SSHProtection[];
  baseline?: Record<string, string[]>;
  planned_baseline?: Record<string, string[]>;
  live?: Record<string, string[]>;
  external?: Record<string, string[]>;
  blocked?: string[];
  ipv6: boolean;
}
export interface FirewallTarget {
  id: string;
  node_id: string;
  fingerprint: string;
  defaults: FirewallDefaults;
  protection: SSHProtection[];
  rules: FirewallRule[];
}
export interface FirewallReceipt {
  id: string;
  status: "applied" | "failed" | "rolled_back";
  error?: string;
  event?: "drift";
  event_id?: string;
  changed?: string[];
}
export interface FirewallRelease {
  id: string;
  target: FirewallTarget;
  status:
    | "pending"
    | "applying"
    | "applied"
    | "failed"
    | "rolled_back"
    | "superseded";
  error: string | null;
  drift: FirewallReceipt | null;
  actor: string;
  created_at: number;
  updated_at: number;
}
export interface FirewallNodeDetail {
  observation: FirewallObservation | null;
  draft: (FirewallDraft & { revision: number }) | null;
  history: FirewallRelease[];
}
export interface FirewallPreview {
  version: string;
  node_id: string;
  before: FirewallRule[];
  before_defaults?: FirewallDefaults;
  after: FirewallTarget;
  baseline_changes?: Record<string, { before: string[]; after: string[] }>;
  affected: { id: string; name: string }[];
}
