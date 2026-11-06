import type { Geo, Mode } from "../shared/protocol";
export interface Node extends Geo {
  id: string;
  name?: string;
  ip: string | null;
  ipv4?: string | null;
  ipv6?: string | null;
  online: boolean;
  last_seen: number | null;
  observed_at: number | null;
  enabled?: number;
  has_token?: boolean;
  jails?: string[];
  mode?: Mode;
  actual_mode?: Mode;
  fallback_reason?: string;
  poll_interval?: number;
  config_revision?: number;
  applied_config_revision?: number;
  applied_policy_revision?: number;
  version?: string;
  error?: string;
}
export type PublicNode = Pick<
  Node,
  | keyof Geo
  | "id"
  | "ip"
  | "ipv4"
  | "ipv6"
  | "online"
  | "last_seen"
  | "observed_at"
>;
export interface PublicBanRow extends Geo {
  id?: string;
  node_id: string;
  ip: string;
  observed_at: number;
  unbanned_at?: number | null;
}
export interface BanRow extends PublicBanRow {
  jail: string;
}
export interface PublicData {
  nodes: PublicNode[];
  bans: PublicBanRow[];
  ban_history?: PublicBanRow[];
  generated_at: number;
}
export interface IntegrationRow {
  id: string;
  name: string;
  token_prefix: string;
  last_used_at: number | null;
  revoked_at: number | null;
}
export interface PolicyRow {
  id: string;
  ip: string;
  expires_at: number | null;
  created_at: number;
  actor: string;
  source?: "manual" | "integration";
  owner_id?: string | null;
  synced_at?: number | null;
}
export interface CommandRow {
  id: string;
  node_id: string;
  kind: string;
  jail: string;
  ip: string;
  status: string;
  error?: string;
  created_at: number;
  actor: string;
}
export interface AuditRow {
  id: string;
  actor: string;
  action: string;
  detail: string;
  created_at: number;
}
export interface Data {
  nodes: Node[];
  bans: BanRow[];
  ban_history?: BanRow[];
  generated_at: number;
  actor?: string;
  visitor_ip?: string | null;
  policy_revision?: number;
  policies?: PolicyRow[];
  integrations?: IntegrationRow[];
  commands?: CommandRow[];
  audit?: AuditRow[];
}
