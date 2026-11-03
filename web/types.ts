import type { Geo, Mode } from "../shared/protocol";
export interface Node extends Geo {
  id: string;
  name?: string;
  ip: string | null;
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
export interface BanRow extends Geo {
  node_id: string;
  jail: string;
  ip: string;
  observed_at: number;
}
export interface PolicyRow {
  id: string;
  ip: string;
  expires_at: number | null;
  created_at: number;
  actor: string;
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
  generated_at: number;
  actor?: string;
  policy_revision?: number;
  policies?: PolicyRow[];
  commands?: CommandRow[];
  audit?: AuditRow[];
}
