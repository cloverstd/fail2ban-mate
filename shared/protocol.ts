export type Mode = "websocket" | "polling";
export interface Geo {
  country?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}
export interface Ban extends Geo {
  jail: string;
  ip: string;
  observed_at: number;
}
export interface BanEvent extends Ban {
  id: string;
  seq: number;
  kind: "ban" | "unban";
}
export interface Snapshot {
  seq: number;
  jails: { name: string; bans: Ban[] }[];
  unavailable_jails: string[];
}
export interface Command {
  id: string;
  kind: "ban" | "unban";
  jail: string;
  ip: string;
  expires_at: number;
}
export interface CommandResult {
  id: string;
  status: "succeeded" | "failed";
  error?: string;
}
export interface Policy {
  id: string;
  ip: string;
  expires_at: number | null;
}
export interface AgentSync {
  protocol: 1;
  type: "sync";
  sequence: number;
  version: string;
  actual_mode: Mode;
  fallback_reason?: string;
  applied_config_revision: number;
  applied_policy_revision: number;
  error?: string;
  events: BanEvent[];
  results: CommandResult[];
  snapshot?: Snapshot;
}
export interface ServerSync {
  protocol: 1;
  type: "sync";
  server_time: number;
  config: { revision: number; mode: Mode; poll_interval: number };
  policy_revision: number;
  policies: Policy[];
  commands: Command[];
  ack_event_ids: string[];
  ack_result_ids: string[];
  snapshot_required: boolean;
  ack_snapshot_seq?: number;
}
