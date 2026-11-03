export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  NODES: DurableObjectNamespace;
  DASHBOARD: DurableObjectNamespace;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ADMIN_EMAILS: string;
  RETENTION_DAYS: string;
}
export interface NodeRow {
  id: string;
  name: string;
  enabled: number;
  token_hash: string | null;
  mode: "websocket" | "polling";
  poll_interval: number;
  config_revision: number;
  applied_config_revision: number;
  applied_policy_revision: number;
  last_seq: number;
  last_seen: number | null;
  observed_at: number | null;
  actual_mode: string | null;
  fallback_reason: string | null;
  version: string | null;
  error: string | null;
  jails_json: string;
  ip: string | null;
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  created_at: number;
}
