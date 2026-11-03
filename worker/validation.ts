import { z } from "zod";
import ipaddr from "ipaddr.js";
export function canonicalIP(value: string): string {
  if (value.includes("/") || value.includes("%") || !ipaddr.isValid(value))
    throw new Error("请输入有效的 IPv4 或 IPv6 单个地址");
  // Reject abbreviated/octal IPv4 accepted by inet_aton-style parsers.
  if (
    !value.includes(":") &&
    (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value) ||
      value.split(".").some((p) => p.length > 1 && p.startsWith("0")))
  )
    throw new Error("IPv4 必须为标准点分十进制");
  return ipaddr.process(value).toString();
}
export const ip = z
  .string()
  .max(64)
  .transform((s, ctx) => {
    try {
      return canonicalIP(s);
    } catch (e) {
      ctx.addIssue({ code: "custom", message: (e as Error).message });
      return z.NEVER;
    }
  });
export const jail = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_][A-Za-z0-9_.:@-]*$/);
const geo = {
  country: z.string().max(128).nullish(),
  city: z.string().max(128).nullish(),
  latitude: z.number().min(-90).max(90).nullish(),
  longitude: z.number().min(-180).max(180).nullish(),
};
const ban = z.object({
  jail,
  ip,
  observed_at: z.number().int().nonnegative(),
  ...geo,
});
export const syncSchema = z
  .object({
    protocol: z.literal(1),
    type: z.literal("sync"),
    sequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    version: z.string().max(64),
    actual_mode: z.enum(["websocket", "polling"]),
    fallback_reason: z.string().max(512).optional(),
    applied_config_revision: z.number().int().nonnegative(),
    applied_policy_revision: z.number().int().nonnegative(),
    error: z.string().max(1024).optional(),
    events: z
      .array(
        ban.extend({
          id: z.string().uuid(),
          seq: z.number().int().positive(),
          kind: z.enum(["ban", "unban"]),
        }),
      )
      .max(100),
    results: z
      .array(
        z.object({
          id: z.string().uuid(),
          status: z.enum(["succeeded", "failed"]),
          error: z.string().max(1024).optional(),
        }),
      )
      .max(100),
    snapshot: z
      .object({
        seq: z.number().int().nonnegative(),
        jails: z
          .array(z.object({ name: jail, bans: z.array(ban).max(20000) }))
          .max(200),
        unavailable_jails: z.array(jail).max(200),
      })
      .optional(),
  })
  .superRefine((s, ctx) => {
    if (
      s.events.some((e) => e.seq > s.sequence) ||
      (s.snapshot && s.snapshot.seq > s.sequence)
    )
      ctx.addIssue({ code: "custom", message: "Invalid sequence" });
    if (s.snapshot?.jails.some((j) => j.bans.some((b) => b.jail !== j.name)))
      ctx.addIssue({ code: "custom", message: "Snapshot jail mismatch" });
    if (
      s.snapshot &&
      new Set([
        ...s.snapshot.jails.map((j) => j.name),
        ...s.snapshot.unavailable_jails,
      ]).size !==
        s.snapshot.jails.length + s.snapshot.unavailable_jails.length
    )
      ctx.addIssue({ code: "custom", message: "Duplicate snapshot jail" });
  });
export const createNodeSchema = z.object({
  name: z.string().trim().min(1).max(80),
});
export const updateNodeSchema = createNodeSchema
  .partial()
  .extend({
    enabled: z.boolean().optional(),
    mode: z.enum(["websocket", "polling"]).optional(),
    poll_interval: z.number().int().min(5).max(300).optional(),
  });
export const commandSchema = z.object({
  node_id: z.string().uuid(),
  kind: z.enum(["ban", "unban"]),
  jail,
  ip,
});
export const whitelistSchema = z.object({
  ip,
  duration: z.number().int().min(60).max(2592000).nullable(),
});
