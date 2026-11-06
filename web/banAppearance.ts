import type { PublicBanRow } from "./types";

export function banAppearance(ban: PublicBanRow, now: number) {
  const released = ban.unbanned_at != null;
  const age = Math.max(0, now - (ban.unbanned_at ?? ban.observed_at));
  const fadeSeconds = (released ? 7 : 1) * 86400;
  return {
    status: released ? "unbanned" : "banned",
    color: released ? "#facc15" : "#ef4444",
    // Older records remain visible after the fade window.
    opacity: 0.3 + 0.65 * Math.max(0, 1 - age / fadeSeconds),
  };
}
