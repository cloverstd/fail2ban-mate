import { describe, expect, it } from "vitest";
import { banAppearance } from "../web/banAppearance";

const now = 2000000;
const ban = { node_id: "node", ip: "203.0.113.7", observed_at: now };

describe("ban map colors", () => {
  it("keeps active bans red, with recent bans stronger than older bans", () => {
    const recent = banAppearance(ban, now);
    const old = banAppearance({ ...ban, observed_at: now - 86400 }, now);
    expect(recent.color).toBe("#ef4444");
    expect(old.color).toBe(recent.color);
    expect(recent.opacity).toBeGreaterThan(old.opacity);
    expect(old.opacity).toBeGreaterThan(0);
  });

  it("fades yellow from release time even for long-running bans", () => {
    const released = { ...ban, observed_at: 1, unbanned_at: now };
    const recent = banAppearance(released, now);
    const old = banAppearance(
      { ...released, unbanned_at: now - 7 * 86400 },
      now,
    );
    expect(recent.color).toBe("#facc15");
    expect(recent.opacity).toBeGreaterThan(old.opacity);
    expect(old.opacity).toBeGreaterThan(0);
    expect(banAppearance(released, now + 365 * 86400).opacity).toBe(
      old.opacity,
    );
    expect(
      banAppearance({ ...released, unbanned_at: now + 100 }, now).opacity,
    ).toBe(recent.opacity);
  });
});
