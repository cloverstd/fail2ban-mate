import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Env, NodeRow } from "./env";
const sets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
export async function hash(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(bytes), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
export function secret(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
export async function admin(
  request: Request,
  env: Env,
): Promise<{ email: string; exp: number } | null> {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD || !env.ADMIN_EMAILS)
    return null;
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return null;
  try {
    const issuer = new URL(env.ACCESS_TEAM_DOMAIN).origin;
    if (
      !issuer.startsWith("https://") ||
      !new URL(issuer).hostname.endsWith(".cloudflareaccess.com")
    )
      return null;
    if (!sets.has(issuer))
      sets.set(
        issuer,
        createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)),
      );
    const { payload } = await jwtVerify(token, sets.get(issuer)!, {
      issuer,
      audience: env.ACCESS_AUD,
      algorithms: ["RS256"],
    });
    const email =
      typeof payload.email === "string" ? payload.email.toLowerCase() : "";
    if (
      !payload.exp ||
      !env.ADMIN_EMAILS.split(",")
        .map((s) => s.trim().toLowerCase())
        .includes(email)
    )
      return null;
    return { email, exp: payload.exp };
  } catch {
    return null;
  }
}
export async function agent(
  request: Request,
  env: Env,
): Promise<NodeRow | null> {
  const bearer = request.headers.get("Authorization");
  if (!bearer?.startsWith("Bearer ")) return null;
  const token = bearer.slice(7);
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  return env.DB.prepare("SELECT * FROM nodes WHERE token_hash=? AND enabled=1")
    .bind(await hash(token))
    .first<NodeRow>();
}
export function sameOrigin(request: Request): boolean {
  return request.headers.get("Origin") === new URL(request.url).origin;
}
