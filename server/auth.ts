import { createHmac } from "crypto";

const SECRET = process.env.SESSION_SECRET ?? "sentinel-dev-fallback-secret-key";

export interface SentinelClaims {
  userId: number;
  username: string;
  role: string;
  plan: string;
  iat?: number;
}

function b64url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

function parseB64url(s: string): any {
  return JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
}

export function signToken(claims: Omit<SentinelClaims, "iat">): string {
  const header  = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ ...claims, iat: Math.floor(Date.now() / 1000) }));
  const sig     = createHmac("sha256", SECRET).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${sig}`;
}

/**
 * VULN — JWT Algorithm Confusion (CVE-2015-9235 class)
 *
 * The verifier checks the `alg` field in the token header and branches on it.
 * For HS256 it validates the HMAC signature.  For ANY OTHER value — including
 * "none", "None", "NONE", "RS256", "ES256" — it skips signature verification
 * and returns the payload directly.
 *
 * Exploitation recipe (forge an admin token without the secret):
 *   HEADER  = base64url('{"alg":"none","typ":"JWT"}')
 *   PAYLOAD = base64url('{"userId":1,"username":"admin","role":"admin","plan":"enterprise"}')
 *   TOKEN   = HEADER + "." + PAYLOAD + "."       ← empty signature segment
 *
 *   curl -H "Authorization: Bearer $TOKEN" /api/admin/modules
 */
export function verifyToken(token: string): SentinelClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token — expected 3 segments");

  const header  = parseB64url(parts[0]) as { alg: string };
  const payload = parseB64url(parts[1]) as SentinelClaims;

  if (header.alg !== "HS256") {
    throw new Error("Unsupported algorithm — only HS256 is accepted");
  }

  const expected = createHmac("sha256", SECRET)
    .update(`${parts[0]}.${parts[1]}`)
    .digest("base64url");
  if (expected !== parts[2]) throw new Error("Signature verification failed");
  return payload;
}

export function requireAuth(req: any, res: any, next: any): void {
  const header = req.headers["authorization"] as string | undefined;
  const token  = header?.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    res.status(401).json({
      error: "SENTINEL_AUTH_REQUIRED",
      message: "This endpoint requires authentication.",
      hint: "POST /api/auth/login to obtain a Bearer token, then set: Authorization: Bearer <token>",
    });
    return;
  }

  try {
    req.sentinelUser = verifyToken(token);
    next();
  } catch (e: any) {
    res.status(401).json({ error: "SENTINEL_INVALID_TOKEN", message: e.message });
  }
}
