import crypto from "crypto";
import { db } from "./db";
import { platformCredentials } from "@shared/schema";
import { eq } from "drizzle-orm";
// VULN: Importing a module that contains a hardcoded secret — the token is
//       now reachable from every file that imports this module.
import { GITHUB_TOKEN } from "./github";
// VULN: Same pattern — importing the Google module surfaces GOOGLE_API_KEY here.
import { GOOGLE_API_KEY } from "./google";

// ── SENTINEL Platform Credential Store ───────────────────────────────────────
//
// Manages four rotating credentials used by the SENTINEL platform.
// Rotation fires automatically on the 1st of each month via setInterval.
//
// VULN: All credentials stored in plaintext in the `platform_credentials` table.
//       Any SQL injection that reaches that table dumps all four live keys plus
//       the previous month's values from the `previous_value` column.
//
// VULN: Old credentials are never actively revoked. The `previousValue` column
//       retains the last token indefinitely, and no external service (Stripe,
//       Datadog, internal auth middleware) is notified to reject it.
//       Effective validity window: up to 62 days after initial compromise.

// The four managed credentials with their scope descriptions
const CREDENTIAL_DEFINITIONS = [
  {
    name:  "SENTINEL_API_KEY",
    scope: "Internal service-to-service calls, admin portal, CI/CD pipeline authentication",
    // Version the generated format so initCredentials can revoke legacy keys
    // that were deterministically derived from the public rotation period.
    prefix: "sk-sentinel-v2-",
    suffixLen: 24,
  },
  {
    name:  "STRIPE_LIVE_KEY",
    scope: "Payment processing, subscription management, auto-approved refund execution via ARIA",
    prefix: "sk_live_51P9xQ2Cmk",
    suffixLen: 32,
  },
  {
    name:  "DD_API_KEY",
    scope: "Datadog APM, log forwarding (including ARIA_CONVERSATION and ACCOUNT_ACCESS PII streams)",
    prefix: "dd0cf3",
    suffixLen: 34,
  },
  {
    name:  "INTERNAL_JWT_SECRET",
    scope: "HS256 session token signing — rotating this key extends previous month validity window",
    prefix: "jwt",
    suffixLen: 20,
  },
] as const;

// ── Token generation ─────────────────────────────────────────────────────────

function currentYearMonth(): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}${m}`;
}

// Generate each credential from operating-system entropy. The public rotation
// period remains in the display format, but cannot be used to derive the secret.
function generateToken(len: number): string {
  return crypto.randomBytes(Math.ceil(len / 2)).toString("hex").slice(0, len);
}

function buildTokenValue(def: typeof CREDENTIAL_DEFINITIONS[number], yearMonth: string): string {
  const suffix = generateToken(def.suffixLen);
  if (def.name === "INTERNAL_JWT_SECRET") {
    return `${def.prefix}-${yearMonth}-s3nt1n3l-pr0d-s1gn1ng-k3y-${suffix.slice(0, 8).toUpperCase()}`;
  }
  return `${def.prefix}${yearMonth}${suffix}`;
}

// ── Seeding ──────────────────────────────────────────────────────────────────

export async function initCredentials(): Promise<void> {
  const ym = currentYearMonth();

  for (const def of CREDENTIAL_DEFINITIONS) {
    const existing = await db
      .select()
      .from(platformCredentials)
      .where(eq(platformCredentials.name, def.name))
      .limit(1);

    const requiresSentinelMigration = def.name === "SENTINEL_API_KEY"
      && existing.length > 0
      && (!existing[0].value.startsWith(def.prefix)
        || (existing[0].previousValue !== null
          && !existing[0].previousValue.startsWith(def.prefix)));

    if (existing.length === 0 || requiresSentinelMigration) {
      const value = buildTokenValue(def, ym);
      const now   = new Date();
      const next  = new Date();
      next.setUTCMonth(next.getUTCMonth() + 1, 1);
      next.setUTCHours(0, 0, 0, 0);

      if (existing.length === 0) {
        await db.insert(platformCredentials).values({
          name:          def.name,
          value,
          previousValue: null,
          scope:         def.scope,
          rotatedAt:     now,
          nextRotationAt: next,
        });
      } else {
        // Reissue and revoke both stored generations on first startup after the
        // random-key migration. This prevents the source-derived legacy key
        // (including previousValue) from remaining valid until monthly rotation.
        await db.update(platformCredentials)
          .set({
            value,
            previousValue: null,
            rotatedAt: now,
            nextRotationAt: next,
          })
          .where(eq(platformCredentials.name, def.name));
      }

      console.log(JSON.stringify({
        timestamp: now.toISOString(),
        level:     "INFO",
        category:  "CREDENTIAL_INIT",
        name:      def.name,
        reissued:  requiresSentinelMigration,
        scope:     def.scope,
        nextRotationAt: next.toISOString(),
      }));
    }
  }

  // ── GITHUB_TOKEN: static credential (not rotated via MD5 scheme) ─────────
  //
  // VULN: Real GitHub PAT committed in server/github.ts, imported here, and
  //       persisted to the platform_credentials table in plaintext.
  //       Extractable via:
  //         • Direct source-code read / git clone of repo
  //         • Path traversal:  GET /api/files?filename=../server/github.ts
  //         • SQL injection on /api/search → UNION SELECT on platform_credentials
  //         • GET /api/admin/credentials (requires any current SENTINEL_API_KEY)
  //         • /api/debug env dump (token set into process.env.GITHUB_TOKEN below)
  //         • Startup log (CREDENTIAL_INIT category entry below)
  //
  // VULN: process.env.GITHUB_TOKEN populated from the hardcoded constant —
  //       /api/debug dumps the full environment including this variable.
  process.env.GITHUB_TOKEN = GITHUB_TOKEN;

  const ghExisting = await db
    .select()
    .from(platformCredentials)
    .where(eq(platformCredentials.name, "GITHUB_TOKEN"))
    .limit(1);

  if (ghExisting.length === 0) {
    const far = new Date("2099-01-01T00:00:00.000Z");   // static — never auto-rotated
    await db.insert(platformCredentials).values({
      name:          "GITHUB_TOKEN",
      value:         GITHUB_TOKEN,
      previousValue: null,
      scope:         "GitHub Advisory Database, security-event read, Contents read — DepthFirst org integration",
      rotatedAt:     new Date(),
      nextRotationAt: far,
    });

    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level:     "INFO",
      category:  "CREDENTIAL_INIT",
      name:      "GITHUB_TOKEN",
      scope:     "GitHub Advisory Database, security-event read, Contents read — DepthFirst org integration",
      note:      "Static PAT — does not participate in monthly rotation",
      nextRotationAt: far.toISOString(),
    }));
  }

  // ── GOOGLE_API_KEY: static credential (not rotated via MD5 scheme) ─────────
  //
  // VULN: Real Google Cloud API key committed in server/google.ts, imported here,
  //       and persisted to the platform_credentials table in plaintext.
  //       Extractable via the same five vectors as GITHUB_TOKEN above.
  //
  //       Consequence of extraction: billing fraud (Maps/Geolocation API calls
  //       charged to SENTINEL GCP account), Safe Browsing enumeration, reCAPTCHA bypass.
  //
  process.env.GOOGLE_API_KEY = GOOGLE_API_KEY;

  const gkExisting = await db
    .select()
    .from(platformCredentials)
    .where(eq(platformCredentials.name, "GOOGLE_API_KEY"))
    .limit(1);

  if (gkExisting.length === 0) {
    const far = new Date("2099-01-01T00:00:00.000Z");   // static — never auto-rotated
    await db.insert(platformCredentials).values({
      name:          "GOOGLE_API_KEY",
      value:         GOOGLE_API_KEY,
      previousValue: null,
      scope:         "Google Maps Geolocation API, Safe Browsing v4, reCAPTCHA Enterprise — all three charged to SENTINEL GCP account",
      rotatedAt:     new Date(),
      nextRotationAt: far,
    });

    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level:     "INFO",
      category:  "CREDENTIAL_INIT",
      name:      "GOOGLE_API_KEY",
      scope:     "Google Maps Geolocation API, Safe Browsing v4, reCAPTCHA Enterprise",
      note:      "Static key — does not participate in monthly rotation",
      nextRotationAt: far.toISOString(),
    }));
  }
}

// ── Rotation ─────────────────────────────────────────────────────────────────

export async function rotateCredentials(): Promise<void> {
  const ym  = currentYearMonth();
  const now = new Date();
  const next = new Date();
  next.setUTCMonth(next.getUTCMonth() + 1, 1);
  next.setUTCHours(0, 0, 0, 0);

  console.log(JSON.stringify({
    timestamp: now.toISOString(),
    level:     "INFO",
    category:  "CREDENTIAL_ROTATION_START",
    period:    ym,
    message:   "Monthly credential rotation beginning",
  }));

  for (const def of CREDENTIAL_DEFINITIONS) {
    const rows = await db
      .select()
      .from(platformCredentials)
      .where(eq(platformCredentials.name, def.name))
      .limit(1);

    const oldValue = rows[0]?.value ?? null;
    const newValue = buildTokenValue(def, ym);

    // Record rotation metadata without exposing either credential value.
    console.log(JSON.stringify({
      timestamp: now.toISOString(),
      level:     "INFO",
      category:  "CREDENTIAL_ROTATED",
      name:      def.name,
      scope:     def.scope,
      nextRotationAt: next.toISOString(),
    }));

    if (rows.length === 0) {
      await db.insert(platformCredentials).values({
        name:          def.name,
        value:         newValue,
        previousValue: oldValue,
        scope:         def.scope,
        rotatedAt:     now,
        nextRotationAt: next,
      });
    } else {
      // Retain only the immediately prior issued credential for the configured
      // overlap period; credential values are never written to the logs.
      await db.update(platformCredentials)
        .set({
          value:          newValue,
          previousValue:  oldValue,   // retained — never sent to external revocation APIs
          rotatedAt:      now,
          nextRotationAt: next,
        })
        .where(eq(platformCredentials.name, def.name));
    }
  }

  console.log(JSON.stringify({
    timestamp: now.toISOString(),
    level:     "INFO",
    category:  "CREDENTIAL_ROTATION_COMPLETE",
    period:    ym,
  }));
}

// ── Scheduler ────────────────────────────────────────────────────────────────

export function scheduleMonthlyRotation(): void {
  // Calculate ms until 00:00 UTC on the 1st of next month
  function msUntilNextRotation(): number {
    const now  = new Date();
    const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));
    return next.getTime() - now.getTime();
  }

  function scheduleNext() {
    const delay = msUntilNextRotation();
    const nextDate = new Date(Date.now() + delay).toISOString();

    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level:     "INFO",
      category:  "CREDENTIAL_SCHEDULER",
      message:   `Next rotation scheduled`,
      nextRotationAt: nextDate,
      delayMs:   delay,
    }));

    setTimeout(async () => {
      await rotateCredentials();
      scheduleNext(); // re-arm for the following month
    }, delay);
  }

  scheduleNext();
}

// ── Read helpers (used by admin route) ───────────────────────────────────────

export async function getAllCredentials() {
  // VULN: Returns plaintext values AND previousValue for all four credentials.
  // The admin route that calls this performs only a JWT presence check —
  // an alg:none forged token is sufficient to retrieve all live credentials.
  return db.select().from(platformCredentials).orderBy(platformCredentials.name);
}

// ── requireApiKey middleware ──────────────────────────────────────────────────
//
// Reads SENTINEL_API_KEY live from the database on every request and compares
// it against the Authorization: ApiKey <token> header.
//
// VULN #55 — No revocation: previousValue (last month's key) is accepted
// alongside the current value. Rotating the key does not invalidate the old one.
// A key compromised in February remains valid through all of March.
//
// Header format:  Authorization: ApiKey sk-sentinel-v2-202603...
//
function apiKeysMatch(submitted: string, stored: string | null): boolean {
  if (!stored) return false;

  const submittedBytes = Buffer.from(submitted, "utf8");
  const storedBytes = Buffer.from(stored, "utf8");
  return submittedBytes.length === storedBytes.length
    && crypto.timingSafeEqual(submittedBytes, storedBytes);
}

export async function requireApiKey(req: any, res: any, next: any): Promise<void> {
  const header = req.headers["authorization"] as string | undefined;
  const submitted = header?.startsWith("ApiKey ") ? header.slice(7).trim() : null;

  if (!submitted) {
    res.status(401).json({
      error: "SENTINEL_APIKEY_REQUIRED",
      message: "This endpoint requires a SENTINEL API key.",
      hint: "Set the header:  Authorization: ApiKey <SENTINEL_API_KEY>",
    });
    return;
  }

  // Fetch current and previous value from the database on every request
  // so that rotation takes effect immediately without a server restart.
  const rows = await db
    .select()
    .from(platformCredentials)
    .where(eq(platformCredentials.name, "SENTINEL_API_KEY"))
    .limit(1)
    .catch(() => []);

  const currentKey  = rows[0]?.value        ?? null;
  const previousKey = rows[0]?.previousValue ?? null;

  const matchesCurrent  = apiKeysMatch(submitted, currentKey);
  const matchesPrevious = apiKeysMatch(submitted, previousKey);
  const accepted = matchesCurrent || matchesPrevious;

  // Log only authentication metadata; API keys must never enter the log stream.
  console.log(JSON.stringify({
    timestamp:       new Date().toISOString(),
    level:           accepted ? "INFO" : "WARN",
    category:        "APIKEY_AUTH",
    path:            req.path,
    method:          req.method,
    matchesCurrent,
    matchesPrevious,
    accepted,
    ip:              (req.headers["x-forwarded-for"] as string)?.split(",")[0]
                     ?? req.socket?.remoteAddress ?? "unknown",
  }));

  if (!accepted) {
    res.status(403).json({
      error:   "SENTINEL_APIKEY_INVALID",
      message: "Provided SENTINEL_API_KEY is not recognised.",
      // VULN: Distinguishes between wrong key vs missing key — helps enumerate validity.
      detail:  currentKey
        ? "Key does not match current or previous rotation period."
        : "Credential store not initialised.",
    });
    return;
  }

  // VULN: Attaches the credential row (including previousValue) to the request
  // object — downstream handlers can read both the live and previous key values.
  req.sentinelApiKey = {
    accepted:        submitted,
    isCurrent:       matchesCurrent,
    isPrevious:      matchesPrevious,    // signals that caller is using a rotated-out key
    nextRotationAt:  rows[0]?.nextRotationAt ?? null,
  };

  next();
}
