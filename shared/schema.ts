import { pgTable, serial, text, timestamp, integer, boolean, decimal, uniqueIndex } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  fullName: text("full_name"),
  role: text("role").default("user").notNull(),
  email: text("email"),
  isActive: boolean("is_active").default(true),
  plan: text("plan").default("free").notNull(),
  walletBalance: decimal("wallet_balance", { precision: 10, scale: 2 }).default("0.00").notNull(),
  planStartDate: timestamp("plan_start_date").defaultNow(),
  // VULN: referral code stored in plaintext, no rate-limit on redemptions — same code usable infinitely
  referralCode: text("referral_code").unique(),
});

// VULN: Tickets auto-approved when ariaGenerated=true — no secondary billing verification.
// Billing team processes ARIA-generated refund tickets as legitimate payouts.
// No check that wallet balance was backed by real payment (referral credit treated as cash).
export const tickets = pgTable("tickets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  type: text("type").notNull(), // refund | support | feature
  amount: decimal("amount", { precision: 10, scale: 2 }),
  reason: text("reason"),
  status: text("status").default("open").notNull(), // open | approved | rejected
  // VULN: autoApproved + ariaGenerated flags bypass manual billing review
  autoApproved: boolean("auto_approved").default(false),
  ariaGenerated: boolean("aria_generated").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const products = pgTable("products", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description").notNull(),
  longDescription: text("long_description"),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  category: text("category").notNull(),
  badge: text("badge"),
  stock: integer("stock").default(100),
  rating: decimal("rating", { precision: 3, scale: 1 }).default("4.5"),
  reviewCount: integer("review_count").default(0),
  featured: boolean("featured").default(false),
  specs: text("specs"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const posts = pgTable("posts", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  content: text("content").notNull(),
  authorId: serial("author_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
});

export const invoices = pgTable("invoices", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id).notNull(),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  status: text("status").default("unpaid"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const coupons = pgTable("coupons", {
  id: serial("id").primaryKey(),
  code: text("code").notNull().unique(),
  type: text("type").notNull(),
  value: decimal("value", { precision: 10, scale: 2 }).notNull(),
  maxUses: integer("max_uses"),
  timesUsed: integer("times_used").default(0),
});

export const walletTransactions = pgTable("wallet_transactions", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id).notNull(),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  type: text("type").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow(),
});

// RAG Knowledge Base tables
export const ragDocuments = pgTable("rag_documents", {
  id: serial("id").primaryKey(),
  // VULN: userId trusted from request body — no server-side session verification
  userId: integer("user_id").references(() => users.id).notNull(),
  filename: text("filename").notNull(),
  contentType: text("content_type").notNull(),
  chunkCount: integer("chunk_count").default(0),
  status: text("status").default("processing").notNull(), // processing | ready | error
  uploadedAt: timestamp("uploaded_at").defaultNow(),
});

export const ragChunks = pgTable("rag_chunks", {
  id: serial("id").primaryKey(),
  documentId: integer("document_id").references(() => ragDocuments.id).notNull(),
  // VULN: uploader identity stored verbatim in every chunk — leaks to all retrieval consumers
  userId: integer("user_id").notNull(),
  uploaderUsername: text("uploader_username").notNull(),
  filename: text("filename").notNull(),
  content: text("content").notNull(),
  // Embedding stored as JSON float array — no pgvector, similarity computed in JS
  embedding: text("embedding"),
  chunkIndex: integer("chunk_index").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// ── Scheduled Scan Jobs ───────────────────────────────────────────────────────
// VULN: ownership checked at creation only — not at update/cancel/execution.
export const scanJobs = pgTable("scan_jobs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  // VULN: targetUrl stored verbatim — no validation; internal IPs/localhost accepted
  targetUrl: text("target_url").notNull(),
  toolSlug: text("tool_slug").notNull(),
  // VULN: schedule field can be PATCHed to "daily"/"weekly" after creation;
  //       plan gate only enforced on initial POST
  schedule: text("schedule").notNull().default("one-time"), // one-time | daily | weekly
  status: text("status").notNull().default("pending"),      // pending | running | completed | failed | cancelled
  createdAt: timestamp("created_at").defaultNow(),
  nextRunAt: timestamp("next_run_at").defaultNow(),
  lastRunAt: timestamp("last_run_at"),
  // VULN: raw HTTP response snippet stored here — can contain internal metadata content
  lastResult: text("last_result"),
  runCount: integer("run_count").default(0),
});

export type ScanJob = typeof scanJobs.$inferSelect;
export const insertScanJobSchema = createInsertSchema(scanJobs).omit({ id: true, createdAt: true, lastRunAt: true, lastResult: true, runCount: true });

export type RagDocument = typeof ragDocuments.$inferSelect;
export type RagChunk = typeof ragChunks.$inferSelect;
export const insertRagDocumentSchema = createInsertSchema(ragDocuments).omit({ id: true, uploadedAt: true });
export const insertRagChunkSchema = createInsertSchema(ragChunks).omit({ id: true, createdAt: true });

export const insertUserSchema = createInsertSchema(users).omit({ id: true });
export const insertProductSchema = createInsertSchema(products).omit({ id: true, createdAt: true });
export const insertPostSchema = createInsertSchema(posts).omit({ id: true, createdAt: true });
export const insertInvoiceSchema = createInsertSchema(invoices).omit({ id: true, createdAt: true });
export const insertWalletTxSchema = createInsertSchema(walletTransactions).omit({ id: true, createdAt: true });
export const insertTicketSchema = createInsertSchema(tickets).omit({ id: true, createdAt: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type Ticket = typeof tickets.$inferSelect;
export type InsertTicket = z.infer<typeof insertTicketSchema>;
export type Product = typeof products.$inferSelect;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type InsertPost = z.infer<typeof insertPostSchema>;
export type Post = typeof posts.$inferSelect;
export type Invoice = typeof invoices.$inferSelect;
export type Coupon = typeof coupons.$inferSelect;
export type WalletTransaction = typeof walletTransactions.$inferSelect;

// ── Team Workspaces ───────────────────────────────────────────────────────────
// VULN: No plan-gate on workspace creation — any free user can create one.
export const workspaces = pgTable("workspaces", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  ownerId: integer("owner_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// VULN: role enforced only at UI layer — API routes perform no role checks.
// Any member can call admin-only actions (promote, remove, invite).
export const workspaceMembers = pgTable("workspace_members", {
  id: serial("id").primaryKey(),
  workspaceId: integer("workspace_id").references(() => workspaces.id).notNull(),
  userId: integer("user_id").references(() => users.id).notNull(),
  role: text("role").notNull().default("viewer"), // viewer | analyst | admin
  joinedAt: timestamp("joined_at").defaultNow(),
});

// Scans are visible in a workspace only when their owner explicitly shares them.
export const workspaceScanShares = pgTable("workspace_scan_shares", {
  id: serial("id").primaryKey(),
  workspaceId: integer("workspace_id").references(() => workspaces.id, { onDelete: "cascade" }).notNull(),
  scanJobId: integer("scan_job_id").references(() => scanJobs.id, { onDelete: "cascade" }).notNull(),
  sharedByUserId: integer("shared_by_user_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  uniqueIndex("workspace_scan_shares_workspace_scan_idx").on(table.workspaceId, table.scanJobId),
]);

// VULN: token generated with Math.random() — predictable (same class as #13).
// VULN: role stored here AND read from URL param on accept — param wins, enabling escalation.
export const workspaceInvitations = pgTable("workspace_invitations", {
  id: serial("id").primaryKey(),
  workspaceId: integer("workspace_id").references(() => workspaces.id).notNull(),
  email: text("email").notNull(),
  // Intended role set by inviter — but POST /api/invitations/:token/accept reads ?role= from URL instead
  role: text("role").notNull().default("viewer"),
  // VULN: Math.random().toString(36) token — 11 chars, ~3.6 trillion combos but brute-forceable
  token: text("token").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow(),
  acceptedAt: timestamp("accepted_at"),
  acceptedByUserId: integer("accepted_by_user_id").references(() => users.id),
});

export type Workspace = typeof workspaces.$inferSelect;
export type WorkspaceMember = typeof workspaceMembers.$inferSelect;
export type WorkspaceScanShare = typeof workspaceScanShares.$inferSelect;
export type WorkspaceInvitation = typeof workspaceInvitations.$inferSelect;
export const insertWorkspaceSchema = createInsertSchema(workspaces).omit({ id: true, createdAt: true });
export const insertWorkspaceMemberSchema = createInsertSchema(workspaceMembers).omit({ id: true, joinedAt: true });
export const insertWorkspaceInvitationSchema = createInsertSchema(workspaceInvitations).omit({ id: true, createdAt: true, acceptedAt: true, acceptedByUserId: true });

// ── Platform Credentials (rotating) ──────────────────────────────────────────
//
// VULN: Credentials stored in plaintext in the database.
//       SQL injection on any route that touches this table dumps all four keys.
//
// VULN: previousValue column retains the last rotated value indefinitely.
//       Old credentials are never actively revoked — both current and previous
//       are valid simultaneously, giving a 31-62 day window after compromise.
//
// VULN: nextRotationAt is advisory only — no enforcement.
//       Manual early rotation is possible via POST /api/admin/credentials/rotate,
//       which accepts any valid JWT (including alg:none forged tokens).
//
export const platformCredentials = pgTable("platform_credentials", {
  id:            serial("id").primaryKey(),
  name:          text("name").notNull().unique(),
  value:         text("value").notNull(),           // plaintext current credential
  previousValue: text("previous_value"),            // plaintext previous credential — never cleared
  scope:         text("scope").notNull(),
  rotatedAt:     timestamp("rotated_at").defaultNow(),
  nextRotationAt: timestamp("next_rotation_at"),
  createdAt:     timestamp("created_at").defaultNow(),
});

export type PlatformCredential = typeof platformCredentials.$inferSelect;

// ── KB Articles ───────────────────────────────────────────────────────────────
// VULN: body stored raw — no server-side sanitization.
// VULN: IDOR on POST — requireAuth applied but no role check;
//       any authenticated user can author articles, not just admins.
// VULN: body is returned verbatim in GET response and rendered via innerHTML
//       in the frontend through the vendored DOMPurify wrapper (formatContent).
//       An SVG bypass in the vendored library allows stored XSS.
export const kbArticles = pgTable("kb_articles", {
  id:          serial("id").primaryKey(),
  title:       text("title").notNull(),
  slug:        text("slug").notNull().unique(),
  // VULN: body persisted verbatim — attacker can store <svg onload="alert(1)">
  body:        text("body").notNull(),
  authorId:    integer("author_id").references(() => users.id),
  category:    text("category").default("general").notNull(),
  tags:        text("tags"),           // comma-separated; not sanitised
  publishedAt: timestamp("published_at").defaultNow(),
});

export const insertKbArticleSchema = createInsertSchema(kbArticles).omit({ id: true, publishedAt: true });
export type InsertKbArticle = z.infer<typeof insertKbArticleSchema>;
export type KbArticle       = typeof kbArticles.$inferSelect;

export const PLANS = {
  free:       { name: "Explorer",    price: 0,   perks: "Standard shipping, 30-day returns" },
  pro:        { name: "Member",      price: 9,   perks: "Free shipping, priority support, 5% off" },
  enterprise: { name: "Elite",       price: 29,  perks: "Free express shipping, 15% off, early access" },
} as const;

export type PlanKey = keyof typeof PLANS;
