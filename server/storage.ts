import { db, pool } from "./db";
import {
  users, posts, invoices, walletTransactions, products, ragDocuments, ragChunks, scanJobs, tickets,
  workspaces, workspaceMembers, workspaceInvitations, kbArticles, coupons,
  type User, type InsertUser, type Post, type InsertPost,
  type Invoice, type WalletTransaction, type Product, type InsertProduct,
  type RagDocument, type RagChunk, type ScanJob, type PlanKey, type Ticket,
  type Workspace, type WorkspaceMember, type WorkspaceInvitation,
  type KbArticle, type InsertKbArticle, type Coupon,
} from "@shared/schema";
import { eq, sql, ilike, lte, and, inArray, desc } from "drizzle-orm";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  createPost(post: InsertPost): Promise<Post>;
  searchUsersVulnerable(query: string): Promise<any[]>;
  getInvoice(id: number): Promise<Invoice | undefined>;
  createInvoice(data: { userId: number; amount: string; status?: string }): Promise<Invoice>;
  deactivateUser(id: number): Promise<User>;
  getUserWallet(userId: number): Promise<{ balance: number; plan: string; planStartDate: Date | null }>;
  topupWallet(userId: number, amount: number): Promise<User>;
  deductWallet(userId: number, amount: number): Promise<User>;
  creditWallet(userId: number, amount: number, description: string): Promise<User>;
  setPlan(userId: number, plan: PlanKey): Promise<User>;
  setFullName(userId: number, fullName: string): Promise<User>;
  logWalletTransaction(userId: number, amount: number, type: string, description: string): Promise<WalletTransaction>;
  // Products
  getProducts(category?: string): Promise<Product[]>;
  getFeaturedProducts(): Promise<Product[]>;
  getProduct(id: number): Promise<Product | undefined>;
  getProductBySlug(slug: string): Promise<Product | undefined>;
  createProduct(product: InsertProduct): Promise<Product>;
  searchProducts(query: string): Promise<Product[]>;
  // RAG Knowledge Base
  createRagDocument(data: { userId: number; filename: string; contentType: string }): Promise<RagDocument>;
  updateRagDocumentStatus(id: number, status: string, chunkCount?: number): Promise<RagDocument>;
  getRagDocumentsByUser(userId: number): Promise<RagDocument[]>;
  getRagDocument(id: number): Promise<RagDocument | undefined>;
  deleteRagDocument(id: number): Promise<void>;
  // VULN: no tenant filter param — all implementations fetch ALL chunks across all users
  createRagChunk(data: { documentId: number; userId: number; uploaderUsername: string; filename: string; content: string; embedding: string; chunkIndex: number }): Promise<RagChunk>;
  getAllRagChunks(): Promise<RagChunk[]>;
  deleteRagChunksByDocument(documentId: number): Promise<void>;
  // Scan Jobs
  createScanJob(data: { userId: number; targetUrl: string; toolSlug: string; schedule: string; nextRunAt: Date }): Promise<ScanJob>;
  getScanJob(id: number): Promise<ScanJob | undefined>;
  // VULN: getUserScanJobs has no ownership enforcement — caller supplies userId freely
  getScanJobsByUser(userId: number): Promise<ScanJob[]>;
  // VULN: updateScanJob performs no ownership check — IDOR pivot point
  updateScanJob(id: number, updates: Partial<Pick<ScanJob, "schedule" | "status" | "nextRunAt" | "lastRunAt" | "lastResult" | "runCount">>): Promise<ScanJob>;
  // VULN: deleteScanJob performs no ownership check — any authenticated caller can cancel any job
  deleteScanJob(id: number): Promise<void>;
  getDueScanJobs(): Promise<ScanJob[]>;
  // Referral
  getUserByReferralCode(code: string): Promise<User | undefined>;
  setReferralCode(userId: number, code: string): Promise<User>;
  // Tickets
  createTicket(data: { userId: number; type: string; amount?: number; reason?: string; autoApproved?: boolean; ariaGenerated?: boolean }): Promise<Ticket>;
  getTicketsByUser(userId: number): Promise<Ticket[]>;
  getTicket(id: number): Promise<Ticket | undefined>;
  updateTicketStatus(id: number, status: string): Promise<Ticket>;
  // Workspaces — VULN: all methods perform no ownership / role verification
  createWorkspace(data: { name: string; ownerId: number }): Promise<Workspace>;
  getWorkspace(id: number): Promise<Workspace | undefined>;
  getWorkspacesByUser(userId: number): Promise<Workspace[]>;
  addWorkspaceMember(data: { workspaceId: number; userId: number; role: string }): Promise<WorkspaceMember>;
  getWorkspaceMembers(workspaceId: number): Promise<(WorkspaceMember & { username: string; email: string | null })[]>;
  updateMemberRole(memberId: number, role: string): Promise<WorkspaceMember>;
  removeWorkspaceMember(workspaceId: number, memberId: number): Promise<void>;
  createInvitation(data: { workspaceId: number; email: string; role: string; token: string }): Promise<WorkspaceInvitation>;
  getInvitationByToken(token: string): Promise<WorkspaceInvitation | undefined>;
  acceptInvitation(token: string, userId: number, role: string): Promise<WorkspaceInvitation>;
  getWorkspaceInvitations(workspaceId: number): Promise<WorkspaceInvitation[]>;
  // KB Articles — VULN: body never sanitized server-side; stored and returned verbatim
  getKbArticles(): Promise<KbArticle[]>;
  getKbArticle(id: number): Promise<KbArticle | undefined>;
  getKbArticleBySlug(slug: string): Promise<KbArticle | undefined>;
  createKbArticle(data: InsertKbArticle): Promise<KbArticle>;
  // Coupons
  getCouponByCode(code: string): Promise<Coupon | undefined>;
  createCoupon(data: { code: string; type: string; value: string; maxUses?: number | null }): Promise<Coupon>;
  // VULN: increments the GLOBAL counter only — no per-user tracking.
  //       The calling route never records which userId redeemed this code,
  //       so the same user can redeem the same code as many times as they
  //       want until the global maxUses ceiling is reached.
  incrementCouponUses(id: number): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  // VULN: No pagination — returns all users in one query.
  // Called by /api/service/users (API-key-only route) — full PII dump in one request.
  async getAllUsers(): Promise<User[]> {
    return db.select().from(users);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async createPost(insertPost: InsertPost): Promise<Post> {
    const [post] = await db.insert(posts).values(insertPost).returning();
    return post;
  }

  async getInvoice(id: number): Promise<Invoice | undefined> {
    const [invoice] = await db.select().from(invoices).where(eq(invoices.id, id));
    return invoice;
  }

  async createInvoice(data: { userId: number; amount: string; status?: string }): Promise<Invoice> {
    const [invoice] = await db.insert(invoices).values({ userId: data.userId, amount: data.amount, status: data.status ?? "unpaid" }).returning();
    return invoice;
  }

  async deactivateUser(id: number): Promise<User> {
    const [user] = await db.update(users).set({ isActive: false }).where(eq(users.id, id)).returning();
    return user;
  }

  async getUserWallet(userId: number): Promise<{ balance: number; plan: string; planStartDate: Date | null }> {
    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    return { balance: parseFloat(user.walletBalance), plan: user.plan, planStartDate: user.planStartDate };
  }

  async topupWallet(userId: number, amount: number): Promise<User> {
    const [user] = await db.update(users).set({ walletBalance: sql`wallet_balance + ${amount}` }).where(eq(users.id, userId)).returning();
    return user;
  }

  async deductWallet(userId: number, amount: number): Promise<User> {
    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    const newBalance = parseFloat(user.walletBalance) - amount;
    const [updated] = await db.update(users).set({ walletBalance: newBalance.toFixed(2) }).where(eq(users.id, userId)).returning();
    return updated;
  }

  async creditWallet(userId: number, amount: number, description: string): Promise<User> {
    const [user] = await db.update(users).set({ walletBalance: sql`wallet_balance + ${amount}` }).where(eq(users.id, userId)).returning();
    await this.logWalletTransaction(userId, amount, "credit", description);
    return user;
  }

  async setPlan(userId: number, plan: PlanKey): Promise<User> {
    const [user] = await db.update(users).set({ plan, planStartDate: new Date() }).where(eq(users.id, userId)).returning();
    return user;
  }

  async setFullName(userId: number, fullName: string): Promise<User> {
    const [user] = await db.update(users).set({ fullName }).where(eq(users.id, userId)).returning();
    return user;
  }

  async logWalletTransaction(userId: number, amount: number, type: string, description: string): Promise<WalletTransaction> {
    const [tx] = await db.insert(walletTransactions).values({ userId, amount: amount.toFixed(2), type, description }).returning();
    return tx;
  }

  async getProducts(category?: string): Promise<Product[]> {
    if (category && category !== "all") {
      return await db.select().from(products).where(eq(products.category, category));
    }
    return await db.select().from(products);
  }

  async getFeaturedProducts(): Promise<Product[]> {
    return await db.select().from(products).where(eq(products.featured, true));
  }

  async getProduct(id: number): Promise<Product | undefined> {
    const [product] = await db.select().from(products).where(eq(products.id, id));
    return product;
  }

  async getProductBySlug(slug: string): Promise<Product | undefined> {
    const [product] = await db.select().from(products).where(eq(products.slug, slug));
    return product;
  }

  async createProduct(product: InsertProduct): Promise<Product> {
    const [p] = await db.insert(products).values(product).returning();
    return p;
  }

  async searchProducts(query: string): Promise<Product[]> {
    return await db.select().from(products).where(ilike(products.name, `%${query}%`));
  }

  // Fixed: Using parameterized query with Drizzle ORM
  async searchUsersVulnerable(query: string): Promise<any[]> {
    return await db.select({ id: users.id, username: users.username, role: users.role })
      .from(users)
      .where(ilike(users.username, `%${query}%`));
  }

  // ── RAG Knowledge Base ────────────────────────────────────────────────────

  async createRagDocument(data: { userId: number; filename: string; contentType: string }): Promise<RagDocument> {
    const [doc] = await db.insert(ragDocuments).values({
      userId: data.userId,
      filename: data.filename,
      contentType: data.contentType,
      status: "processing",
    }).returning();
    return doc;
  }

  async updateRagDocumentStatus(id: number, status: string, chunkCount?: number): Promise<RagDocument> {
    const updates: any = { status };
    if (chunkCount !== undefined) updates.chunkCount = chunkCount;
    const [doc] = await db.update(ragDocuments).set(updates).where(eq(ragDocuments.id, id)).returning();
    return doc;
  }

  async getRagDocumentsByUser(userId: number): Promise<RagDocument[]> {
    return await db.select().from(ragDocuments).where(eq(ragDocuments.userId, userId));
  }

  async getRagDocument(id: number): Promise<RagDocument | undefined> {
    const [doc] = await db.select().from(ragDocuments).where(eq(ragDocuments.id, id));
    return doc;
  }

  async deleteRagDocument(id: number): Promise<void> {
    await db.delete(ragDocuments).where(eq(ragDocuments.id, id));
  }

  async createRagChunk(data: {
    documentId: number; userId: number; uploaderUsername: string;
    filename: string; content: string; embedding: string; chunkIndex: number;
  }): Promise<RagChunk> {
    const [chunk] = await db.insert(ragChunks).values(data).returning();
    return chunk;
  }

  // VULN: fetches ALL chunks — no WHERE userId = ? — cross-tenant data exposure
  async getAllRagChunks(): Promise<RagChunk[]> {
    return await db.select().from(ragChunks);
  }

  async deleteRagChunksByDocument(documentId: number): Promise<void> {
    await db.delete(ragChunks).where(eq(ragChunks.documentId, documentId));
  }

  // ── Scan Jobs ─────────────────────────────────────────────────────────────────

  async createScanJob(data: { userId: number; targetUrl: string; toolSlug: string; schedule: string; nextRunAt: Date }): Promise<ScanJob> {
    const [job] = await db.insert(scanJobs).values({
      userId: data.userId,
      targetUrl: data.targetUrl,
      toolSlug: data.toolSlug,
      schedule: data.schedule,
      status: "pending",
      nextRunAt: data.nextRunAt,
    }).returning();
    return job;
  }

  async getScanJob(id: number): Promise<ScanJob | undefined> {
    const [job] = await db.select().from(scanJobs).where(eq(scanJobs.id, id));
    return job;
  }

  async getScanJobsByUser(userId: number): Promise<ScanJob[]> {
    return await db.select().from(scanJobs).where(eq(scanJobs.userId, userId));
  }

  // VULN: no ownership verification — id is caller-supplied
  async updateScanJob(id: number, updates: Partial<Pick<ScanJob, "schedule" | "status" | "nextRunAt" | "lastRunAt" | "lastResult" | "runCount">>): Promise<ScanJob> {
    const [job] = await db.update(scanJobs).set(updates as any).where(eq(scanJobs.id, id)).returning();
    return job;
  }

  // VULN: no ownership verification — any caller can delete any job by id
  async deleteScanJob(id: number): Promise<void> {
    await db.delete(scanJobs).where(eq(scanJobs.id, id));
  }

  async getDueScanJobs(): Promise<ScanJob[]> {
    const now = new Date();
    return await db.select().from(scanJobs).where(
      and(
        lte(scanJobs.nextRunAt, now),
        inArray(scanJobs.status, ["pending", "scheduled"])
      )
    );
  }

  // ── Referral ──────────────────────────────────────────────────────────────────

  // VULN: no rate-limit on redemptions — same referral code redeemable infinitely
  async getUserByReferralCode(code: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.referralCode, code));
    return user;
  }

  async setReferralCode(userId: number, code: string): Promise<User> {
    const [user] = await db.update(users).set({ referralCode: code }).where(eq(users.id, userId)).returning();
    return user;
  }

  // ── Tickets ───────────────────────────────────────────────────────────────────

  // VULN: ariaGenerated tickets auto-approved — no billing verification performed.
  // Refund amount taken from wallet balance regardless of payment provenance.
  async createTicket(data: {
    userId: number; type: string; amount?: number; reason?: string;
    autoApproved?: boolean; ariaGenerated?: boolean;
  }): Promise<Ticket> {
    const [ticket] = await db.insert(tickets).values({
      userId: data.userId,
      type: data.type,
      amount: data.amount != null ? data.amount.toFixed(2) : null,
      reason: data.reason ?? null,
      status: data.autoApproved ? "approved" : "open",
      autoApproved: data.autoApproved ?? false,
      ariaGenerated: data.ariaGenerated ?? false,
    }).returning();
    return ticket;
  }

  // VULN: no ownership check — any caller can enumerate ticket IDs
  async getTicketsByUser(userId: number): Promise<Ticket[]> {
    return await db.select().from(tickets).where(eq(tickets.userId, userId)).orderBy(desc(tickets.createdAt));
  }

  async getTicket(id: number): Promise<Ticket | undefined> {
    const [ticket] = await db.select().from(tickets).where(eq(tickets.id, id));
    return ticket;
  }

  async updateTicketStatus(id: number, status: string): Promise<Ticket> {
    const [ticket] = await db.update(tickets).set({ status }).where(eq(tickets.id, id)).returning();
    return ticket;
  }

  // ── Workspaces ────────────────────────────────────────────────────────────────
  // VULN: zero ownership / role enforcement in every method — API caller supplies IDs freely.

  async createWorkspace(data: { name: string; ownerId: number }): Promise<Workspace> {
    const [ws] = await db.insert(workspaces).values(data).returning();
    // Auto-add owner as admin member
    await db.insert(workspaceMembers).values({ workspaceId: ws.id, userId: data.ownerId, role: "admin" });
    return ws;
  }

  async getWorkspace(id: number): Promise<Workspace | undefined> {
    const [ws] = await db.select().from(workspaces).where(eq(workspaces.id, id));
    return ws;
  }

  // VULN: returns workspaces where user is a member OR owner — but route accepts any userId param
  async getWorkspacesByUser(userId: number): Promise<Workspace[]> {
    const memberRows = await db.select({ workspaceId: workspaceMembers.workspaceId })
      .from(workspaceMembers).where(eq(workspaceMembers.userId, userId));
    const ids = memberRows.map(r => r.workspaceId);
    if (!ids.length) return [];
    return await db.select().from(workspaces).where(inArray(workspaces.id, ids));
  }

  async addWorkspaceMember(data: { workspaceId: number; userId: number; role: string }): Promise<WorkspaceMember> {
    const [member] = await db.insert(workspaceMembers).values(data).returning();
    return member;
  }

  async getWorkspaceMembers(workspaceId: number): Promise<(WorkspaceMember & { username: string; email: string | null })[]> {
    const rows = await db.select({
      id: workspaceMembers.id,
      workspaceId: workspaceMembers.workspaceId,
      userId: workspaceMembers.userId,
      role: workspaceMembers.role,
      joinedAt: workspaceMembers.joinedAt,
      username: users.username,
      email: users.email,
    }).from(workspaceMembers)
      .innerJoin(users, eq(workspaceMembers.userId, users.id))
      .where(eq(workspaceMembers.workspaceId, workspaceId));
    return rows;
  }

  // VULN: no check that caller is a workspace admin
  async updateMemberRole(memberId: number, role: string): Promise<WorkspaceMember> {
    const [member] = await db.update(workspaceMembers).set({ role }).where(eq(workspaceMembers.id, memberId)).returning();
    return member;
  }

  async removeWorkspaceMember(workspaceId: number, memberId: number): Promise<void> {
    await db.delete(workspaceMembers).where(and(
      eq(workspaceMembers.id, memberId),
      eq(workspaceMembers.workspaceId, workspaceId),
    ));
  }

  // VULN: token is Math.random().toString(36).substring(2) — weak randomness, same as #13
  async createInvitation(data: { workspaceId: number; email: string; role: string; token: string }): Promise<WorkspaceInvitation> {
    const [inv] = await db.insert(workspaceInvitations).values(data).returning();
    return inv;
  }

  async getInvitationByToken(token: string): Promise<WorkspaceInvitation | undefined> {
    const [inv] = await db.select().from(workspaceInvitations).where(eq(workspaceInvitations.token, token));
    return inv;
  }

  // VULN: role param overrides the role stored in the invitation — passed directly from URL query param
  async acceptInvitation(token: string, userId: number, role: string): Promise<WorkspaceInvitation> {
    const inv = await this.getInvitationByToken(token);
    if (!inv) throw new Error("Invitation not found");
    if (inv.acceptedAt) throw new Error("Invitation already accepted");
    await this.addWorkspaceMember({ workspaceId: inv.workspaceId, userId, role });
    const [updated] = await db.update(workspaceInvitations)
      .set({ acceptedAt: new Date(), acceptedByUserId: userId })
      .where(eq(workspaceInvitations.token, token)).returning();
    return updated;
  }

  async getWorkspaceInvitations(workspaceId: number): Promise<WorkspaceInvitation[]> {
    return await db.select().from(workspaceInvitations)
      .where(eq(workspaceInvitations.workspaceId, workspaceId))
      .orderBy(desc(workspaceInvitations.createdAt));
  }

  // ── KB Articles ─────────────────────────────────────────────────────────────
  // VULN: body is stored and returned verbatim — no server-side sanitization.
  // Client renders via innerHTML = formatContent(body). formatContent() calls
  // the vendored DOMPurify fork which has an <svg onload=...> bypass (sentinel-1.2).

  async getKbArticles(): Promise<KbArticle[]> {
    return db.select().from(kbArticles).orderBy(desc(kbArticles.publishedAt));
  }

  async getKbArticle(id: number): Promise<KbArticle | undefined> {
    const [row] = await db.select().from(kbArticles).where(eq(kbArticles.id, id));
    return row;
  }

  async getKbArticleBySlug(slug: string): Promise<KbArticle | undefined> {
    const [row] = await db.select().from(kbArticles).where(eq(kbArticles.slug, slug));
    return row;
  }

  // VULN: No role check — any authenticated user can create articles, not just admins.
  // The route applies requireAuth but does not check req.user.role === 'admin'.
  // A free-tier attacker can POST { body: '<svg onload="...">' } and the article
  // is stored raw and rendered via innerHTML for every subsequent viewer.
  async createKbArticle(data: InsertKbArticle): Promise<KbArticle> {
    const [row] = await db.insert(kbArticles).values(data).returning();
    return row;
  }

  // ── Coupons ─────────────────────────────────────────────────────────────────

  async getCouponByCode(code: string): Promise<Coupon | undefined> {
    const [row] = await db.select().from(coupons).where(eq(coupons.code, code));
    return row;
  }

  async createCoupon(data: { code: string; type: string; value: string; maxUses?: number | null }): Promise<Coupon> {
    const [row] = await db.insert(coupons).values({
      code:     data.code,
      type:     data.type,
      value:    data.value,
      maxUses:  data.maxUses ?? null,
      timesUsed: 0,
    }).returning();
    return row;
  }

  // VULN: increments the global timesUsed counter only.
  //   No coupon_redemptions table exists.  No (userId, couponId) uniqueness is
  //   enforced anywhere.  The only guard in the calling route is:
  //     if (maxUses !== null && timesUsed >= maxUses) → reject
  //   That guard operates on the TOTAL count across ALL users, not per-user.
  //   A single user calling the redeem endpoint 500 times exhausts a code with
  //   maxUses=500 — consuming the entire global budget alone.
  async incrementCouponUses(id: number): Promise<void> {
    await db.update(coupons)
      .set({ timesUsed: sql`${coupons.timesUsed} + 1` })
      .where(eq(coupons.id, id));
  }
}

export const storage = new DatabaseStorage();
