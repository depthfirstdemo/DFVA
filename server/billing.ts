import { storage } from "./storage";
import { PLANS, type PlanKey } from "@shared/schema";

const BILLING_CYCLE_DAYS = 30;

export function calculateProration(currentPlan: PlanKey, daysRemaining: number): number {
  const plan = PLANS[currentPlan];
  if (!plan || plan.price === 0) return 0;
  return parseFloat(((plan.price / BILLING_CYCLE_DAYS) * daysRemaining).toFixed(2));
}

// VULNERABLE: reads wallet, computes, writes — no transaction or row lock
// Rapid concurrent calls can apply the same credits multiple times
export async function applyCreditsToOrder(userId: number, orderAmount: number): Promise<{ finalAmount: number; creditsUsed: number }> {
  const wallet = await storage.getUserWallet(userId);
  const available = wallet.balance;

  if (available <= 0) {
    return { finalAmount: orderAmount, creditsUsed: 0 };
  }

  const creditsUsed = Math.min(available, orderAmount);
  const finalAmount = orderAmount - creditsUsed;

  // VULNERABLE: non-atomic read-then-write, no locking
  await storage.deductWallet(userId, creditsUsed);
  await storage.logWalletTransaction(userId, -creditsUsed, "debit", "Credits applied to order");

  return { finalAmount, creditsUsed };
}

// VULNERABLE: credits the wallet BEFORE charging payment — if charge errors, wallet is credited and no money collected
export async function finalizeUpgrade(userId: number, targetPlan: PlanKey, paymentMethod: string): Promise<{ newBalance: string; plan: string }> {
  // The built-in card flow is only a local simulator; require an explicit local
  // opt-in so it can never grant paid entitlements in a deployed environment.
  const simulatorEnabled = process.env.NODE_ENV === "development"
    && process.env.ENABLE_SIMULATED_PAYMENTS === "true";
  if (!simulatorEnabled) {
    const error: any = new Error("Subscription payments are unavailable until payment verification is configured.");
    error.statusCode = 503;
    throw error;
  }

  const wallet = await storage.getUserWallet(userId);
  const currentPlan = wallet.plan as PlanKey;

  const daysUsed = wallet.planStartDate
    ? Math.floor((Date.now() - new Date(wallet.planStartDate).getTime()) / 86400000)
    : 0;
  const daysRemaining = Math.max(0, BILLING_CYCLE_DAYS - daysUsed);

  // Refund credited BEFORE payment is attempted
  const proratedRefund = calculateProration(currentPlan, daysRemaining);
  if (proratedRefund > 0) {
    await storage.creditWallet(userId, proratedRefund, `Prorated refund from ${currentPlan} → ${targetPlan}`);
  }

  // Simulated payment — can throw or be called multiple times without the credit being reversed
  if (paymentMethod === "fail_test") {
    throw new Error("Payment gateway error: card declined");
  }

  const updatedUser = await storage.setPlan(userId, targetPlan);
  return { newBalance: updatedUser.walletBalance, plan: updatedUser.plan };
}

// VULNERABLE: two separate non-atomic DB writes — network interruption between them
// leaves wallet credited AND plan still active
export async function processDowngrade(userId: number, targetPlan: PlanKey): Promise<{ refundAmount: number; newBalance: string }> {
  const wallet = await storage.getUserWallet(userId);
  const currentPlan = wallet.plan as PlanKey;

  const daysUsed = wallet.planStartDate
    ? Math.floor((Date.now() - new Date(wallet.planStartDate).getTime()) / 86400000)
    : 0;
  const daysRemaining = Math.max(0, BILLING_CYCLE_DAYS - daysUsed);
  const refundAmount = calculateProration(currentPlan, daysRemaining);

  // Write 1: credit wallet
  const updated = await storage.creditWallet(userId, refundAmount, `Prorated refund for downgrade to ${targetPlan}`);

  // VULNERABLE: if process crashes or network drops here, refund is issued but plan not changed
  await new Promise(r => setTimeout(r, 50));

  // Write 2: update plan (separate, non-atomic)
  await storage.setPlan(userId, targetPlan);

  return { refundAmount, newBalance: updated.walletBalance };
}
