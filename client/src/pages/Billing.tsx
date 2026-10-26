import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { CreditCard, Zap, ArrowUp, ArrowDown, Wallet, ChevronRight, Loader2 } from "lucide-react";
import { api } from "@shared/routes";
import { apiRequest } from "@/lib/queryClient";
import { PLANS } from "@shared/schema";

const PLAN_ORDER = ["free", "pro", "enterprise"] as const;

async function handleResponse(res: Response) {
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
  return data;
}

function PlanBadge({ plan }: { plan: string }) {
  const colors: Record<string, string> = {
    free: "bg-muted text-muted-foreground",
    pro: "bg-primary/20 text-primary border border-primary/30",
    enterprise: "bg-accent/20 text-accent-foreground border border-accent/30",
  };
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest ${colors[plan] ?? colors.free}`}>
      {plan}
    </span>
  );
}

function StatCard({ label, value, icon: Icon, sub }: { label: string; value: string; icon: any; sub?: string }) {
  return (
    <div className="glass-panel rounded-xl p-5 flex items-center gap-4">
      <div className="p-3 rounded-lg bg-primary/10 text-primary">
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold font-mono text-foreground">{value}</p>
        {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

export default function Billing() {
  const queryClient = useQueryClient();
  const [userId, setUserId] = useState(2);
  const [orderAmount, setOrderAmount] = useState("100");
  const [topupAmount, setTopupAmount] = useState("25");
  const [paymentMethod, setPaymentMethod] = useState("card_4242");
  const [actionLog, setActionLog] = useState<string[]>([]);

  const log = (msg: string) => setActionLog(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev.slice(0, 19)]);

  const { data: billing, isLoading, error } = useQuery({
    queryKey: ["/api/billing", userId],
    queryFn: async () => {
      const res = await fetch(`/api/billing/${userId}`);
      return handleResponse(res);
    },
    refetchInterval: false,
  });

  const upgrade = useMutation({
    mutationFn: async (targetPlan: string) => {
      const res = await fetch(api.billing.upgrade.path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, targetPlan, paymentMethod }),
      });
      return handleResponse(res);
    },
    onSuccess: (data) => {
      log(`Upgraded to ${data.plan}. Wallet: $${data.walletBalance}`);
      queryClient.invalidateQueries({ queryKey: ["/api/billing", userId] });
    },
    onError: (e: Error) => log(`Upgrade FAILED: ${e.message}`),
  });

  const downgrade = useMutation({
    mutationFn: async (targetPlan: string) => {
      const res = await apiRequest("POST", api.billing.downgrade.path, { userId, targetPlan });
      return handleResponse(res);
    },
    onSuccess: (data) => {
      log(`Downgraded. Refund: $${data.refundAmount}. Wallet: $${data.walletBalance}`);
      queryClient.invalidateQueries({ queryKey: ["/api/billing", userId] });
    },
    onError: (e: Error) => log(`Downgrade FAILED: ${e.message}`),
  });

  const applyCredits = useMutation({
    mutationFn: async () => {
      const res = await fetch(api.billing.applyCredits.path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, orderAmount: parseFloat(orderAmount) }),
      });
      return handleResponse(res);
    },
    onSuccess: (data) => {
      log(`Credits applied. Used: $${data.creditsUsed}. Final amount: $${data.finalAmount}`);
      queryClient.invalidateQueries({ queryKey: ["/api/billing", userId] });
    },
    onError: (e: Error) => log(`Apply credits FAILED: ${e.message}`),
  });

  const topup = useMutation({
    mutationFn: async () => {
      const res = await fetch(api.billing.topup.path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, amount: parseFloat(topupAmount) }),
      });
      return handleResponse(res);
    },
    onSuccess: (data) => {
      log(`Wallet topped up. New balance: $${data.walletBalance}`);
      queryClient.invalidateQueries({ queryKey: ["/api/billing", userId] });
    },
    onError: (e: Error) => log(`Top-up FAILED: ${e.message}`),
  });

  const currentPlanIdx = billing ? PLAN_ORDER.indexOf(billing.plan as any) : -1;
  const isPending = upgrade.isPending || downgrade.isPending || applyCredits.isPending || topup.isPending;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-12">
      <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-4xl font-display font-bold text-foreground mb-2 text-glow">
            Billing &amp; Subscription
          </h1>
          <p className="text-muted-foreground">Manage your plan, credits, and wallet balance.</p>
        </div>
        <div className="flex items-center gap-3 glass-panel rounded-xl p-3">
          <span className="text-sm text-muted-foreground font-mono">User ID:</span>
          <input
            type="number"
            value={userId}
            onChange={(e) => setUserId(parseInt(e.target.value))}
            className="w-16 bg-input text-foreground border-border rounded px-2 py-1 text-sm font-mono text-center"
            min={1}
          />
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/billing", userId] })}
            className="bg-primary/20 hover:bg-primary/30 text-primary rounded px-3 py-1 text-sm font-mono transition-colors"
          >
            Load
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-20 text-muted-foreground gap-3">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading billing data...
        </div>
      )}
      {error && (
        <div className="glass-panel rounded-xl p-6 border border-destructive/30 text-destructive font-mono text-sm mb-6">
          Error: {(error as Error).message}
        </div>
      )}

      {billing && (
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
          {/* Stats Row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <StatCard
              label="Current Plan"
              value={billing.plan.toUpperCase()}
              icon={CreditCard}
              sub={`$${PLANS[billing.plan as keyof typeof PLANS]?.price ?? 0}/mo`}
            />
            <StatCard
              label="Wallet Balance"
              value={`$${parseFloat(billing.walletBalance).toFixed(2)}`}
              icon={Wallet}
              sub="Redeemable credits"
            />
            <StatCard
              label="Account"
              value={billing.username}
              icon={Zap}
              sub={`User #${billing.userId}`}
            />
          </div>

          {/* Plan Cards */}
          <div className="glass-panel rounded-xl p-6">
            <h2 className="text-lg font-display font-bold text-foreground mb-4 flex items-center gap-2">
              <ArrowUp className="w-4 h-4 text-primary" /> Plan Management
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {PLAN_ORDER.map((planKey, idx) => {
                const plan = PLANS[planKey];
                const isCurrent = billing.plan === planKey;
                const isHigher = idx > currentPlanIdx;
                const isLower = idx < currentPlanIdx;
                return (
                  <div
                    key={planKey}
                    className={`rounded-xl p-4 border transition-all ${
                      isCurrent
                        ? "border-primary/60 bg-primary/10"
                        : "border-border/50 bg-card/40"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <PlanBadge plan={planKey} />
                      {isCurrent && <span className="text-xs text-primary font-mono">ACTIVE</span>}
                    </div>
                    <p className="text-2xl font-bold text-foreground font-mono mt-2">
                      ${plan.price}<span className="text-sm text-muted-foreground font-normal">/mo</span>
                    </p>
                    <div className="mt-3 flex flex-col gap-2">
                      {isHigher && (
                        <button
                          onClick={() => upgrade.mutate(planKey)}
                          disabled={isPending}
                          className="w-full bg-primary text-primary-foreground rounded-lg py-1.5 text-sm font-medium flex items-center justify-center gap-1 disabled:opacity-50 transition-all"
                        >
                          <ArrowUp className="w-3 h-3" /> Upgrade
                        </button>
                      )}
                      {isLower && (
                        <button
                          onClick={() => downgrade.mutate(planKey)}
                          disabled={isPending}
                          className="w-full bg-secondary text-secondary-foreground rounded-lg py-1.5 text-sm font-medium flex items-center justify-center gap-1 disabled:opacity-50 transition-all"
                        >
                          <ArrowDown className="w-3 h-3" /> Downgrade
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mt-4 p-3 rounded-lg bg-muted/40 border border-border/50">
              <label className="text-xs text-muted-foreground font-mono uppercase tracking-wider block mb-1.5">
                Payment Method
              </label>
              <div className="flex gap-2">
                <input
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  className="flex-1 bg-input text-foreground border-border rounded-lg px-3 py-1.5 text-sm font-mono"
                  placeholder="card_4242 or fail_test"
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1.5">
                Use <code className="text-primary">fail_test</code> to trigger a payment failure (observe wallet credit behavior).
              </p>
            </div>
          </div>

          {/* Credits & Wallet */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="glass-panel rounded-xl p-6">
              <h2 className="text-lg font-display font-bold text-foreground mb-4 flex items-center gap-2">
                <Wallet className="w-4 h-4 text-primary" /> Apply Credits
              </h2>
              <p className="text-xs text-muted-foreground mb-3">
                Apply wallet credits toward a purchase. Current balance: <span className="text-primary font-mono">${parseFloat(billing.walletBalance).toFixed(2)}</span>
              </p>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={orderAmount}
                  onChange={(e) => setOrderAmount(e.target.value)}
                  className="flex-1 bg-input text-foreground border-border rounded-lg px-3 py-2 text-sm font-mono"
                  placeholder="Order amount..."
                />
                <button
                  onClick={() => applyCredits.mutate()}
                  disabled={isPending}
                  className="bg-primary text-primary-foreground rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50"
                >
                  Apply
                </button>
              </div>
            </div>

            <div className="glass-panel rounded-xl p-6">
              <h2 className="text-lg font-display font-bold text-foreground mb-4 flex items-center gap-2">
                <CreditCard className="w-4 h-4 text-primary" /> Top Up Wallet
              </h2>
              <p className="text-xs text-muted-foreground mb-3">
                Add credits to wallet manually. Referral bonuses and prorated refunds also credit here.
              </p>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={topupAmount}
                  onChange={(e) => setTopupAmount(e.target.value)}
                  className="flex-1 bg-input text-foreground border-border rounded-lg px-3 py-2 text-sm font-mono"
                  placeholder="Amount..."
                />
                <button
                  onClick={() => topup.mutate()}
                  disabled={isPending}
                  className="bg-primary text-primary-foreground rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50"
                >
                  Top Up
                </button>
              </div>
            </div>
          </div>

          {/* Activity Log */}
          {actionLog.length > 0 && (
            <div className="glass-panel rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-border/50 bg-secondary/20 flex items-center gap-2">
                <ChevronRight className="w-4 h-4 text-primary" />
                <span className="text-sm font-display font-bold text-foreground">Activity Log</span>
              </div>
              <div className="p-4 font-mono text-xs space-y-1 max-h-48 overflow-auto">
                {actionLog.map((entry, i) => (
                  <div key={i} className="text-primary/80">{entry}</div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
