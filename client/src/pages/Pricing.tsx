import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Check, ArrowUp, ArrowDown, Wallet, Loader2, Shield, Zap, Star,
  AlertTriangle, X
} from "lucide-react";
import { PLANS } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session";
import { apiRequest } from "@/lib/queryClient";
import { api } from "@shared/routes";
import PaymentModal from "@/components/PaymentModal";
import type { CardDetails } from "@/components/PaymentModal";

const PLAN_ORDER = ["free", "pro", "enterprise"] as const;

const PLAN_UI: Record<string, {
  icon: React.ElementType;
  color: string;
  highlight: boolean;
  perks: string[];
  tools: string;
}> = {
  free: {
    icon: Zap,
    color: "border-border/60",
    highlight: false,
    perks: [
      "NullScan — port scanner",
      "DNSReaper — DNS enumeration",
      "5,000 API calls / month",
      "Community support",
      "REST API access",
    ],
    tools: "2 tools",
  },
  pro: {
    icon: Shield,
    color: "border-primary/40 ring-1 ring-primary/20",
    highlight: true,
    perks: [
      "Everything in Free",
      "WebProbe — web app scanner",
      "VaultBreach — password auditor",
      "PhantomTrace — OSINT framework",
      "CipherAudit — TLS analyser",
      "PacketVault — traffic analyser",
      "50,000 API calls / month",
      "Priority support",
      "CI/CD integrations",
    ],
    tools: "7 tools",
  },
  enterprise: {
    icon: Star,
    color: "border-amber-500/30",
    highlight: false,
    perks: [
      "Everything in Pro",
      "ThreatFeed Pro — live intelligence",
      "LogSentinel — cloud SIEM",
      "ShadowBrute — credential testing",
      "Unlimited API calls",
      "Dedicated support engineer",
      "SSO / SAML",
      "Self-hosted deployment",
      "99.9% SLA",
    ],
    tools: "All 10 tools",
  },
};

const DOWNGRADE_LOSS: Record<string, string[]> = {
  free:       ["WebProbe", "VaultBreach", "PhantomTrace", "CipherAudit", "PacketVault", "ThreatFeed Pro", "LogSentinel", "ShadowBrute"],
  pro:        ["ThreatFeed Pro", "LogSentinel", "ShadowBrute"],
  enterprise: [],
};

async function apiFetch(url: string, body: object) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
  return data;
}

export default function Pricing() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const { user, refreshUser } = useSession();
  const [, navigate] = useLocation();

  useEffect(() => {
    if (!user) navigate("/login");
  }, [user]);

  if (!user) return null;

  const [paymentTarget, setPaymentTarget] = useState<{ plan: string; price: number } | null>(null);
  const [downgradeTarget, setDowngradeTarget] = useState<string | null>(null);
  const [topupAmount, setTopupAmount] = useState("25");

  const { data: billing, isLoading } = useQuery({
    queryKey: ["/api/billing", user.id],
    queryFn: async () => {
      const res = await fetch(`/api/billing/${user.id}`);
      const d = await res.json();
      if (!res.ok) throw new Error(d.message);
      return d;
    },
  });

  const currentPlan = billing?.plan ?? user.plan;
  const currentPlanIdx = PLAN_ORDER.indexOf(currentPlan as any);

  const downgrade = useMutation({
    mutationFn: async (plan: string) => (await apiRequest("POST", api.billing.downgrade.path, { targetPlan: plan })).json(),
    onSuccess: async (d, plan) => {
      toast({ title: "Plan downgraded", description: `Moved to ${plan}. Refund: $${d.refundAmount ?? "0.00"}` });
      await refreshUser();
      qc.invalidateQueries({ queryKey: ["/api/billing", user.id] });
      setDowngradeTarget(null);
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const topup = useMutation({
    mutationFn: () => apiFetch("/api/billing/topup", { userId: user.id, amount: parseFloat(topupAmount) }),
    onSuccess: async (d) => {
      toast({ title: "Credits added", description: `Balance: $${d.walletBalance}` });
      await refreshUser();
      qc.invalidateQueries({ queryKey: ["/api/billing", user.id] });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const handlePayment = async (plan: string, price: number, card: CardDetails) => {
    const data = await apiFetch("/api/subscription/pay", {
      userId: user.id,
      targetPlan: plan,
      card,
    });
    await refreshUser();
    qc.invalidateQueries({ queryKey: ["/api/billing", user.id] });
    toast({ title: "Subscription updated", description: `Now on ${data.plan} plan.` });
  };

  const busy = downgrade.isPending || topup.isPending;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
      {/* Header */}
      <div className="text-center mb-14">
        <h1 className="text-4xl sm:text-5xl font-display font-bold text-foreground mb-3">
          Simple, transparent pricing
        </h1>
        <p className="text-lg text-muted-foreground max-w-xl mx-auto">
          One subscription. All the tools your security team needs. Cancel anytime.
        </p>
        {billing && (
          <div className="inline-flex items-center gap-2 mt-5 px-4 py-2 rounded-full border border-border/60 bg-card/40 text-sm text-muted-foreground">
            Signed in as <strong className="text-foreground">{billing.username}</strong>
            <span className="text-border mx-1">·</span>
            <span className="capitalize text-foreground">{billing.plan} plan</span>
            <span className="text-border mx-1">·</span>
            <span className="text-primary font-mono">${parseFloat(billing.walletBalance ?? "0").toFixed(2)} credits</span>
            {isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin ml-1" />}
          </div>
        )}
      </div>

      {/* Plan cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-14">
        {PLAN_ORDER.map((planKey, idx) => {
          const plan = PLANS[planKey];
          const ui = PLAN_UI[planKey];
          const Icon = ui.icon;
          const isCurrent = currentPlan === planKey;
          const isHigher = idx > currentPlanIdx;
          const isLower = idx < currentPlanIdx;

          return (
            <div
              key={planKey}
              data-testid={`card-plan-${planKey}`}
              className={`relative glass-panel rounded-2xl p-7 border flex flex-col gap-5 ${ui.color} ${ui.highlight ? "shadow-lg shadow-primary/10" : ""}`}
            >
              {ui.highlight && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-primary text-primary-foreground text-xs font-bold px-4 py-1 rounded-full uppercase tracking-wider">
                  Most Popular
                </div>
              )}

              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${ui.highlight ? "bg-primary/20 text-primary" : "bg-muted/50 text-muted-foreground"}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <div className="font-display font-bold text-lg text-foreground">{plan.name}</div>
                  <div className="text-xs text-muted-foreground">{ui.tools}</div>
                </div>
                {isCurrent && (
                  <span className="ml-auto text-[10px] bg-primary/10 text-primary border border-primary/30 px-2 py-0.5 rounded-full font-bold uppercase tracking-widest">
                    Current
                  </span>
                )}
              </div>

              <div>
                <span className="text-4xl font-display font-bold text-foreground">
                  {plan.price === 0 ? "Free" : `$${plan.price}`}
                </span>
                {plan.price > 0 && <span className="text-muted-foreground text-sm">/month</span>}
              </div>

              <ul className="space-y-2.5 flex-1">
                {ui.perks.map(perk => (
                  <li key={perk} className="flex items-start gap-2 text-sm text-muted-foreground">
                    <Check className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                    {perk}
                  </li>
                ))}
              </ul>

              <div className="pt-2 space-y-2">
                {isHigher && (
                  <button
                    data-testid={`button-upgrade-${planKey}`}
                    onClick={() => setPaymentTarget({ plan: planKey, price: plan.price })}
                    disabled={busy}
                    className="w-full flex items-center justify-center gap-2 bg-primary text-primary-foreground rounded-xl py-2.5 text-sm font-semibold disabled:opacity-50 transition-all"
                  >
                    <ArrowUp className="w-4 h-4" /> Upgrade to {plan.name}
                  </button>
                )}
                {isLower && (
                  <button
                    data-testid={`button-downgrade-${planKey}`}
                    onClick={() => setDowngradeTarget(planKey)}
                    disabled={busy}
                    className="w-full flex items-center justify-center gap-2 bg-secondary text-secondary-foreground rounded-xl py-2.5 text-sm font-medium disabled:opacity-50 transition-all"
                  >
                    <ArrowDown className="w-4 h-4" /> Downgrade to {plan.name}
                  </button>
                )}
                {isCurrent && (
                  <div className="text-center text-sm text-muted-foreground py-2">Current plan</div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Credit top-up section */}
      <div className="glass-panel rounded-2xl border border-border/60 p-8">
        <h2 className="text-xl font-display font-bold text-foreground mb-2">Add Credits</h2>
        <p className="text-sm text-muted-foreground mb-6">Credits are used for pay-per-use API calls above your plan limit.</p>
        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Wallet className="w-3.5 h-3.5" /> Amount ($)
            </label>
            <input
              data-testid="input-topup-amount"
              type="number"
              value={topupAmount}
              onChange={e => setTopupAmount(e.target.value)}
              className="w-32 bg-input border border-border rounded-xl px-4 py-2.5 text-sm font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <button
            data-testid="button-topup"
            onClick={() => topup.mutate()}
            disabled={busy}
            className="bg-primary text-primary-foreground rounded-xl px-5 py-2.5 text-sm font-semibold disabled:opacity-50 flex items-center gap-2 transition-all"
          >
            {topup.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wallet className="w-4 h-4" />}
            Top Up
          </button>
        </div>
      </div>

      {/* Payment modal */}
      {paymentTarget && (
        <PaymentModal
          planName={PLANS[paymentTarget.plan].name}
          planPrice={paymentTarget.price}
          onConfirm={(card) => handlePayment(paymentTarget.plan, paymentTarget.price, card)}
          onClose={() => setPaymentTarget(null)}
        />
      )}

      {/* Downgrade confirmation modal */}
      {downgradeTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-sm glass-panel rounded-2xl border border-border/60 p-7 shadow-2xl">
            <div className="flex items-start gap-3 mb-5">
              <div className="p-2 rounded-lg bg-destructive/10 text-destructive flex-shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-display font-bold text-foreground mb-1">Downgrade to {PLANS[downgradeTarget]?.name}?</h3>
                <p className="text-sm text-muted-foreground">You'll immediately lose access to:</p>
              </div>
            </div>

            <ul className="mb-6 space-y-1.5 ml-2">
              {(DOWNGRADE_LOSS[downgradeTarget] ?? []).slice(0, currentPlanIdx === 2 && downgradeTarget === "free" ? 8 : 3).map(t => (
                <li key={t} className="flex items-center gap-2 text-sm text-muted-foreground">
                  <X className="w-3.5 h-3.5 text-destructive flex-shrink-0" /> {t}
                </li>
              ))}
            </ul>

            <div className="flex gap-3">
              <button
                data-testid="button-downgrade-cancel"
                onClick={() => setDowngradeTarget(null)}
                className="flex-1 rounded-xl py-2.5 border border-border/60 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                Cancel
              </button>
              <button
                data-testid="button-downgrade-confirm"
                onClick={() => downgrade.mutate(downgradeTarget)}
                disabled={downgrade.isPending}
                className="flex-1 rounded-xl py-2.5 bg-destructive/10 border border-destructive/30 text-destructive text-sm font-semibold hover:bg-destructive/20 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {downgrade.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                Downgrade
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
