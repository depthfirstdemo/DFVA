import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Wallet as WalletIcon, Copy, Check, Gift, RefreshCw, TrendingUp,
  TrendingDown, ArrowDownCircle, Ticket, ExternalLink, ArrowRight,
  AlertCircle, CheckCircle2, Clock, XCircle, Zap
} from "lucide-react";
import { useSession } from "@/lib/session";
import { apiRequest } from "@/lib/queryClient";
import { api } from "@shared/routes";
import { useToast } from "@/hooks/use-toast";
import type { WalletTransaction, Ticket as TicketType, User } from "@shared/schema";

const TX_ICON: Record<string, React.ElementType> = {
  credit:   TrendingUp,
  debit:    TrendingDown,
  topup:    ArrowDownCircle,
  referral: Gift,
};

const TICKET_STATUS_STYLE: Record<string, { cls: string; icon: React.ElementType }> = {
  open:     { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20", icon: Clock },
  approved: { cls: "bg-green-500/10  text-green-400  border-green-500/20",  icon: CheckCircle2 },
  rejected: { cls: "bg-red-500/10    text-red-400    border-red-500/20",    icon: XCircle },
};

function StatusBadge({ status, autoApproved, ariaGenerated }: { status: string; autoApproved?: boolean; ariaGenerated?: boolean }) {
  const { cls, icon: Icon } = TICKET_STATUS_STYLE[status] ?? TICKET_STATUS_STYLE.open;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cls}`}>
      <Icon className="w-2.5 h-2.5" /> {status}
      {/* VULN marker: auto-approved ARIA tickets shown in UI */}
      {ariaGenerated && (
        <span className="ml-1 text-primary font-mono">·ARIA</span>
      )}
    </span>
  );
}

export default function Wallet() {
  const { user, refreshUser } = useSession();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [showDowngrade, setShowDowngrade] = useState(false);
  const [promoCode, setPromoCode] = useState("");
  const [promoResult, setPromoResult] = useState<{ ok: boolean; message: string } | null>(null);

  const userId = user?.id ?? 0;

  const { data: billing } = useQuery<{ walletBalance: string; plan: string; referralCode?: string }>({
    queryKey: ["/api/billing", userId],
    queryFn: () => fetch(`/api/billing/${userId}`).then(r => r.json()),
    enabled: !!userId,
  });

  const { data: referral } = useQuery<{ referralCode: string; username: string }>({
    queryKey: ["/api/referral", userId],
    queryFn: () => fetch(`/api/referral/${userId}`).then(r => r.json()),
    enabled: !!userId,
  });

  const { data: transactions = [] } = useQuery<WalletTransaction[]>({
    queryKey: ["/api/wallet/transactions", userId],
    queryFn: () => fetch(`/api/wallet/transactions/${userId}`).then(r => r.json()),
    enabled: !!userId,
  });

  const { data: tickets = [] } = useQuery<TicketType[]>({
    queryKey: ["/api/tickets", userId],
    queryFn: () => fetch(`/api/tickets?userId=${userId}`).then(r => r.json()),
    enabled: !!userId,
  });

  /*
   * VULN (Business Logic — Missing per-user redemption gate, CWE-841):
   *
   * This mutation calls POST /api/wallet/redeem-promo with whatever code the
   * user types.  The server checks:
   *   1. Does the code exist?          → yes/no
   *   2. Is the global cap not hit?    → timesUsed < maxUses
   * It does NOT check: has THIS user already redeemed this code?
   *
   * Calling this mutation in a loop adds $10/$20/$25 per iteration indefinitely
   * (for codes with no maxUses, like SENTINEL10, there is no global cap either).
   *
   * The UI shows a success message each time — no client-side guard either.
   */
  const redeemPromoMutation = useMutation({
    mutationFn: async (code: string) => {
      const token = localStorage.getItem("sentinel_token");
      const res = await fetch("/api/wallet/redeem-promo", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": token ? `Bearer ${token}` : "",
        },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      return data;
    },
    onSuccess: (data) => {
      setPromoResult({ ok: true, message: data.message });
      setPromoCode("");
      qc.invalidateQueries({ queryKey: ["/api/billing", userId] });
      qc.invalidateQueries({ queryKey: ["/api/wallet/transactions", userId] });
      refreshUser();
    },
    onError: (e: any) => {
      setPromoResult({ ok: false, message: e.message });
    },
  });

  // VULN: downgrade calls processDowngrade — two non-atomic writes (C3)
  const downgradeMutation = useMutation({
    mutationFn: async (targetPlan: string) =>
      (await apiRequest("POST", api.billing.downgrade.path, { targetPlan })).json(),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["/api/billing", userId] });
      qc.invalidateQueries({ queryKey: ["/api/wallet/transactions", userId] });
      refreshUser();
      toast({ title: "Plan downgraded", description: `Proration credit: $${data.refundAmount}` });
      setShowDowngrade(false);
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function copyReferralCode() {
    const code = referral?.referralCode;
    if (!code) return;
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const balance = parseFloat(billing?.walletBalance ?? "0");
  const plan = billing?.plan ?? user?.plan ?? "free";
  const refCode = referral?.referralCode;
  const referralLink = refCode ? `${window.location.origin}/register?ref=${refCode}` : null;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8 flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
          <WalletIcon className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold font-display tracking-tight text-foreground">Wallet & Credits</h1>
          <p className="text-sm text-muted-foreground">Manage your balance, referrals, and support tickets</p>
        </div>
      </div>

      {/* Balance + plan cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
        <div
          data-testid="card-wallet-balance"
          className="rounded-xl border border-border/60 bg-card/40 p-5"
        >
          <p className="text-xs text-muted-foreground uppercase tracking-widest mb-2">Wallet Balance</p>
          <p className="text-3xl font-bold font-mono text-foreground">${balance.toFixed(2)}</p>
          <p className="text-xs text-muted-foreground mt-1">Available for plan upgrades and payouts</p>
        </div>

        <div
          data-testid="card-current-plan"
          className="rounded-xl border border-border/60 bg-card/40 p-5"
        >
          <p className="text-xs text-muted-foreground uppercase tracking-widest mb-2">Current Plan</p>
          <p className="text-xl font-bold font-display capitalize text-foreground">{plan}</p>
          <div className="flex items-center gap-2 mt-3">
            {plan !== "free" && (
              <button
                data-testid="button-downgrade-plan"
                onClick={() => setShowDowngrade(x => !x)}
                className="text-xs px-3 py-1.5 rounded-lg border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                Downgrade plan
              </button>
            )}
            <a
              href="/pricing"
              data-testid="link-upgrade-plan"
              className="text-xs px-3 py-1.5 rounded-lg bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 transition-colors flex items-center gap-1"
            >
              Upgrade <ArrowRight className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Downgrade panel — VULN C3: non-atomic writes, race condition */}
      {showDowngrade && (
        <div
          data-testid="panel-downgrade"
          className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-5 mb-8"
        >
          <div className="flex items-start gap-2 mb-3">
            <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-foreground">Downgrade plan</p>
              <p className="text-xs text-muted-foreground">
                You will receive a prorated credit for unused days. Credits post to your wallet immediately.
              </p>
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            {plan === "enterprise" && (
              <button
                data-testid="button-confirm-downgrade-pro"
                onClick={() => downgradeMutation.mutate("pro")}
                disabled={downgradeMutation.isPending}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30 text-sm font-semibold hover:bg-amber-500/30 transition-colors disabled:opacity-50"
              >
                {downgradeMutation.isPending ? <><RefreshCw className="w-3 h-3 animate-spin" /> Processing…</> : "→ Pro"}
              </button>
            )}
            <button
              data-testid="button-confirm-downgrade-free"
              onClick={() => downgradeMutation.mutate("free")}
              disabled={downgradeMutation.isPending}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 text-sm font-semibold hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              {downgradeMutation.isPending ? <><RefreshCw className="w-3 h-3 animate-spin" /> Processing…</> : "→ Free"}
            </button>
          </div>
        </div>
      )}

      {/*
        * VULN (Business Logic — promo code redemption without per-user tracking):
        *
        * The UI presents a normal promo code input.  The endpoint it calls
        * (POST /api/wallet/redeem-promo) validates code existence and a global
        * usage cap, but never records which user redeemed which code.
        *
        * The same user submitting this form repeatedly receives $10/$20/$25
        * on each submission with no server-side block.
        *
        * Known redeemable codes (seeded on startup):
        *   WELCOME20   → $20  (maxUses: 500, per-user: unlimited)
        *   SENTINEL10  → $10  (maxUses: none, per-user: unlimited)
        *   BLACKHAT25  → $25  (maxUses: 200, per-user: unlimited)
        */}
      <div
        data-testid="card-promo-redeem"
        className="rounded-xl border border-border/60 bg-card/40 p-5 mb-8"
      >
        <div className="flex items-center gap-2 mb-3">
          <Ticket className="w-4 h-4 text-primary" />
          <h2 className="text-sm font-semibold text-foreground">Redeem Promo Code</h2>
        </div>
        <p className="text-xs text-muted-foreground mb-4">
          Have a promotional code? Enter it below to credit your wallet instantly.
        </p>

        <div className="flex gap-2">
          <input
            data-testid="input-promo-code"
            type="text"
            value={promoCode}
            onChange={e => { setPromoCode(e.target.value.toUpperCase()); setPromoResult(null); }}
            onKeyDown={e => e.key === "Enter" && promoCode && redeemPromoMutation.mutate(promoCode)}
            placeholder="e.g. WELCOME20"
            className="flex-1 bg-background border border-border/60 rounded-lg px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50"
          />
          <button
            data-testid="button-redeem-promo"
            onClick={() => promoCode && redeemPromoMutation.mutate(promoCode)}
            disabled={!promoCode || redeemPromoMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-primary/10 hover:bg-primary/20 border border-primary/30 hover:border-primary/50 text-primary text-sm font-semibold rounded-lg transition-all disabled:opacity-40"
          >
            {redeemPromoMutation.isPending ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5" />
            )}
            Apply
          </button>
        </div>

        {promoResult && (
          <div
            data-testid="text-promo-result"
            className={`mt-3 flex items-center gap-2 text-xs rounded-lg px-3 py-2 border ${
              promoResult.ok
                ? "text-green-400 bg-green-500/10 border-green-500/20"
                : "text-red-400 bg-red-500/10 border-red-500/20"
            }`}
          >
            {promoResult.ok
              ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
              : <AlertCircle className="w-3.5 h-3.5 shrink-0" />}
            {promoResult.message}
          </div>
        )}
      </div>

      {/* Referral code — C1 vector */}
      {refCode && (
        <div
          data-testid="card-referral"
          className="rounded-xl border border-primary/20 bg-primary/5 p-5 mb-8"
        >
          <div className="flex items-center gap-2 mb-3">
            <Gift className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold text-foreground">Your Referral Code</h2>
          </div>
          <p className="text-xs text-muted-foreground mb-3">
            Share your code with new users. You earn <span className="text-primary font-semibold">$25 wallet credit</span> instantly
            when they register — no payment required on their part.
          </p>

          <div className="flex items-center gap-2 mb-3">
            <span
              data-testid="text-referral-code"
              className="font-mono text-lg font-bold text-primary tracking-widest"
            >
              {refCode}
            </span>
            <button
              data-testid="button-copy-referral"
              onClick={copyReferralCode}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>

          {referralLink && (
            <div className="flex items-center gap-2">
              <p
                data-testid="text-referral-link"
                className="text-xs font-mono text-muted-foreground truncate bg-background/60 rounded px-2 py-1 flex-1"
              >
                {referralLink}
              </p>
              <button
                data-testid="button-copy-referral-link"
                onClick={() => { navigator.clipboard.writeText(referralLink); toast({ title: "Link copied!" }); }}
                className="p-1.5 rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors shrink-0"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <div
            data-testid="banner-referral-vuln-note"
            className="mt-3 flex items-center gap-1.5 text-[10px] text-amber-400/70"
          >
            <Zap className="w-2.5 h-2.5 shrink-0" />
            Credit posts before any payment is verified. Code can be reused unlimited times.
          </div>
        </div>
      )}

      {/* Transaction history */}
      <div className="mb-8">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest mb-3">
          Transaction History
        </h2>

        {transactions.length === 0 ? (
          <div
            data-testid="state-empty-transactions"
            className="text-center py-8 text-muted-foreground text-sm"
          >
            No transactions yet.
          </div>
        ) : (
          <div className="space-y-2">
            {transactions.map(tx => {
              const Icon = TX_ICON[tx.type] ?? TrendingUp;
              const isPositive = parseFloat(tx.amount) > 0;
              return (
                <div
                  key={tx.id}
                  data-testid={`row-transaction-${tx.id}`}
                  className="flex items-center gap-3 rounded-xl border border-border/60 bg-card/40 px-4 py-3"
                >
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${isPositive ? "bg-green-500/10" : "bg-red-500/10"}`}>
                    <Icon className={`w-3.5 h-3.5 ${isPositive ? "text-green-400" : "text-red-400"}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-foreground truncate">{tx.description ?? tx.type}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(tx.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <span
                    data-testid={`text-tx-amount-${tx.id}`}
                    className={`font-mono text-sm font-semibold ${isPositive ? "text-green-400" : "text-red-400"}`}
                  >
                    {isPositive ? "+" : ""}${parseFloat(tx.amount).toFixed(2)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Support tickets — C4 ARIA refund tickets appear here */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest">
            Support Tickets
          </h2>
          <span className="text-xs text-muted-foreground">
            Ask ARIA to submit a refund ticket for auto-processing
          </span>
        </div>

        {tickets.length === 0 ? (
          <div
            data-testid="state-empty-tickets"
            className="text-center py-8 text-muted-foreground text-sm"
          >
            No tickets yet. Chat with ARIA to request a refund.
          </div>
        ) : (
          <div className="space-y-2">
            {tickets.map(ticket => (
              <div
                key={ticket.id}
                data-testid={`card-ticket-${ticket.id}`}
                className="rounded-xl border border-border/60 bg-card/40 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <Ticket className="w-4 h-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="text-sm font-medium text-foreground capitalize">{ticket.type}</p>
                      {ticket.amount && (
                        <span
                          data-testid={`text-ticket-amount-${ticket.id}`}
                          className="text-sm font-mono font-bold text-green-400"
                        >
                          ${parseFloat(ticket.amount).toFixed(2)}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground truncate">{ticket.reason}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(ticket.createdAt).toLocaleString()}
                      {ticket.ariaGenerated && <span className="ml-2 text-primary">· generated by ARIA</span>}
                    </p>
                  </div>
                  <StatusBadge
                    status={ticket.status}
                    autoApproved={ticket.autoApproved ?? false}
                    ariaGenerated={ticket.ariaGenerated ?? false}
                  />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ARIA shortcut */}
        <div
          data-testid="banner-aria-refund"
          className="mt-4 rounded-xl border border-primary/20 bg-primary/5 px-4 py-3 flex items-center gap-3"
        >
          <Zap className="w-4 h-4 text-primary shrink-0" />
          <p className="text-xs text-muted-foreground flex-1">
            ARIA can submit refund tickets on your behalf. Refund tickets are automatically approved and
            processed — no manual billing review required for amounts under $500.
          </p>
          <a
            href="/"
            data-testid="link-open-aria"
            className="text-xs text-primary hover:underline flex items-center gap-1 shrink-0"
          >
            Chat with ARIA <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </div>
  );
}
