import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Clock, Plus, Trash2, RefreshCw, CheckCircle2, XCircle,
  AlertCircle, Play, Calendar, Globe, ChevronDown, ChevronUp, Lock, Download
} from "lucide-react";
import { useSession } from "@/lib/session";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { ScanJob } from "@shared/schema";

const TOOLS = ["nullscan", "webprobe", "dnsreaper", "phantomtrace", "vaultbreach", "cipheraudit"];

const STATUS_STYLES: Record<string, { cls: string; icon: React.ElementType }> = {
  pending:   { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",  icon: Clock },
  scheduled: { cls: "bg-blue-500/10  text-blue-400  border-blue-500/20",     icon: Calendar },
  running:   { cls: "bg-primary/10   text-primary   border-primary/20",      icon: RefreshCw },
  completed: { cls: "bg-green-500/10 text-green-400  border-green-500/20",   icon: CheckCircle2 },
  failed:    { cls: "bg-red-500/10   text-red-400    border-red-500/20",     icon: XCircle },
  cancelled: { cls: "bg-muted/60     text-muted-foreground border-border/40", icon: XCircle },
};

function StatusBadge({ status }: { status: string }) {
  const { cls, icon: Icon } = STATUS_STYLES[status] ?? STATUS_STYLES.pending;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cls}`}>
      <Icon className={`w-2.5 h-2.5 ${status === "running" ? "animate-spin" : ""}`} />
      {status}
    </span>
  );
}

function JobRow({ job, onDelete, onPatch }: {
  job: ScanJob;
  onDelete: (id: number) => void;
  onPatch:  (id: number, schedule: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const result = (() => {
    try { return job.lastResult ? JSON.parse(job.lastResult) : null; }
    catch { return null; }
  })();

  return (
    <div
      data-testid={`card-job-${job.id}`}
      className="rounded-xl border border-border/60 bg-card/40 overflow-hidden"
    >
      <div className="flex items-center gap-3 px-4 py-3">
        <Globe className="w-4 h-4 text-muted-foreground shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-foreground truncate" data-testid={`text-job-url-${job.id}`}>
            {job.targetUrl}
          </p>
          <p className="text-xs text-muted-foreground">
            <span className="font-mono">{job.toolSlug}</span>
            {" · "}
            <span className="capitalize">{job.schedule}</span>
            {" · "}
            runs: {job.runCount ?? 0}
            {job.lastRunAt && ` · last: ${new Date(job.lastRunAt).toLocaleString()}`}
          </p>
        </div>

        <StatusBadge status={job.status} />

        {/* Offer a schedule upgrade for pending or scheduled one-time jobs. */}
        {(job.status === "pending" || job.status === "scheduled") && job.schedule === "one-time" && (
          <button
            data-testid={`button-upgrade-schedule-${job.id}`}
            onClick={() => onPatch(job.id, "daily")}
            title="Upgrade to daily (plan gate bypass)"
            className="text-[10px] px-2 py-1 rounded border border-primary/30 text-primary hover:bg-primary/10 transition-colors font-mono"
          >
            → daily
          </button>
        )}

        {result && (
          <button
            data-testid={`button-expand-result-${job.id}`}
            onClick={() => setExpanded(x => !x)}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}

        {/*
          * Download Report button — visible only for completed scan jobs.
          *
          * Calls GET /api/reports/download?reportId={job.id}
          * The reportId is the DB-integer job ID in normal use.
          *
          * VULN: An attacker can replace the reportId in the URL directly.
          *       The backend middleware validates parseInt(reportId) against the DB,
          *       but path.join uses the raw string.  Bypass:
          *         GET /api/reports/download?reportId=1/../../server/github.ts
          *       (parseInt("1/../../server/github.ts") = 1 → DB passes for jdoe)
          */}
        {job.status === "completed" && (
          <a
            data-testid={`button-download-report-${job.id}`}
            href={`/api/reports/download?reportId=${job.id}`}
            download={`sentinel-report-${job.id}.txt`}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors"
            title="Download scan report"
          >
            <Download className="w-3.5 h-3.5" />
          </a>
        )}

        {/* Allow owners to cancel a job. */}
        <button
          data-testid={`button-cancel-job-${job.id}`}
          onClick={() => onDelete(job.id)}
          className="p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
          title="Cancel / delete job"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      {expanded && result && (
        <div className="border-t border-border/40 px-4 py-3 bg-muted/10">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-2">
            Last Scan Result
          </p>
          {result.error ? (
            <p className="text-xs text-red-400 font-mono">{result.error}</p>
          ) : (
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">
                HTTP <span className="font-mono text-foreground">{result.status}</span>
                {" · "}scanned at {result.scannedAt}
              </p>
              <pre
                data-testid={`text-scan-result-${job.id}`}
                className="text-xs font-mono text-foreground bg-background/60 rounded p-2 overflow-x-auto max-h-40 whitespace-pre-wrap break-all"
              >
                {result.body}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Scans() {
  const { user } = useSession();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [url,      setUrl]      = useState("");
  const [tool,     setTool]     = useState(TOOLS[0]);
  const [schedule, setSchedule] = useState("one-time");

  const canSchedule = user?.plan === "pro" || user?.plan === "enterprise";
  const userId = user?.id ?? 0;

  // PR #24: list query uses the authenticated session — no ?userId= param needed.
  // The server derives the caller from the JWT and returns only their own jobs.
  const { data: jobs = [], isLoading } = useQuery<ScanJob[]>({
    queryKey: ["/api/scans"],
    queryFn: () => apiRequest("GET", "/api/scans").then(r => r.json()),
    enabled: !!userId,
    refetchInterval: 8000,
  });

  // PR #24: userId removed from body — server derives it from the JWT.
  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest("POST", "/api/scans", body).then(async r => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.message);
        return d;
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/scans"] });
      setUrl("");
      toast({ title: "Scan job created" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  // PR #24: PATCH sent via apiRequest so the JWT is included in Authorization header.
  const patchMutation = useMutation({
    mutationFn: ({ id, schedule }: { id: number; schedule: string }) =>
      apiRequest("PATCH", `/api/scans/${id}`, { schedule }).then(r => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/scans"] }),
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  // PR #24: DELETE sent via apiRequest so the JWT is included in Authorization header.
  const deleteMutation = useMutation({
    mutationFn: (id: number) =>
      apiRequest("DELETE", `/api/scans/${id}`).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/scans"] });
      toast({ title: "Job cancelled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    // PR #24: userId not sent — server reads it from the verified JWT.
    createMutation.mutate({ targetUrl: url, toolSlug: tool, schedule });
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Clock className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display tracking-tight text-foreground">
              Scheduled Scans
            </h1>
            <p className="text-sm text-muted-foreground">Automate recurring scans on target URLs</p>
          </div>
        </div>
        <p className="text-muted-foreground text-sm mt-3 max-w-2xl">
          Pro and Enterprise subscribers can schedule daily or weekly scans. Results are stored and accessible from this dashboard.
        </p>
      </div>

      {/* Create form */}
      <form
        onSubmit={handleCreate}
        className="rounded-xl border border-border/60 bg-card/40 p-5 mb-8"
        data-testid="form-create-scan"
      >
        <h2 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
          <Plus className="w-4 h-4 text-primary" /> New Scan Job
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
          <div className="sm:col-span-3">
            <label className="text-xs text-muted-foreground mb-1 block">Target URL</label>
            <input
              data-testid="input-scan-url"
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3 py-2 rounded-lg bg-input text-foreground border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono"
              required
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Tool</label>
            <select
              data-testid="select-scan-tool"
              value={tool}
              onChange={e => setTool(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-input text-foreground border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              Schedule {!canSchedule && <span className="text-amber-400 ml-1">(Pro/Enterprise)</span>}
            </label>
            <select
              data-testid="select-scan-schedule"
              value={schedule}
              onChange={e => setSchedule(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-input text-foreground border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="one-time">One-time</option>
              {/* These render in UI for all plans — plan gate only enforced server-side on POST */}
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              data-testid="button-create-scan"
              type="submit"
              disabled={createMutation.isPending}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {createMutation.isPending
                ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Creating…</>
                : <><Play className="w-3.5 h-3.5" /> Create Job</>}
            </button>
          </div>
        </div>

        {!canSchedule && schedule !== "one-time" && (
          <div
            data-testid="banner-plan-warning"
            className="flex items-center gap-2 text-xs text-amber-400 bg-amber-500/5 border border-amber-500/20 rounded-lg px-3 py-2"
          >
            <Lock className="w-3 h-3 shrink-0" />
            Recurring schedules require a Pro or Enterprise plan.
          </div>
        )}
      </form>

      {/* Job list */}
      <div>
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest mb-3">
          Your Jobs ({jobs.length})
        </h2>

        {isLoading ? (
          <div className="space-y-2">
            {[1, 2].map(i => <div key={i} className="h-16 rounded-xl bg-muted/20 animate-pulse" />)}
          </div>
        ) : jobs.length === 0 ? (
          <div data-testid="state-empty-scans" className="text-center py-16 text-muted-foreground">
            <Clock className="w-8 h-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No scan jobs yet.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {jobs.map(job => (
              <JobRow
                key={job.id}
                job={job}
                onDelete={id => deleteMutation.mutate(id)}
                onPatch={(id, sched) => patchMutation.mutate({ id, schedule: sched })}
              />
            ))}
          </div>
        )}
      </div>

      {/* Info banner */}
      <div
        data-testid="banner-scan-info"
        className="mt-10 flex items-start gap-3 rounded-xl border border-border/60 bg-muted/10 px-4 py-3 text-xs text-muted-foreground"
      >
        <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
        <p>
          Jobs are executed by the background worker every 15 seconds. One-time jobs run once and complete;
          daily and weekly jobs are rescheduled automatically. Scan results including HTTP status and response
          previews are stored and displayed here.
        </p>
      </div>
    </div>
  );
}
