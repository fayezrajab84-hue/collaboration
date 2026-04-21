import { useState, useRef, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  FileText, Sparkles, RotateCcw, Copy, Download, Check,
  Trash2, RefreshCw, GitBranch, Box, Globe, AlertTriangle,
  ExternalLink, ShieldCheck,
} from "lucide-react";
import { reportsApi, type ReportMeta } from "../lib/api";
import { formatDate } from "../lib/utils";
import { SEVERITY_TEXT } from "../lib/colors";

// ── Severity colours — canonical from colors.ts ───────────────────────────────
const SEV_COLOR = SEVERITY_TEXT;

const GRADE_STYLE: Record<string, string> = {
  A: "bg-green-900/40  text-green-300  border border-green-700/50",
  B: "bg-lime-900/40   text-lime-300   border border-lime-700/50",
  C: "bg-amber-900/40  text-amber-300  border border-amber-700/50",
  D: "bg-orange-900/40 text-orange-300 border border-orange-700/50",
  F: "bg-red-900/40    text-red-300    border border-red-700/50",
};

const TARGET_ICON: Record<string, React.ElementType> = {
  REPOSITORY: GitBranch,
  CONTAINER:  Box,
  DOMAIN:     Globe,
};

// ── Severity mini-bar ─────────────────────────────────────────────────────────

function SevBar({ meta }: { meta: ReportMeta["metadata"] }) {
  const total = meta.totalFindings || 1;
  const segs = [
    { sev: "CRITICAL", count: meta.CRITICAL, color: "bg-red-500"    },
    { sev: "HIGH",     count: meta.HIGH,     color: "bg-orange-500" },
    { sev: "MEDIUM",   count: meta.MEDIUM,   color: "bg-amber-500"  },
    { sev: "LOW",      count: meta.LOW,      color: "bg-green-500"  },
    { sev: "INFO",     count: meta.INFO,     color: "bg-gray-500"   },
  ].filter((s) => s.count > 0);

  if (segs.length === 0) return <span className="text-xs text-green-400">✓ Clean</span>;

  return (
    <div className="flex items-center gap-2">
      <div className="flex h-1.5 w-24 overflow-hidden rounded-full bg-gray-800">
        {segs.map((s) => (
          <div
            key={s.sev}
            className={`h-full ${s.color}`}
            style={{ width: `${(s.count / total) * 100}%` }}
            title={`${s.sev}: ${s.count}`}
          />
        ))}
      </div>
      <div className="flex gap-1.5">
        {segs.map((s) => (
          <span key={s.sev} className={`text-[10px] font-bold ${SEV_COLOR[s.sev]}`}>
            {s.count}
            <span className="font-normal opacity-60">{s.sev[0]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Report card ───────────────────────────────────────────────────────────────

function ReportCard({
  report,
  onDelete,
}: {
  report: ReportMeta;
  onDelete: (id: string) => void;
}) {
  const grade   = report.metadata.riskGrade ?? "?";
  const Icon    = TARGET_ICON[report.targetType] ?? ShieldCheck;
  const dlUrl   = reportsApi.downloadUrl(report.id);

  return (
    <div className="group flex items-center gap-4 rounded-xl border border-gray-800 bg-gray-900 px-5 py-4 hover:border-gray-700 transition-colors">

      {/* Grade badge */}
      <div className={`flex h-12 w-12 flex-shrink-0 flex-col items-center justify-center rounded-xl border text-center font-black ${GRADE_STYLE[grade] ?? GRADE_STYLE["F"]}`}>
        <span className="text-xl leading-none">{grade}</span>
      </div>

      {/* Info */}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-0.5">
          <Icon className="h-3.5 w-3.5 text-gray-500 flex-shrink-0" />
          <p className="truncate text-sm font-semibold text-gray-100">
            {report.metadata.targetName}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[11px] text-gray-500">
          <span>{formatDate(report.generatedAt)}</span>
          {report.metadata.riskScore !== null && (
            <span>Risk: <span className="text-gray-300 font-medium">{report.metadata.riskScore}/100</span></span>
          )}
          <span>{report.metadata.totalFindings} findings</span>
          <span>{report.metadata.scanTypes?.join(", ")}</span>
        </div>
        <div className="mt-1.5">
          <SevBar meta={report.metadata} />
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <a
          href={dlUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 rounded-lg border border-indigo-700/50 bg-indigo-900/30 px-3 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-900/60 transition-colors"
        >
          <Download className="h-3.5 w-3.5" />
          Download HTML
        </a>
        <a
          href={dlUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded-lg border border-gray-700 bg-gray-800 p-1.5 text-gray-500 hover:text-gray-200 transition-colors"
          title="Open in browser"
        >
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
        <button
          onClick={() => onDelete(report.id)}
          className="rounded-lg border border-gray-700 bg-gray-800 p-1.5 text-gray-600 hover:border-red-800 hover:bg-red-900/20 hover:text-red-400 transition-colors"
          title="Delete report"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

// ── AI streaming report (existing) ───────────────────────────────────────────

function renderMarkdown(text: string): React.ReactNode {
  const lines = text.split("\n");
  const nodes: React.ReactNode[] = [];
  let key = 0;

  for (const line of lines) {
    if (!line.trim()) { nodes.push(<div key={key++} className="h-2" />); continue; }
    if (/^## /.test(line)) {
      nodes.push(<h2 key={key++} className="mt-6 mb-2 text-base font-bold text-white border-b border-gray-700 pb-1">{line.slice(3)}</h2>);
      continue;
    }
    if (/^# /.test(line)) {
      nodes.push(<h1 key={key++} className="mt-4 mb-3 text-lg font-bold text-white">{line.slice(2)}</h1>);
      continue;
    }
    if (/^### /.test(line)) {
      nodes.push(<h3 key={key++} className="mt-4 mb-1 text-sm font-semibold text-indigo-300">{line.slice(4)}</h3>);
      continue;
    }
    if (/^\d+\. /.test(line)) {
      const m = line.match(/^(\d+)\. (.+)/);
      if (m) nodes.push(
        <div key={key++} className="flex gap-2 text-sm text-gray-300 my-0.5">
          <span className="flex-shrink-0 font-semibold text-indigo-400 w-5">{m[1]}.</span>
          <span>{inlineMd(m[2])}</span>
        </div>
      );
      continue;
    }
    if (/^[-*] /.test(line)) {
      nodes.push(
        <div key={key++} className="flex gap-2 text-sm text-gray-300 my-0.5">
          <span className="mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-indigo-400" />
          <span>{inlineMd(line.slice(2))}</span>
        </div>
      );
      continue;
    }
    nodes.push(<p key={key++} className="text-sm text-gray-300 leading-relaxed">{inlineMd(line)}</p>);
  }
  return nodes;
}

function inlineMd(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((p, i) => {
    if (/^\*\*(.+)\*\*$/.test(p)) return <strong key={i} className="font-semibold text-white">{p.slice(2, -2)}</strong>;
    if (/^`([^`]+)`$/.test(p)) return <code key={i} className="rounded bg-gray-700 px-1 py-0.5 text-xs font-mono text-indigo-300">{p.slice(1, -1)}</code>;
    return p;
  });
}

function AiReportTab() {
  const [report, setReport]       = useState("");
  const [streaming, setStreaming] = useState(false);
  const [done, setDone]           = useState(false);
  const [copied, setCopied]       = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const generate = useCallback(async () => {
    setReport(""); setDone(false); setStreaming(true);
    abortRef.current = new AbortController();
    try {
      const resp = await fetch("/api/reports/ai-generate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        credentials: "include", signal: abortRef.current.signal,
      });
      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done: d, value } = await reader.read();
        if (d) break;
        for (const line of decoder.decode(value, { stream: true }).split("\n").filter((l) => l.startsWith("data: "))) {
          try {
            const data = JSON.parse(line.slice(6)) as { token?: string; done?: boolean; error?: string };
            if (data.token) setReport((p) => p + data.token);
            if (data.done)  setDone(true);
            if (data.error) { setReport((p) => p + `\n\n⚠️ ${data.error}`); setDone(true); }
          } catch { /* skip */ }
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError")
        setReport((p) => p + "\n\n⚠️ Connection failed. Is Ollama running?");
    } finally { setStreaming(false); }
  }, []);

  const handleReset = () => { abortRef.current?.abort(); setReport(""); setDone(false); setStreaming(false); };
  const handleCopy  = async () => { await navigator.clipboard.writeText(report); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const handleDownload = () => {
    const date = new Date().toISOString().split("T")[0];
    const blob = new Blob([report], { type: "text/markdown" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `breachlens-ai-report-${date}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          Generate a comprehensive AI-written org-wide security assessment — executive summary, top risks, and a remediation roadmap.
        </p>
        <div className="flex items-center gap-2">
          {done && report && (
            <>
              <button onClick={handleCopy}
                className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors">
                {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "Copied!" : "Copy"}
              </button>
              <button onClick={handleDownload}
                className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors">
                <Download className="h-3.5 w-3.5" /> Download .md
              </button>
            </>
          )}
          {(streaming || done) && (
            <button onClick={handleReset}
              className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors">
              <RotateCcw className="h-3.5 w-3.5" /> Reset
            </button>
          )}
        </div>
      </div>

      {!report && !streaming ? (
        <div className="flex flex-col items-center justify-center py-20 gap-6 text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-950 border border-indigo-700">
            <Sparkles className="h-8 w-8 text-indigo-400" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">AI Security Summary</h3>
            <p className="mt-1 text-sm text-gray-400 max-w-sm">Org-wide markdown report covering executive summary, top risks, and remediation roadmap.</p>
          </div>
          <button onClick={generate}
            className="flex items-center gap-2 rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white hover:bg-indigo-500 transition-colors">
            <Sparkles className="h-4 w-4" /> Generate AI Summary
          </button>
        </div>
      ) : (
        <div className="mx-auto w-full max-w-3xl">
          {streaming && (
            <div className="mb-4 flex items-center gap-2 rounded-lg border border-indigo-900/40 bg-indigo-950/20 px-4 py-2.5">
              <Sparkles className="h-3.5 w-3.5 animate-pulse text-indigo-400" />
              <span className="text-xs text-indigo-300">Generating…</span>
              <span className="ml-auto inline-block h-4 w-0.5 bg-indigo-400 animate-pulse" />
            </div>
          )}
          {done && (
            <div className="mb-4 flex items-center gap-2 rounded-lg border border-green-900/40 bg-green-950/20 px-4 py-2">
              <Check className="h-3.5 w-3.5 text-green-400" />
              <span className="text-xs text-green-300">Report complete</span>
            </div>
          )}
          <div className="rounded-xl border border-gray-800 bg-gray-900 px-6 py-5 space-y-1">
            {renderMarkdown(report)}
            {streaming && <span className="inline-block h-4 w-0.5 bg-indigo-400 animate-pulse ml-0.5" />}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Scan Reports tab ──────────────────────────────────────────────────────────

function ScanReportsTab() {
  const qc = useQueryClient();

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: () => reportsApi.list(1, 50),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => reportsApi.delete(id),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const reports = data?.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          HTML reports are generated automatically when a scan completes. Click <strong className="text-gray-300">Download HTML</strong> to save a self-contained file.
        </p>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Grade legend */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-2.5">
        <span className="text-xs text-gray-500 mr-1">Risk grade:</span>
        {[
          { grade: "A", desc: "No critical/high — clean",           style: GRADE_STYLE["A"] },
          { grade: "B", desc: "1–5 high, no critical",              style: GRADE_STYLE["B"] },
          { grade: "C", desc: "1 critical or 6–15 high",            style: GRADE_STYLE["C"] },
          { grade: "D", desc: "2–4 critical or 16–30 high",         style: GRADE_STYLE["D"] },
          { grade: "F", desc: "5+ critical or 30+ high",            style: GRADE_STYLE["F"] },
        ].map(({ grade, desc, style }) => (
          <span
            key={grade}
            title={desc}
            className={`inline-flex h-6 w-6 cursor-default items-center justify-center rounded border text-xs font-black ${style}`}
          >
            {grade}
          </span>
        ))}
        <span className="ml-1 text-[10px] text-gray-600">Hover a grade for details</span>
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <div className="h-7 w-7 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-2 rounded-lg border border-red-900/40 bg-red-950/20 px-4 py-3 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          Failed to load reports. Please refresh.
        </div>
      )}

      {!isLoading && !isError && reports.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gray-800 border border-gray-700">
            <FileText className="h-8 w-8 text-gray-600" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-gray-300">No reports yet</h3>
            <p className="mt-1 text-sm text-gray-500">
              HTML reports are generated automatically when a scan completes.<br />
              Trigger a scan on any target to generate your first report.
            </p>
          </div>
        </div>
      )}

      {reports.length > 0 && (
        <div className="flex flex-col gap-3">
          {reports.map((r) => (
            <ReportCard
              key={r.id}
              report={r}
              onDelete={(id) => deleteMut.mutate(id)}
            />
          ))}
          {data && data.total > reports.length && (
            <p className="text-center text-xs text-gray-600 py-2">
              Showing {reports.length} of {data.total} reports
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = "scan" | "ai";

export default function ReportPage() {
  const [tab, setTab] = useState<Tab>("scan");

  return (
    <div className="flex h-full flex-col bg-gray-950">
      {/* Header */}
      <div className="border-b border-gray-800 px-6 pt-6 pb-0">
        <div className="flex items-center gap-3 mb-5">
          <FileText className="h-5 w-5 text-indigo-400" />
          <h1 className="text-2xl font-bold text-white">Reports</h1>
        </div>

        {/* Tabs */}
        <div className="flex gap-1">
          {([
            { id: "scan", label: "Scan Reports",    icon: ShieldCheck },
            { id: "ai",   label: "AI Summary",      icon: Sparkles    },
          ] as { id: Tab; label: string; icon: React.ElementType }[]).map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={[
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors",
                tab === id
                  ? "border-indigo-500 text-indigo-300"
                  : "border-transparent text-gray-500 hover:text-gray-300",
              ].join(" ")}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-6">
        {tab === "scan" && <ScanReportsTab />}
        {tab === "ai"   && <AiReportTab />}
      </div>
    </div>
  );
}
