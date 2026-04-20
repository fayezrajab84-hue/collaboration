import { useState, useRef, useCallback } from "react";
import { FileText, Sparkles, RotateCcw, Copy, Download, Check } from "lucide-react";

// ── Lightweight markdown renderer (reuses the same approach as ChatPage) ──────

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
          <span>{inline(m[2])}</span>
        </div>
      );
      continue;
    }
    if (/^[-*] /.test(line)) {
      nodes.push(
        <div key={key++} className="flex gap-2 text-sm text-gray-300 my-0.5">
          <span className="mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-indigo-400" />
          <span>{inline(line.slice(2))}</span>
        </div>
      );
      continue;
    }
    if (/^\|/.test(line)) {
      // Table row — render as monospace
      nodes.push(<pre key={key++} className="text-xs text-gray-400 font-mono">{line}</pre>);
      continue;
    }
    nodes.push(<p key={key++} className="text-sm text-gray-300 leading-relaxed">{inline(line)}</p>);
  }
  return nodes;
}

function inline(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((p, i) => {
    if (/^\*\*(.+)\*\*$/.test(p)) return <strong key={i} className="font-semibold text-white">{p.slice(2, -2)}</strong>;
    if (/^`([^`]+)`$/.test(p)) return <code key={i} className="rounded bg-gray-700 px-1 py-0.5 text-xs font-mono text-indigo-300">{p.slice(1, -1)}</code>;
    return p;
  });
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ReportPage() {
  const [report, setReport]       = useState("");
  const [streaming, setStreaming] = useState(false);
  const [done, setDone]           = useState(false);
  const [copied, setCopied]       = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const generate = useCallback(async () => {
    setReport("");
    setDone(false);
    setStreaming(true);

    abortRef.current = new AbortController();

    try {
      const resp = await fetch("/api/reports/generate", {
        method:      "POST",
        headers:     { "Content-Type": "application/json" },
        credentials: "include",
        signal:      abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`);

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done: d, value } = await reader.read();
        if (d) break;

        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split("\n").filter((l) => l.startsWith("data: "))) {
          try {
            const data = JSON.parse(line.slice(6)) as { token?: string; done?: boolean; error?: string };
            if (data.token) setReport((prev) => prev + data.token);
            if (data.done)  { setDone(true); }
            if (data.error) { setReport((prev) => prev + `\n\n⚠️ ${data.error}`); setDone(true); }
          } catch { /* skip */ }
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setReport((prev) => prev + "\n\n⚠️ Connection failed. Is Ollama running?");
      }
    } finally {
      setStreaming(false);
    }
  }, []);

  const handleReset = () => {
    abortRef.current?.abort();
    setReport("");
    setDone(false);
    setStreaming(false);
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const date = new Date().toISOString().split("T")[0];
    const blob = new Blob([report], { type: "text/markdown" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `breachlens-security-report-${date}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full flex-col bg-gray-950">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
        <div className="flex items-center gap-3">
          <FileText className="h-5 w-5 text-indigo-400" />
          <h1 className="text-3xl font-bold text-white">Security Report</h1>
        </div>
        <div className="flex items-center gap-2">
          {done && report && (
            <>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "Copied!" : "Copy"}
              </button>
              <button
                onClick={handleDownload}
                className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
              >
                <Download className="h-3.5 w-3.5" />
                Download .md
              </button>
            </>
          )}
          {(streaming || done) && (
            <button
              onClick={handleReset}
              className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-6">
        {!report && !streaming ? (
          /* Landing state */
          <div className="flex flex-col items-center justify-center h-full gap-6 text-center">
            <div className="flex h-20 w-20 items-center justify-center rounded-2xl bg-indigo-950 border border-indigo-700 shadow-xl shadow-indigo-950/50">
              <FileText className="h-9 w-9 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">AI Security Report</h2>
              <p className="mt-1.5 text-sm text-gray-400 max-w-md">
                Generate a comprehensive markdown report covering your org's security posture —
                executive summary, finding breakdown, top risks, and a remediation roadmap.
              </p>
            </div>
            <div className="flex flex-wrap justify-center gap-2 text-xs text-gray-500">
              {["Executive Summary", "Finding Overview", "Top Risks", "Remediation Roadmap"].map((s) => (
                <span key={s} className="rounded-full border border-gray-700 px-3 py-1">{s}</span>
              ))}
            </div>
            <button
              onClick={generate}
              className="flex items-center gap-2 rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white hover:bg-indigo-500 transition-colors shadow-lg shadow-indigo-900/40"
            >
              <Sparkles className="h-4 w-4" />
              Generate Report
            </button>
          </div>
        ) : (
          /* Report content */
          <div className="mx-auto max-w-3xl">
            {/* Status bar */}
            {streaming && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-indigo-900/40 bg-indigo-950/20 px-4 py-2.5">
                <Sparkles className="h-3.5 w-3.5 animate-pulse text-indigo-400" />
                <span className="text-xs text-indigo-300">Generating report…</span>
                <span className="ml-auto inline-block h-4 w-0.5 bg-indigo-400 animate-pulse" />
              </div>
            )}
            {done && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-green-900/40 bg-green-950/20 px-4 py-2">
                <Check className="h-3.5 w-3.5 text-green-400" />
                <span className="text-xs text-green-300">Report complete — use Copy or Download above</span>
              </div>
            )}

            {/* Rendered markdown */}
            <div className="rounded-xl border border-gray-800 bg-gray-900 px-6 py-5 space-y-1">
              {renderMarkdown(report)}
              {streaming && (
                <span className="inline-block h-4 w-0.5 bg-indigo-400 animate-pulse ml-0.5" />
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
