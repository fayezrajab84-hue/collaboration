/**
 * Interactive DAST Recording Panel
 *
 * Surfaces the proxy-recorded session lifecycle to the user:
 *   • Start    — provisions a ZAP context, returns proxy host/port + CA download
 *   • Live     — live URL/alert counters (polled every 2s)
 *   • Scan     — interactive DAST active scan against the recorded URLs (~10 min)
 *   • Promote  — PENTEST_FULL against the same recorded URLs (~25 min)
 *                Surfaces the authenticated attack surface to nuclei / sqlmap
 *                without re-crawling — a journey no competitor offers at this
 *                price point.
 *   • Stop     — tears down the context. Guarded by confirm modal because
 *                it destroys recorded URLs + passive alerts irreversibly.
 *
 * Browser config: user sets HTTP/HTTPS proxy → 127.0.0.1:8090 and trusts
 * ZAP's CA cert (downloaded from this panel). Then they browse the target.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Play, Square, Radio, Download, AlertCircle, ScanSearch, Copy, Check,
  Rocket, ShieldAlert, X,
} from "lucide-react";
import { domainsApi, type RecordingSessionView } from "../lib/api";
import { useToast } from "../hooks/useToast";

export default function RecordingPanel({ domainId }: { domainId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showInstructions, setShowInstructions] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);
  const [confirmPromote, setConfirmPromote] = useState(false);

  // Poll status every 2s when a session is active.
  const { data: session, refetch } = useQuery({
    queryKey: ["recording", domainId],
    queryFn:  () => domainsApi.recordingStatus(domainId),
    refetchInterval: (q) => {
      const s = q.state.data;
      return s && (s.status === "ACTIVE" || s.status === "SCANNING") ? 2_000 : false;
    },
  });

  const start = useMutation({
    mutationFn: () => domainsApi.recordingStart(domainId),
    onSuccess: () => { void refetch(); setShowInstructions(true); },
    onError:   (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error || e.message || "Failed to start recording"),
  });

  const stop = useMutation({
    mutationFn: () => domainsApi.recordingStop(domainId),
    onSuccess: () => {
      setConfirmStop(false);
      void refetch();
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
    },
  });

  const scan = useMutation({
    mutationFn: () => domainsApi.recordingScan(domainId),
    onSuccess: () => {
      toast.success("Recorded scan queued — ZAP active attack on recorded URLs");
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      void refetch();
    },
    onError: (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error || e.message || "Failed to start scan"),
  });

  const promote = useMutation({
    mutationFn: (depth: "STANDARD" | "AGGRESSIVE") => domainsApi.recordingPromote(domainId, depth),
    onSuccess: () => {
      toast.success("Full Pentest queued against recorded URLs");
      setConfirmPromote(false);
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      void refetch();
    },
    onError: (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error || e.message || "Failed to promote scan"),
  });

  const isActive   = session?.status === "ACTIVE";
  const isScanning = session?.status === "SCANNING";
  const hasUrls    = (session?.urlCount ?? 0) > 0;

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className={`h-4 w-4 ${isActive ? "text-red-400 animate-pulse" : "text-gray-600"}`} />
          <h3 className="text-sm font-semibold text-white">Interactive DAST — Recorded Session</h3>
        </div>
        {!session && (
          <button
            onClick={() => start.mutate()}
            disabled={start.isPending}
            className="flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            <Play className="h-3 w-3" /> Start Recording
          </button>
        )}
      </div>

      <p className="mb-3 text-xs text-gray-500">
        Set your browser's proxy to ZAP, browse the application as a real user
        (login, click around, exercise forms), then scan only the URLs you
        visited — either with ZAP's active attack (~10 min) or the full pentest
        toolchain (~25 min). Reaches authenticated surface the crawler can't.
      </p>

      {!session ? (
        <div className="rounded border border-dashed border-gray-700 bg-gray-900/40 p-3 text-xs text-gray-500">
          No active recording. Click <span className="text-gray-300">Start Recording</span> to provision a ZAP context for this domain.
        </div>
      ) : (
        <div className="space-y-3">
          {/* Proxy info card */}
          <ProxyInfoCard session={session} />

          {/* Live counters */}
          <div className="grid grid-cols-3 gap-3">
            <Counter label="URLs Recorded"  value={session.urlCount ?? 0}   accent="indigo" />
            <Counter label="Passive Alerts" value={session.alertCount ?? 0} accent="amber"  />
            <Counter label="Status"         value={session.status}           accent="indigo" text />
          </div>

          {/* Toggleable browser instructions */}
          <div>
            <button
              onClick={() => setShowInstructions((s) => !s)}
              className="text-xs text-indigo-400 hover:text-indigo-300"
            >
              {showInstructions ? "Hide" : "Show"} browser setup instructions
            </button>
            {showInstructions && <Instructions session={session} />}
          </div>

          {/* Two clear CTAs — recorded active scan (fast) or full pentest (deep) */}
          <div className="grid gap-2 border-t border-gray-800 pt-3 sm:grid-cols-2">
            <ScanCta
              icon={<ScanSearch className="h-4 w-4" />}
              title="Run Recorded Scan"
              subtitle="ZAP active attack (~10 min) · XSS, SQLi, traversal"
              onClick={() => scan.mutate()}
              disabled={scan.isPending || isScanning || !hasUrls}
              accent="sky"
              loading={scan.isPending || isScanning}
              disabledReason={!hasUrls ? "Browse the target first to record traffic" : undefined}
            />
            <ScanCta
              icon={<Rocket className="h-4 w-4" />}
              title="Promote to Full Pentest"
              subtitle="nuclei + nikto + testssl (~25 min) · deep coverage"
              onClick={() => setConfirmPromote(true)}
              disabled={promote.isPending || !hasUrls}
              accent="indigo"
              loading={promote.isPending}
              disabledReason={!hasUrls ? "Browse the target first to record traffic" : undefined}
            />
          </div>

          {/* Stop action — destructive, separated */}
          <div className="flex items-center justify-end border-t border-gray-800 pt-2">
            <button
              onClick={() => setConfirmStop(true)}
              disabled={stop.isPending || isScanning}
              className="flex items-center gap-1.5 rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 disabled:opacity-50"
              title={isScanning ? "Wait for scan to finish" : "Tear down the recording (destroys recorded URLs + alerts)"}
            >
              <Square className="h-3 w-3" /> Stop Recording
            </button>
          </div>

          {isScanning && session.scanJobId && (
            <div className="flex items-center gap-2 rounded border border-gray-800 bg-gray-900/60 p-2 text-xs text-gray-400">
              <AlertCircle className="h-3 w-3 flex-none text-gray-500" />
              Active scan in progress (job <span className="font-mono text-gray-300">{session.scanJobId.slice(-8)}</span>) —
              this can run up to ~30 minutes against the recorded URLs.
            </div>
          )}

          {session.promotedScanJobId && (
            <div className="flex items-center gap-2 rounded border border-gray-800 bg-gray-900/60 p-2 text-xs text-gray-400">
              <Rocket className="h-3 w-3 flex-none text-gray-500" />
              Promoted pentest: job <span className="font-mono text-gray-300">{session.promotedScanJobId.slice(-8)}</span>
              {session.promotedScanJobStatus && (
                <span className="text-gray-500">· {session.promotedScanJobStatus}</span>
              )}
            </div>
          )}
        </div>
      )}

      {confirmStop && session && (
        <StopConfirmModal
          urlCount={session.urlCount ?? 0}
          alertCount={session.alertCount ?? 0}
          hasUrls={hasUrls}
          onClose={() => setConfirmStop(false)}
          onRunThenStop={() => { scan.mutate(); setConfirmStop(false); }}
          onConfirmStop={() => stop.mutate()}
          stopPending={stop.isPending}
        />
      )}

      {confirmPromote && session && (
        <PromoteConfirmModal
          urlCount={session.urlCount ?? 0}
          targetUrl={session.targetUrl}
          onClose={() => setConfirmPromote(false)}
          onConfirm={(depth) => promote.mutate(depth)}
          pending={promote.isPending}
        />
      )}
    </div>
  );
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

function ScanCta({
  icon, title, subtitle, onClick, disabled, accent, loading, disabledReason,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  onClick: () => void;
  disabled: boolean;
  accent: "sky" | "indigo";
  loading: boolean;
  disabledReason?: string;
}) {
  // Neutral base + neutral icon at rest; full accent only on hover.
  // Labels + icon shape already distinguish the two CTAs.
  const accentMap: Record<string, string> = {
    sky:    "border-gray-800 bg-gray-900/40 hover:border-sky-700/60 hover:bg-sky-950/30 text-gray-200 hover:text-sky-100",
    indigo: "border-gray-800 bg-gray-900/40 hover:border-indigo-700/60 hover:bg-indigo-950/30 text-gray-200 hover:text-indigo-100",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={disabled && disabledReason ? disabledReason : ""}
      className={`flex flex-col items-start gap-1 rounded border p-3 text-left text-xs transition disabled:opacity-40 disabled:cursor-not-allowed ${accentMap[accent]}`}
    >
      <div className="flex items-center gap-2 font-semibold">
        {icon}
        {loading ? "Queuing…" : title}
      </div>
      <div className="text-[11px] text-gray-500">{subtitle}</div>
    </button>
  );
}

function StopConfirmModal({
  urlCount, alertCount, hasUrls, onClose, onRunThenStop, onConfirmStop, stopPending,
}: {
  urlCount: number;
  alertCount: number;
  hasUrls: boolean;
  onClose: () => void;
  onRunThenStop: () => void;
  onConfirmStop: () => void;
  stopPending: boolean;
}) {
  return (
    <Modal onClose={onClose} title="Stop recording?">
      <div className="space-y-3 text-sm text-gray-300">
        <div className="flex gap-2 rounded border border-amber-700/40 bg-amber-900/10 p-3 text-xs text-amber-200">
          <ShieldAlert className="h-4 w-4 flex-none" />
          <div>
            Stopping tears down the ZAP context. You'll lose{" "}
            <span className="font-mono text-amber-100">{urlCount}</span> recorded URL(s) and{" "}
            <span className="font-mono text-amber-100">{alertCount}</span> passive alert(s).
            This can't be undone.
          </div>
        </div>
        <p className="text-xs text-gray-400">
          If you want to keep the findings, run a scan first — it'll capture the
          alerts as permanent Findings before the context is destroyed.
        </p>
      </div>
      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          onClick={onClose}
          className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
        >
          Cancel
        </button>
        {hasUrls && (
          <button
            onClick={onRunThenStop}
            className="rounded bg-sky-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-600"
          >
            Run scan, then stop later
          </button>
        )}
        <button
          onClick={onConfirmStop}
          disabled={stopPending}
          className="rounded bg-red-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-600 disabled:opacity-50"
        >
          {stopPending ? "Stopping…" : "Stop and discard"}
        </button>
      </div>
    </Modal>
  );
}

function PromoteConfirmModal({
  urlCount, targetUrl, onClose, onConfirm, pending,
}: {
  urlCount: number;
  targetUrl: string;
  onClose: () => void;
  onConfirm: (depth: "STANDARD" | "AGGRESSIVE") => void;
  pending: boolean;
}) {
  const [depth, setDepth] = useState<"STANDARD" | "AGGRESSIVE">("STANDARD");
  const tools = [
    { name: "nuclei",   desc: "CVE & misconfig templates" },
    { name: "nikto",    desc: "web server checks" },
    { name: "testssl",  desc: "TLS posture" },
    { name: "ffuf",     desc: "content discovery" },
    { name: "pentest-checks", desc: "CORS, SSRF, IDOR, SSTI, rate-limit" },
  ];
  if (depth === "AGGRESSIVE") {
    tools.push({ name: "sqlmap",   desc: "SQL injection exploit" });
    tools.push({ name: "xsstrike", desc: "XSS exploit" });
    tools.push({ name: "dalfox",   desc: "XSS exploit" });
  }
  return (
    <Modal onClose={onClose} title="Promote recording to Full Pentest?">
      <div className="space-y-3 text-sm text-gray-300">
        <p className="text-xs text-gray-400">
          Instead of re-crawling, the pentest toolchain will attack the{" "}
          <span className="font-mono text-indigo-300">{urlCount}</span> URL(s)
          you already recorded at{" "}
          <span className="font-mono text-indigo-300">{targetUrl}</span>.
          Your recording session stays live.
        </p>

        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-gray-500">Tools</div>
          <div className="flex flex-wrap gap-1.5">
            {tools.map((t) => (
              <span key={t.name} className="rounded border border-indigo-700/40 bg-indigo-900/20 px-2 py-0.5 text-[11px] text-indigo-200" title={t.desc}>
                {t.name}
              </span>
            ))}
          </div>
        </div>

        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-gray-500">Depth</div>
          <div className="flex gap-2">
            <DepthOption
              label="Standard"
              desc="Passive tests only (~25 min)"
              active={depth === "STANDARD"}
              onClick={() => setDepth("STANDARD")}
            />
            <DepthOption
              label="Aggressive"
              desc="+ SQLMap, XSStrike (~45 min)"
              active={depth === "AGGRESSIVE"}
              onClick={() => setDepth("AGGRESSIVE")}
            />
          </div>
        </div>

        {depth === "AGGRESSIVE" && (
          <div className="flex gap-2 rounded border border-gray-800 bg-gray-900/40 p-2 text-xs text-gray-400">
            <ShieldAlert className="h-4 w-4 flex-none text-gray-500" />
            <div>
              Aggressive mode runs real exploit tooling. Only use it against
              targets you own or have explicit authorization to test.
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          onClick={onClose}
          className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
        >
          Cancel
        </button>
        <button
          onClick={() => onConfirm(depth)}
          disabled={pending}
          className="flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
        >
          <Rocket className="h-3 w-3" />
          {pending ? "Queuing…" : "Start Full Pentest"}
        </button>
      </div>
    </Modal>
  );
}

function DepthOption({
  label, desc, active, onClick,
}: { label: string; desc: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 rounded border p-2 text-left text-xs transition ${
        active
          ? "border-indigo-600 bg-indigo-900/20 text-indigo-100"
          : "border-gray-700 bg-gray-900/40 text-gray-400 hover:bg-gray-800"
      }`}
    >
      <div className="font-semibold">{label}</div>
      <div className="text-[10px] opacity-80">{desc}</div>
    </button>
  );
}

function Modal({
  title, onClose, children,
}: { title: string; onClose: () => void; children: React.ReactNode }) {
  // Close on Esc for keyboard users.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-lg border border-gray-800 bg-gray-950 p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-base font-semibold text-white">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function Counter({
  label, value, accent, text = false,
}: { label: string; value: string | number; accent: "indigo" | "amber" | "green"; text?: boolean }) {
  // Numeric counters read as gray-100 — the size already conveys importance,
  // colour there is just noise. The text-status field uses indigo to stay on
  // theme, regardless of the state.
  void accent; // retained in the type for callers that still pass "green"/"amber"
  const valueClass = text ? "text-sm font-medium text-indigo-300" : "text-xl font-bold text-gray-100";
  return (
    <div className="rounded border border-gray-800 bg-gray-900/60 p-3">
      <div className="text-[10px] uppercase tracking-wider text-gray-500">{label}</div>
      <div className={`mt-1 ${valueClass}`}>{value}</div>
    </div>
  );
}

function ProxyInfoCard({ session }: { session: RecordingSessionView }) {
  const [copied, setCopied] = useState<string | null>(null);

  const proxy = `${session.proxyHost}:${session.proxyPort}`;
  const copy = (label: string, val: string) => {
    void navigator.clipboard.writeText(val);
    setCopied(label);
    setTimeout(() => setCopied((c) => (c === label ? null : c)), 1200);
  };

  return (
    <div className="space-y-2 rounded border border-indigo-700/30 bg-indigo-900/10 p-3 text-xs">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-gray-500">Proxy:</span>{" "}
          <span className="font-mono text-indigo-200">{proxy}</span>
        </div>
        <button onClick={() => copy("proxy", proxy)} className="text-gray-500 hover:text-gray-300">
          {copied === "proxy" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
        </button>
      </div>
      <div className="flex items-center justify-between">
        <div>
          <span className="text-gray-500">Target:</span>{" "}
          <span className="font-mono text-indigo-200">{session.targetUrl}</span>
        </div>
        <button onClick={() => copy("target", session.targetUrl)} className="text-gray-500 hover:text-gray-300">
          {copied === "target" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
        </button>
      </div>
      <div className="pt-1">
        <a
          href={session.caUrl}
          download="zap-root-ca.cer"
          className="inline-flex items-center gap-1.5 text-indigo-400 hover:text-indigo-300"
        >
          <Download className="h-3 w-3" /> Download ZAP root CA (install to inspect HTTPS)
        </a>
      </div>
    </div>
  );
}

function Instructions({ session }: { session: RecordingSessionView }) {
  return (
    <div className="mt-2 space-y-3 rounded border border-gray-800 bg-gray-950/60 p-3 text-xs text-gray-400">
      <Step n={1} title="Install the ZAP root CA">
        Download the cert above and add it to your browser's trusted authorities
        (Firefox: <span className="text-gray-300">Settings → Privacy → View Certificates → Import</span>).
        Without this, HTTPS sites show certificate errors.
      </Step>
      <Step n={2} title="Configure your browser proxy">
        Point HTTP and HTTPS through{" "}
        <span className="font-mono text-indigo-300">{session.proxyHost}:{session.proxyPort}</span>.
        We recommend a separate Firefox profile so your normal browsing isn't affected.
      </Step>
      <Step n={3} title="Browse the target">
        Open <span className="font-mono text-indigo-300">{session.targetUrl}</span>{" "}
        and exercise the application — log in, click links, submit forms.
        The URL counter above updates live as ZAP records traffic.
      </Step>
      <Step n={4} title="Run the recorded scan or promote to pentest">
        When you've covered everything you want tested, pick the depth:
        <span className="text-emerald-300"> Run Recorded Scan</span> for a fast
        ZAP active attack, or <span className="text-indigo-300">Promote to
        Full Pentest</span> for nuclei + nikto + testssl against the same URLs.
      </Step>
      <details className="rounded border border-gray-800 bg-gray-900/40 p-2">
        <summary className="cursor-pointer text-gray-300">Quick test from a terminal (curl)</summary>
        <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-[11px] text-gray-300">
{`# Verify proxy reaches ZAP and a request is recorded:
curl -x http://${session.proxyHost}:${session.proxyPort} ${session.targetUrl} -k`}
        </pre>
      </details>
    </div>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <div className="flex h-5 w-5 flex-none items-center justify-center rounded-full bg-indigo-700 text-[10px] font-bold text-white">
        {n}
      </div>
      <div>
        <div className="font-medium text-gray-200">{title}</div>
        <div className="mt-0.5">{children}</div>
      </div>
    </div>
  );
}
