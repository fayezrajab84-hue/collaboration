/**
 * Interactive DAST Recording Panel
 *
 * Surfaces the proxy-recorded session lifecycle to the user:
 *   • Start  — provisions a ZAP context, returns proxy host/port + CA download
 *   • Live   — live URL/alert counters (polled every 2s)
 *   • Scan   — runs an active scan against the recorded URLs
 *   • Stop   — tears down the context
 *
 * Browser config: user sets HTTP/HTTPS proxy → 127.0.0.1:8090 and trusts
 * ZAP's CA cert (downloaded from this panel). Then they browse the target.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Square, Radio, Download, AlertCircle, ScanSearch, Copy, Check } from "lucide-react";
import { domainsApi } from "../lib/api";
import { useToast } from "../hooks/useToast";

export default function RecordingPanel({ domainId }: { domainId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showInstructions, setShowInstructions] = useState(false);

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
      void refetch();
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
    },
  });

  const scan = useMutation({
    mutationFn: () => domainsApi.recordingScan(domainId),
    onSuccess: () => {
      toast.success("Scan queued — running against recorded traffic");
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      void refetch();
    },
    onError: (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error || e.message || "Failed to start scan"),
  });

  const isActive   = session?.status === "ACTIVE";
  const isScanning = session?.status === "SCANNING";

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
        (login, click around, exercise forms), then run the active scan against
        only the URLs you visited. Surfaces vulnerabilities the spider can't reach.
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
            <Counter label="Status"         value={session.status}           accent={isScanning ? "violet" : "green"} text />
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

          {/* Actions */}
          <div className="flex items-center justify-end gap-2 border-t border-gray-800 pt-3">
            <button
              onClick={() => stop.mutate()}
              disabled={stop.isPending || isScanning}
              className="flex items-center gap-1.5 rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
              title={isScanning ? "Wait for scan to finish" : "Tear down the recording"}
            >
              <Square className="h-3 w-3" /> Stop Recording
            </button>
            <button
              onClick={() => scan.mutate()}
              disabled={scan.isPending || isScanning || (session.urlCount ?? 0) === 0}
              className="flex items-center gap-1.5 rounded bg-emerald-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
              title={(session.urlCount ?? 0) === 0 ? "Browse the target first to record traffic" : ""}
            >
              <ScanSearch className="h-3 w-3" />
              {isScanning ? "Scanning…" : "Run Recorded Scan"}
            </button>
          </div>

          {isScanning && session.scanJobId && (
            <div className="flex items-center gap-2 rounded border border-violet-700/40 bg-violet-900/10 p-2 text-xs text-violet-300">
              <AlertCircle className="h-3 w-3" />
              Active scan in progress (job <span className="font-mono">{session.scanJobId.slice(-8)}</span>) —
              this can run up to ~30 minutes against the recorded URLs.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Counter({
  label, value, accent, text = false,
}: { label: string; value: string | number; accent: "indigo" | "amber" | "green" | "violet"; text?: boolean }) {
  const accentMap: Record<string, string> = {
    indigo: "text-indigo-300",
    amber:  "text-amber-300",
    green:  "text-emerald-300",
    violet: "text-violet-300",
  };
  return (
    <div className="rounded border border-gray-800 bg-gray-900/60 p-3">
      <div className="text-[10px] uppercase tracking-wider text-gray-500">{label}</div>
      <div className={`mt-1 ${text ? "text-sm font-medium" : "text-xl font-bold"} ${accentMap[accent]}`}>
        {value}
      </div>
    </div>
  );
}

function ProxyInfoCard({ session }: { session: { proxyHost: string; proxyPort: number; caUrl: string; targetUrl: string } }) {
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

function Instructions({ session }: { session: { proxyHost: string; proxyPort: number; targetUrl: string } }) {
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
      <Step n={4} title="Run the recorded scan">
        When you've covered everything you want tested, click{" "}
        <span className="text-gray-200">Run Recorded Scan</span>.
        ZAP will only attack the URLs you visited.
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
