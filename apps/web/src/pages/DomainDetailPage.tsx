/**
 * DomainDetailPage — single-domain "command center" replacing the
 * config-chip-cluttered list row.
 *
 * Layout (Burp-Suite-style, persistent left rail):
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │ ← All domains                                                │
 *   │ dvwa                                            [HIGH] [78]  │
 *   │                                                              │
 *   │ ┌─ Run a scan ──────────────────────────────────────────┐  │
 *   │ │ Fast ─●──── Standard ──── Deep                         │  │
 *   │ │ [ Run Scan ]                                            │  │
 *   │ └─────────────────────────────────────────────────────────┘  │
 *   │                                                              │
 *   │ ┌──────────────┬──────────────────────────────────────────┐ │
 *   │ │ ⌐ URLs (122) │ Tabs: Overview · Recording · Auth & Spec │ │
 *   │ │ ▾ http://dvwa│      · Settings                          │ │
 *   │ │   📁 docs    │ {tab content}                            │ │
 *   │ │   📄 index   │                                          │ │
 *   │ └──────────────┴──────────────────────────────────────────┘ │
 *   └──────────────────────────────────────────────────────────────┘
 *
 * The URL tree as a left rail (not an inline expander) gives the
 * operator the recorded attack surface as a constant reference while
 * they read scan results in the right pane — same mental model as a
 * file explorer in an IDE or Burp's Site Map. The rail collapses to
 * an icon-only strip when the operator wants more horizontal room.
 *
 * Tab content was moved from the row-level inline panels into here
 * so the tabs read as "what this domain has", not "what verbose
 * config did the operator turn on per-row".
 */
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, ChevronLeft, ChevronRight, Pencil, Trash2, Globe,
  Radio, Lock, FileJson, Layers, Activity, AlertCircle,
} from "lucide-react";
import { domainsApi } from "../lib/api";
import ScanSpeedSlider, { type ScanSpeed } from "../components/ScanSpeedSlider";
import DomainUrlsPanel from "../components/DomainUrlsPanel";
import DomainAuthPanel from "../components/DomainAuthPanel";
import DomainApiSpecPanel from "../components/DomainApiSpecPanel";
import RecordingPanel from "../components/RecordingPanel";
import { DomainAssetLinksPanel } from "../components/AssetLinksPanel";
import ApplicationPickerPanel from "../components/ApplicationPickerPanel";
import RiskScoreBadge from "../components/RiskScoreBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import ScanStatusBadge from "../components/ScanStatusBadge";
import Can from "../components/Can";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";

type DetailTab = "overview" | "recording" | "auth" | "settings";

const TABS: { key: DetailTab; label: string; icon: typeof Activity }[] = [
  { key: "overview",  label: "Overview",     icon: Layers   },
  { key: "recording", label: "Recording",    icon: Radio    },
  { key: "auth",      label: "Auth & Spec",  icon: Lock     },
  { key: "settings",  label: "Settings",     icon: Activity },
];

export default function DomainDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();

  const [tab, setTab]               = useState<DetailTab>("overview");
  const [speed, setSpeed]           = useState<ScanSpeed>("STANDARD");
  const [railOpen, setRailOpen]     = useState(true);

  const { data: domain, isLoading } = useQuery({
    queryKey: ["domain", id],
    queryFn:  () => domainsApi.get(id!),
    enabled:  !!id,
  });

  const { status, isActive, latestScan } = useTargetScanStatus(id ?? "");

  // While a scan is running, the slider should reflect WHAT'S RUNNING,
  // not whatever the operator last clicked. Otherwise the screenshot
  // confusion happens: operator clicks "Run Deep", slider snaps back to
  // the React state default ("STANDARD"), and the page reads as if a
  // Standard scan is in progress when it's actually Deep.
  //
  // Mapping:
  //   active scan is DAST            → slider shows FAST
  //   active scan is PENTEST_FULL    → slider shows STANDARD or DEEP
  //                                     based on Domain.pentestDepth
  //                                     (updated on /pentest trigger)
  //   no active scan                 → operator's last selection
  const runningSpeed: ScanSpeed | null = useMemo(() => {
    if (!isActive || !latestScan) return null;
    if (latestScan.scanTypes.includes("PENTEST_FULL")) {
      return domain?.pentestDepth === "AGGRESSIVE" ? "DEEP" : "STANDARD";
    }
    if (latestScan.scanTypes.includes("DAST")) return "FAST";
    return null;
  }, [isActive, latestScan, domain?.pentestDepth]);

  // When a scan kicks off, snap the slider to match. After the scan
  // ends (`isActive` flips false) we leave the slider where it is so
  // the operator can re-trigger the same speed without re-clicking the
  // stop. They can always move it themselves to pick a different one.
  useEffect(() => {
    if (runningSpeed && runningSpeed !== speed) setSpeed(runningSpeed);
  }, [runningSpeed]); // eslint-disable-line react-hooks/exhaustive-deps

  const [showAuthGate, setShowAuthGate] = useState(false);

  // ── Slider → API call. The 3 stops collapse to 2 different APIs;
  // the slider hides this so the operator never sees DAST vs PENTEST_FULL.
  //
  // Standard/Deep route through /api/domains/:id/pentest, which enforces:
  //   1. Body Zod check: { authorized: literal(true) }   — explicit consent
  //      to run an active attack (legal gate; never auto-true on the wire).
  //   2. DB check: domain.authorized = true               — operator has
  //      already accepted the platform-level authorization for this domain.
  //
  // For unauthorized domains we show a one-time confirmation modal that
  // flips the DB flag via /authorize before triggering. After that, future
  // scans against the same domain skip the modal.
  const runScan = useMutation({
    mutationFn: async () => {
      if (!id) throw new Error("No domain id");
      if (speed === "FAST") {
        return domainsApi.triggerScan(id);
      }
      const depth = speed === "DEEP" ? "AGGRESSIVE" : "STANDARD";
      // Pass authorized:true on the wire; the server still rejects if the
      // domain row isn't authorized, so this isn't a backdoor — just the
      // contract that the Zod schema requires.
      return domainsApi.triggerPentest(id, { depth, authorized: true });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      qc.invalidateQueries({ queryKey: ["domain", id] });
      toast.success(
        speed === "FAST"     ? "Fast scan queued (~10 min)" :
        speed === "STANDARD" ? "Standard scan queued (~25 min)" :
                               "Deep scan queued (~45 min)",
      );
    },
    onError: (err: Error) => toast.error(err.message || "Failed to queue scan"),
  });

  // Authorize-then-scan flow for unauthorized domains. On success the
  // domain.authorized flag is persisted, so subsequent scans skip the
  // modal entirely.
  const authorizeAndScan = useMutation({
    mutationFn: async () => {
      if (!id) throw new Error("No domain id");
      await domainsApi.authorize(id, { confirmed: true });
      const depth = speed === "DEEP" ? "AGGRESSIVE" : "STANDARD";
      return domainsApi.triggerPentest(id, { depth, authorized: true });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      qc.invalidateQueries({ queryKey: ["domain", id] });
      setShowAuthGate(false);
      toast.success(
        speed === "STANDARD" ? "Standard scan queued (~25 min)" :
                               "Deep scan queued (~45 min)",
      );
    },
    onError: (err: Error) => toast.error(err.message || "Failed to authorize + queue scan"),
  });

  function handleRunClick() {
    if (!domain) return;
    // Fast scan never needs authorization (passive ZAP DAST is always allowed).
    if (speed === "FAST") {
      runScan.mutate();
      return;
    }
    // Standard / Deep need the domain to be authorized in DB. Show the
    // gate when it isn't; otherwise just trigger.
    if (!domain.authorized) {
      setShowAuthGate(true);
      return;
    }
    runScan.mutate();
  }

  const remove = useMutation({
    mutationFn: () => domainsApi.delete(id!),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["domains"] });
      toast.success("Domain removed");
      navigate("/domains");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to delete"),
  });

  if (isLoading) return <div className="p-6 text-gray-500">Loading…</div>;
  if (!domain) {
    return (
      <div className="p-6">
        <Link to="/domains" className="text-sm text-gray-500 hover:text-gray-300">← All domains</Link>
        <p className="mt-3 text-base text-gray-300">Domain not found.</p>
      </div>
    );
  }

  // Display the active running scan as a pill near the title — operators
  // pop over here from the Scans page when something is mid-flight, and
  // the running indicator is the most decision-relevant fact at the top.
  const displayStatus = status && status !== "COMPLETED" ? status : null;

  return (
    <div className="p-6">
      <Link
        to="/domains"
        className="mb-3 inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-300"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> All domains
      </Link>

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <Globe className="h-6 w-6 flex-shrink-0 text-indigo-400" />
            <h1 className="text-2xl font-bold text-white">{domain.domain}</h1>
            {displayStatus && <ScanStatusBadge status={displayStatus} />}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-gray-400">
            <span>
              Last scan: {domain.lastScannedAt ? formatRelative(domain.lastScannedAt) : "Never"}
            </span>
            <span>·</span>
            <FindingCountBadges
              counts={domain.findingCounts}
              targetType="domain"
              targetId={domain.id}
            />
            <span>·</span>
            <RiskScoreBadge score={domain.aiRiskScore} reason={domain.aiRiskReason} />
          </div>
        </div>
        <Can role="ADMIN">
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const next = prompt("Rename domain to:", domain.domain);
                if (next && next !== domain.domain) {
                  domainsApi.update(domain.id, { domain: next })
                    .then(() => qc.invalidateQueries({ queryKey: ["domain", id] }));
                }
              }}
              className="inline-flex items-center gap-1 rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700"
            >
              <Pencil className="h-3 w-3" /> Rename
            </button>
            <button
              onClick={() => {
                if (confirm(`Remove "${domain.domain}"? Findings stay; the domain row is deleted.`)) {
                  remove.mutate();
                }
              }}
              className="inline-flex items-center gap-1 rounded border border-red-800 bg-red-950/30 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/40"
            >
              <Trash2 className="h-3 w-3" /> Delete
            </button>
          </div>
        </Can>
      </div>

      {/* ── Scan launcher ──────────────────────────────────────────── */}
      <div className="mb-5">
        <ScanSpeedSlider
          value={speed}
          onChange={setSpeed}
          onRun={handleRunClick}
          isRunning={runScan.isPending || authorizeAndScan.isPending || isActive}
          inFlightLabel={isActive ? "Scan in progress…" : "Queuing…"}
        />
      </div>

      {/* Authorization gate — only renders when the operator clicks Run on
          a Standard/Deep scan against a not-yet-authorized domain. Mirrors
          the existing PentestWizard's confirmation step but inline. */}
      {showAuthGate && domain && (
        <AuthorizeAndRunModal
          domain={domain.domain}
          speed={speed}
          isPending={authorizeAndScan.isPending}
          onCancel={() => setShowAuthGate(false)}
          onConfirm={() => authorizeAndScan.mutate()}
        />
      )}

      {/* ── Two-column body: URL rail + tabbed content ────────────── */}
      <div className="grid gap-4" style={{
        gridTemplateColumns: railOpen ? "320px minmax(0, 1fr)" : "44px minmax(0, 1fr)",
        transition: "grid-template-columns 200ms ease",
      }}>
        {/* Left rail */}
        <aside className="rounded-xl border border-gray-800 bg-gray-900/40">
          <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2.5">
            {railOpen ? (
              <>
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                  Site Map
                </span>
                <button
                  onClick={() => setRailOpen(false)}
                  className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
                  title="Collapse rail"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </button>
              </>
            ) : (
              <button
                onClick={() => setRailOpen(true)}
                className="mx-auto rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
                title="Expand site map"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          {railOpen ? (
            <div className="p-2">
              <DomainUrlsPanel domainId={domain.id} embedded />
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3 py-3 text-gray-600">
              <Globe className="h-4 w-4" />
            </div>
          )}
        </aside>

        {/* Right pane */}
        <main className="rounded-xl border border-gray-800 bg-gray-900/40">
          {/* Tabs */}
          <div className="flex flex-wrap gap-1 border-b border-gray-800 px-3 pt-2">
            {TABS.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`flex items-center gap-2 rounded-t px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  tab === key
                    ? "border-indigo-500 text-white"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>

          <div className="p-5">
            {tab === "overview" && <OverviewTab domainId={domain.id} />}
            {tab === "recording" && <RecordingPanel domainId={domain.id} />}
            {tab === "auth" && (
              <div className="space-y-5">
                <DomainAuthPanel    domainId={domain.id} />
                <DomainApiSpecPanel domainId={domain.id} />
              </div>
            )}
            {tab === "settings" && (
              <div className="space-y-4">
                <ApplicationPickerPanel
                  kind="domain"
                  resourceId={domain.id}
                  currentApplicationId={domain.applicationId}
                />
                <DomainAssetLinksPanel domain={domain} />
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

/**
 * AuthorizeAndRunModal — one-time gate before running an active attack
 * scan against a not-yet-authorized domain. Captures explicit "I'm
 * authorized to test this" consent (legal-cover requirement) and
 * persists the flag so future scans skip the modal.
 */
function AuthorizeAndRunModal({
  domain, speed, isPending, onCancel, onConfirm,
}: {
  domain:     string;
  speed:      ScanSpeed;
  isPending:  boolean;
  onCancel:   () => void;
  onConfirm:  () => void;
}) {
  const [agreed, setAgreed] = useState(false);
  const speedLabel = speed === "DEEP" ? "Deep" : "Standard";
  const includesActive = speed === "DEEP";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-xl border border-amber-800 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-start gap-3">
          <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-400" />
          <div>
            <h2 className="text-base font-semibold text-white">Authorize {speedLabel} Scan</h2>
            <p className="mt-1 text-xs text-gray-400">
              You're about to run a {speedLabel} scan against{" "}
              <span className="font-mono text-gray-200">{domain}</span>.
              {includesActive
                ? " This includes active exploitation (sqlmap, xsstrike, dalfox, OWASP Top 10 modules)."
                : " This includes nuclei + nikto + testssl + targeted OWASP checks against your endpoints."}
            </p>
          </div>
        </div>

        <div className="mb-4 rounded-md border border-amber-900/40 bg-amber-950/20 p-3 text-xs text-amber-200">
          Active scanning without authorization may violate computer-misuse laws
          and your hosting provider's terms of service. Only proceed if you own
          this domain or have explicit written permission to test it.
        </div>

        <label className="flex cursor-pointer items-start gap-2 rounded-md border border-gray-800 bg-gray-950/40 px-3 py-2.5">
          <input
            type="checkbox"
            checked={agreed}
            onChange={(e) => setAgreed(e.target.checked)}
            className="mt-0.5 h-4 w-4 cursor-pointer accent-indigo-500"
          />
          <span className="text-xs text-gray-300">
            I confirm I am authorized to perform security testing against{" "}
            <span className="font-mono text-gray-200">{domain}</span>.
          </span>
        </label>

        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={isPending}
            className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!agreed || isPending}
            className={`rounded px-4 py-1.5 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50 ${
              // Match the slider's monochromatic indigo intensity scale —
              // brighter button for the more intense scan.
              speed === "DEEP"
                ? "bg-indigo-500 hover:bg-indigo-400"
                : "bg-indigo-700 hover:bg-indigo-600"
            }`}
          >
            {isPending ? "Authorizing…" : `Authorize and Run ${speedLabel}`}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Overview tab — a thin "what's the state of this domain" summary so
 * the tab pane isn't empty when the operator first lands. Most of the
 * juicy data lives on the Findings + Scans pages already; we just point
 * there.
 */
function OverviewTab({ domainId }: { domainId: string }) {
  return (
    <div className="space-y-4 text-sm text-gray-300">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <div className="mb-2 flex items-center gap-2 text-gray-200">
            <AlertCircle className="h-4 w-4 text-amber-400" />
            <span className="font-semibold">Findings for this domain</span>
          </div>
          <p className="mb-3 text-xs text-gray-500">
            Scoped to this single domain across DAST and Pentest scans.
          </p>
          <Link
            to={`/findings?targetType=DOMAIN&targetId=${domainId}`}
            className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
          >
            View findings →
          </Link>
        </div>
        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <div className="mb-2 flex items-center gap-2 text-gray-200">
            <Layers className="h-4 w-4 text-indigo-400" />
            <span className="font-semibold">Scan history</span>
          </div>
          <p className="mb-3 text-xs text-gray-500">
            Every scan run against this domain, with status and findings count.
          </p>
          <Link
            to={`/scans?targetType=DOMAIN&targetId=${domainId}`}
            className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
          >
            View scans →
          </Link>
        </div>
      </div>
      <div className="rounded-lg border border-indigo-900/30 bg-indigo-950/10 p-4 text-xs text-indigo-200">
        <p className="font-semibold">Tip</p>
        <p className="mt-1 text-indigo-300/80">
          Run a <span className="text-indigo-200">Standard</span> scan first to
          map the attack surface, then go <span className="text-rose-300">Deep</span>{" "}
          on domains where Standard surfaced HIGH/CRITICAL findings — saves you
          ~30 minutes vs running Deep on every domain.
        </p>
      </div>
    </div>
  );
}
