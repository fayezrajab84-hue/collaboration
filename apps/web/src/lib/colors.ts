/**
 * Canonical color tokens for the DevSecOps platform UI.
 *
 * All severity, status, and confidence colors are defined once here and
 * imported everywhere else.  Never write inline severity/status color maps
 * in pages or components — add an export here instead.
 *
 * Opacity rules
 * ─────────────
 * • Background pills  : /60 (badge-with-border)  |  /70 (count circles, no border)
 * • Borders on badges : /50
 * • Hover surfaces    : hover:bg-gray-800/40  (all table rows, list items)
 * • Disabled / muted  : /40 background, /40 border
 */

// ── Severity ─────────────────────────────────────────────────────────────────

/**
 * Full pill badge — background + text + border.
 * Used by SeverityBadge, inline group-count tags, FindingDetailDrawer, etc.
 */
export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-900/60    text-red-300    border border-red-700/50",
  HIGH:     "bg-orange-900/60 text-orange-300 border border-orange-700/50",
  MEDIUM:   "bg-amber-900/60  text-amber-300  border border-amber-700/50",
  LOW:      "bg-green-900/60  text-green-300  border border-green-700/50",
  INFO:     "bg-gray-800/60   text-gray-400   border border-gray-700/50",
};

/**
 * Small count circle (no border).
 * Used by FindingCountBadges and SeverityPill (ScansPage).
 */
export const SEVERITY_PILL: Record<string, string> = {
  CRITICAL: "bg-red-950/70    text-red-300",
  HIGH:     "bg-orange-950/70 text-orange-300",
  MEDIUM:   "bg-amber-950/70  text-amber-300",
  LOW:      "bg-green-950/70  text-green-300",
  INFO:     "bg-gray-800/70   text-gray-400",
};

/**
 * Ring-style badge (ChecksTab "severity dot" pill).
 * Background + text + ring-1 class (no border shorthand — uses ring instead).
 */
export const SEVERITY_RING: Record<string, { dot: string; badge: string; label: string }> = {
  CRITICAL: { dot: "bg-red-500",    badge: "bg-red-950/60    text-red-400    ring-red-800/50",    label: "Critical" },
  HIGH:     { dot: "bg-orange-500", badge: "bg-orange-950/60 text-orange-400 ring-orange-800/50", label: "High"     },
  MEDIUM:   { dot: "bg-amber-500",  badge: "bg-amber-950/60  text-amber-400  ring-amber-800/50",  label: "Medium"   },
  LOW:      { dot: "bg-green-500",  badge: "bg-green-950/60  text-green-400  ring-green-800/50",  label: "Low"      },
  INFO:     { dot: "bg-gray-500",   badge: "bg-gray-800/60   text-gray-400   ring-gray-700/50",   label: "Info"     },
};

/**
 * Text-only severity color — for chart labels, mini data tables, bar labels.
 */
export const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-amber-400",
  LOW:      "text-green-400",
  INFO:     "text-gray-400",
};

/**
 * Hex colors for Recharts / charting libraries.
 * Keep in sync with tailwind.config.ts severity theme keys.
 */
export const SEVERITY_CHART: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ea580c",
  MEDIUM:   "#d97706",
  LOW:      "#65a30d",
  INFO:     "#6b7280",
};

// ── Finding status ────────────────────────────────────────────────────────────

/**
 * Full pill badge for FindingStatus (OPEN / ACKNOWLEDGED / FALSE_POSITIVE /
 * FIXED / IGNORED).  Each value is a complete Tailwind class string that can
 * be spread onto the badge element.
 */
export const FINDING_STATUS_BADGE: Record<string, { cls: string; label: string }> = {
  OPEN:           { cls: "bg-gray-800/60    text-gray-300    border border-gray-700/50",    label: "Open"           },
  ACKNOWLEDGED:   { cls: "bg-indigo-950/60  text-indigo-300  border border-indigo-800/50",  label: "Acknowledged"   },
  FALSE_POSITIVE: { cls: "bg-gray-800/40    text-gray-500    border border-gray-700/40",    label: "False Positive" },
  FIXED:          { cls: "bg-green-950/60   text-green-300   border border-green-700/50",   label: "Fixed"          },
  IGNORED:        { cls: "bg-gray-800/40    text-gray-500    border border-gray-700/40",    label: "Ignored"        },
};

// ── Confidence ────────────────────────────────────────────────────────────────

export const CONFIDENCE_BADGE: Record<string, { cls: string; label: string }> = {
  CONFIRMED: { cls: "bg-red-900/40   text-red-300   border border-red-700/50",   label: "Confirmed" },
  LIKELY:    { cls: "bg-amber-900/40 text-amber-300 border border-amber-700/50", label: "Likely"    },
  POSSIBLE:  { cls: "bg-gray-800/40  text-gray-400  border border-gray-700/50",  label: "Possible"  },
};

// ── Scan status ───────────────────────────────────────────────────────────────

export const SCAN_STATUS_BADGE: Record<string, string> = {
  PENDING:   "bg-gray-800    text-gray-400",
  RUNNING:   "bg-indigo-900/60 text-indigo-300",
  COMPLETED: "bg-green-900/60  text-green-300",
  FAILED:    "bg-red-900/60    text-red-300",
  CANCELLED: "bg-gray-800    text-gray-500",
};

// ── Risk score ────────────────────────────────────────────────────────────────

export function riskScoreStyle(score: number) {
  if (score >= 80) return { label: "CRITICAL", ring: "border-red-700/60",    bg: "bg-red-950/60",    text: "text-red-300",    bar: "bg-red-500"    };
  if (score >= 60) return { label: "HIGH",     ring: "border-orange-700/60", bg: "bg-orange-950/60", text: "text-orange-300", bar: "bg-orange-500" };
  if (score >= 35) return { label: "MEDIUM",   ring: "border-amber-700/60",  bg: "bg-amber-950/60",  text: "text-amber-300",  bar: "bg-amber-500"  };
  return               { label: "LOW",      ring: "border-green-700/60",  bg: "bg-green-950/60",  text: "text-green-300",  bar: "bg-green-500"  };
}

// ── Shared surface tokens ─────────────────────────────────────────────────────

/** Standard hover style for ALL table rows and list items. */
export const ROW_HOVER = "hover:bg-gray-800/40";
