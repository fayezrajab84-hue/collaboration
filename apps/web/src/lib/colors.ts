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
// Unified severity palette — matches the toned-down HTML report template.
// LOW switched from green → sky so it no longer clashes with Fixed/Clean greens.
// Depths bumped to `-950/40` and text to `-400` so the badge reads as a muted
// accent instead of a saturated pill; borders dropped to `-800/40` for less
// visual weight. Used by direct token consumers (Findings groups sample list,
// FindingDetailDrawer). The main SeverityBadge component uses a separate
// neutral-chip-with-dot style (see components/SeverityBadge.tsx).
export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-950/40    text-red-400    border border-red-800/40",
  HIGH:     "bg-orange-950/40 text-orange-400 border border-orange-800/40",
  MEDIUM:   "bg-amber-950/40  text-amber-400  border border-amber-800/40",
  LOW:      "bg-sky-950/40    text-sky-400    border border-sky-800/40",
  INFO:     "bg-gray-800/40   text-gray-400   border border-gray-700/40",
};

/**
 * Small count circle (no border).
 * Used by FindingCountBadges and SeverityPill (ScansPage).
 */
export const SEVERITY_PILL: Record<string, string> = {
  CRITICAL: "bg-red-950/70    text-red-300",
  HIGH:     "bg-orange-950/70 text-orange-300",
  MEDIUM:   "bg-amber-950/70  text-amber-300",
  LOW:      "bg-sky-950/70    text-sky-300",
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
  LOW:      { dot: "bg-sky-500",    badge: "bg-sky-950/60    text-sky-400    ring-sky-800/50",    label: "Low"      },
  INFO:     { dot: "bg-gray-500",   badge: "bg-gray-800/60   text-gray-400   ring-gray-700/50",   label: "Info"     },
};

/**
 * Text-only severity color — for chart labels, mini data tables, bar labels.
 */
export const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-amber-400",
  LOW:      "text-sky-400",
  INFO:     "text-gray-400",
};

/**
 * Hex colors for Recharts / charting libraries.
 * Keep in sync with tailwind.config.ts severity theme keys.
 */
// Hex palette — kept in sync with the HTML report template (reportHtmlService)
// and with Tailwind severity classes above. Muted deeper tones instead of
// neon reds/oranges so charts don't overwhelm the page.
export const SEVERITY_CHART: Record<string, string> = {
  CRITICAL: "#b91c1c",  // red-700
  HIGH:     "#c2410c",  // orange-700
  MEDIUM:   "#a16207",  // yellow-700 (muted amber)
  LOW:      "#0369a1",  // sky-700
  INFO:     "#64748b",  // slate-500
};

// ── Finding status ────────────────────────────────────────────────────────────

/**
 * Full pill badge for FindingStatus (OPEN / ACKNOWLEDGED / FALSE_POSITIVE /
 * FIXED / IGNORED).  Each value is a complete Tailwind class string that can
 * be spread onto the badge element.
 */
// FIXED / COMPLETED moved off warm emerald onto cool teal — the emerald was
// the only warm hue in an otherwise cool scheme (indigo / slate / blue / teal
// / sky) and stood out uncomfortably. Teal matches the Domain target icon
// and sits naturally alongside the rest of the palette.
export const FINDING_STATUS_BADGE: Record<string, { cls: string; label: string }> = {
  OPEN:           { cls: "bg-gray-800/60    text-gray-300    border border-gray-700/50",    label: "Open"           },
  ACKNOWLEDGED:   { cls: "bg-indigo-950/60  text-indigo-300  border border-indigo-800/50",  label: "Acknowledged"   },
  FALSE_POSITIVE: { cls: "bg-gray-800/40    text-gray-500    border border-gray-700/40",    label: "False Positive" },
  FIXED:          { cls: "bg-teal-950/40    text-teal-400    border border-teal-800/40",    label: "Fixed"          },
  IGNORED:        { cls: "bg-gray-800/40    text-gray-500    border border-gray-700/40",    label: "Ignored"        },
};

// ── Confidence ────────────────────────────────────────────────────────────────

// Confidence is secondary metadata — keep it muted so it doesn't compete
// with the severity badge in the same row. Slightly tinted text only.
export const CONFIDENCE_BADGE: Record<string, { cls: string; label: string }> = {
  CONFIRMED: { cls: "bg-gray-800/60  text-red-300/90    border border-gray-700/50", label: "Confirmed" },
  LIKELY:    { cls: "bg-gray-800/60  text-amber-300/90  border border-gray-700/50", label: "Likely"    },
  POSSIBLE:  { cls: "bg-gray-800/40  text-gray-400      border border-gray-700/50", label: "Possible"  },
};

// ── Scan status ───────────────────────────────────────────────────────────────

// Scan status — Completed uses a neutral slate chip so finished scans recede
// into the background (they're the "default good" state and don't need to
// shout). Only RUNNING / FAILED carry color to draw the eye.
export const SCAN_STATUS_BADGE: Record<string, string> = {
  PENDING:   "bg-gray-800        text-gray-400",
  RUNNING:   "bg-indigo-950/50   text-indigo-300",
  COMPLETED: "bg-slate-800/60    text-slate-300   border border-slate-700/50",
  FAILED:    "bg-red-950/40      text-red-400     border border-red-800/40",
  CANCELLED: "bg-gray-800        text-gray-500",
};

// ── Risk score ────────────────────────────────────────────────────────────────

export function riskScoreStyle(score: number) {
  if (score >= 80) return { label: "CRITICAL", ring: "border-red-700/60",    bg: "bg-red-950/60",    text: "text-red-300",    bar: "bg-red-500"    };
  if (score >= 60) return { label: "HIGH",     ring: "border-orange-700/60", bg: "bg-orange-950/60", text: "text-orange-300", bar: "bg-orange-500" };
  if (score >= 35) return { label: "MEDIUM",   ring: "border-amber-700/60",  bg: "bg-amber-950/60",  text: "text-amber-300",  bar: "bg-amber-500"  };
  return               { label: "LOW",      ring: "border-sky-700/60",    bg: "bg-sky-950/60",    text: "text-sky-300",    bar: "bg-sky-500"    };
}

// ── Shared surface tokens ─────────────────────────────────────────────────────

/** Standard hover style for ALL table rows and list items. */
export const ROW_HOVER = "hover:bg-gray-800/40";
