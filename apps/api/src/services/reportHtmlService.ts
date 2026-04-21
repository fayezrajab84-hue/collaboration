/**
 * Report HTML Service
 *
 * Generates a self-contained HTML security report (inline CSS + SVG charts)
 * and stores it in the Report table. Triggered automatically on scan completion.
 *
 * Report sections:
 *   1. Header — target name, scan date, risk grade
 *   2. Severity summary cards (Critical / High / Medium / Low / Info)
 *   3. Charts — severity donut  +  scan-type bar chart
 *   4. Remediation status bar (Open / Acknowledged / Fixed)
 *   5. AI risk assessment (if scored)
 *   6. Scan history (last 5 scans)
 *   7. Top findings table (up to 50 rows, severity-sorted)
 *   8. Footer
 */

import prisma from "../db.js";
import { logger } from "../logger.js";

// ── Colour palettes ───────────────────────────────────────────────────────────

const SEV_HEX: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ea580c",
  MEDIUM:   "#d97706",
  LOW:      "#65a30d",
  INFO:     "#3b82f6",
};

const SEV_BG: Record<string, string> = {
  CRITICAL: "#fef2f2",
  HIGH:     "#fff7ed",
  MEDIUM:   "#fffbeb",
  LOW:      "#f7fee7",
  INFO:     "#eff6ff",
};

const SEV_LABEL: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH:     "High",
  MEDIUM:   "Medium",
  LOW:      "Low",
  INFO:     "Info",
};

const TYPE_HEX: Record<string, string> = {
  SAST:         "#8b5cf6",
  SCA:          "#ec4899",
  SECRET:       "#f59e0b",
  IAC:          "#10b981",
  CONTAINER:    "#06b6d4",
  DAST:         "#f97316",
  PENTEST:      "#ef4444",
  PENTEST_FULL: "#b91c1c",
};

// ── SVG helpers ───────────────────────────────────────────────────────────────

interface Slice { value: number; color: string; label: string }

function svgDonut(slices: Slice[], size = 180): string {
  const total = slices.reduce((s, sl) => s + sl.value, 0);
  if (total === 0) {
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${size / 2}" cy="${size / 2}" r="${size * 0.37}"
        fill="none" stroke="#d1fae5" stroke-width="${size * 0.13}" />
      <text x="${size / 2}" y="${size / 2 + 8}" text-anchor="middle"
        fill="#16a34a" font-size="28" font-weight="700" font-family="system-ui">✓</text>
    </svg>`;
  }

  const cx = size / 2, cy = size / 2;
  const r  = size * 0.37;
  const ir = size * 0.23;
  let angle = -Math.PI / 2;
  const paths: string[] = [];

  for (const sl of slices.filter((s) => s.value > 0)) {
    const sweep = (sl.value / total) * 2 * Math.PI;
    const ea   = angle + sweep;
    const x1   = cx + r  * Math.cos(angle), y1 = cy + r  * Math.sin(angle);
    const x2   = cx + r  * Math.cos(ea),    y2 = cy + r  * Math.sin(ea);
    const ix1  = cx + ir * Math.cos(ea),    iy1 = cy + ir * Math.sin(ea);
    const ix2  = cx + ir * Math.cos(angle), iy2 = cy + ir * Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    paths.push(
      `<path d="M ${x1.toFixed(1)} ${y1.toFixed(1)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(1)} ${y2.toFixed(1)} ` +
      `L ${ix1.toFixed(1)} ${iy1.toFixed(1)} A ${ir} ${ir} 0 ${large} 0 ${ix2.toFixed(1)} ${iy2.toFixed(1)} Z" ` +
      `fill="${sl.color}" />`
    );
    angle = ea;
  }

  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
  ${paths.join("\n  ")}
  <text x="${cx}" y="${cy - 7}" text-anchor="middle" fill="#0f172a"
    font-size="24" font-weight="700" font-family="system-ui">${total}</text>
  <text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="#64748b"
    font-size="11" font-family="system-ui">findings</text>
</svg>`;
}

interface Bar { label: string; value: number; color: string }

function svgBar(bars: Bar[], w = 380, h = 180): string {
  if (bars.length === 0) return `<svg width="${w}" height="${h}"></svg>`;
  const maxVal   = Math.max(...bars.map((b) => b.value), 1);
  const gap      = 8;
  const bw       = Math.max(18, (w - 40) / bars.length - gap);
  const chartH   = h - 48;

  const items = bars.map((b, i) => {
    const bh  = Math.round((b.value / maxVal) * chartH);
    const x   = 20 + i * (bw + gap);
    const y   = h - 34 - bh;
    return `  <rect x="${x.toFixed(0)}" y="${y.toFixed(0)}" width="${bw.toFixed(0)}" height="${Math.max(bh, 0).toFixed(0)}"
    fill="${b.color}" rx="4" opacity="0.85"/>
  <text x="${(x + bw / 2).toFixed(0)}" y="${(h - 16).toFixed(0)}" text-anchor="middle"
    fill="#475569" font-size="9" font-family="system-ui">${b.label}</text>
  ${b.value > 0 ? `<text x="${(x + bw / 2).toFixed(0)}" y="${(y - 5).toFixed(0)}" text-anchor="middle"
    fill="#1e293b" font-size="11" font-weight="600" font-family="system-ui">${b.value}</text>` : ""}`;
  });

  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
${items.join("\n")}
</svg>`;
}

// ── Grade calculation ─────────────────────────────────────────────────────────

function gradeInfo(
  riskScore: number | null,
  critical:  number,
  high:      number,
): { grade: string; color: string; bg: string; label: string } {
  let g: string;
  if (critical > 5 || (riskScore !== null && riskScore >= 80))      g = "F";
  else if (critical > 0 || (riskScore !== null && riskScore >= 60)) g = "D";
  else if (high > 5    || (riskScore !== null && riskScore >= 40))  g = "C";
  else if (high > 0    || (riskScore !== null && riskScore >= 20))  g = "B";
  else                                                               g = "A";

  const map: Record<string, { color: string; bg: string; label: string }> = {
    A: { color: "#16a34a", bg: "#dcfce7", label: "Excellent" },
    B: { color: "#65a30d", bg: "#ecfccb", label: "Good" },
    C: { color: "#d97706", bg: "#fef3c7", label: "Fair" },
    D: { color: "#ea580c", bg: "#ffedd5", label: "Poor" },
    F: { color: "#dc2626", bg: "#fee2e2", label: "Critical" },
  };
  return { grade: g, ...map[g]! };
}

// ── Date helpers ──────────────────────────────────────────────────────────────

function fmt(d: Date | string | null | undefined): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
  });
}

function fmtFull(d: Date | string | null | undefined): string {
  if (!d) return "—";
  return new Date(d).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

// ── HTML legend item ──────────────────────────────────────────────────────────

function legendItem(color: string, label: string, value: number): string {
  return `<div class="legend-item">
    <span class="legend-dot" style="background:${color}"></span>
    <span class="legend-label">${label}</span>
    <span class="legend-val">${value}</span>
  </div>`;
}

// ── Core HTML builder ─────────────────────────────────────────────────────────

interface ReportData {
  orgName:       string;
  targetName:    string;
  targetType:    string;
  targetUrl:     string | null;
  riskScore:     number | null;
  riskReason:    string | null;
  scanDate:      Date | null;
  scanTypes:     string[];
  aiSummary:     string | null;
  sevCounts:     Record<string, number>;
  typeCounts:    Record<string, number>;
  statusCounts:  { OPEN: number; ACKNOWLEDGED: number; FIXED: number };
  findings:      Array<{
    title:       string;
    severity:    string;
    status:      string;
    scanType:    string;
    filePath:    string | null;
    lineStart:   number | null;
    cveId:       string | null;
    packageName: string | null;
    fixVersion:  string | null;
    firstSeen:   Date;
    aiSummary:   string | null;
  }>;
  scanHistory: Array<{
    id:            string;
    completedAt:   Date | null;
    criticalCount: number;
    highCount:     number;
    mediumCount:   number;
    lowCount:      number;
    infoCount:     number;
    scanTypes:     string[];
  }>;
}

function buildHtml(d: ReportData): string {
  const { grade, color: gradeColor, bg: gradeBg, label: gradeLabel } =
    gradeInfo(d.riskScore, d.sevCounts.CRITICAL ?? 0, d.sevCounts.HIGH ?? 0);

  // ── Charts ─────────────────────────────────────────────────────────────────
  const pieSlices: Slice[] = [
    { value: d.sevCounts.CRITICAL ?? 0, color: SEV_HEX.CRITICAL ?? "#dc2626", label: "Critical" },
    { value: d.sevCounts.HIGH     ?? 0, color: SEV_HEX.HIGH     ?? "#ea580c", label: "High"     },
    { value: d.sevCounts.MEDIUM   ?? 0, color: SEV_HEX.MEDIUM   ?? "#d97706", label: "Medium"   },
    { value: d.sevCounts.LOW      ?? 0, color: SEV_HEX.LOW      ?? "#65a30d", label: "Low"      },
    { value: d.sevCounts.INFO     ?? 0, color: SEV_HEX.INFO     ?? "#6b7280", label: "Info"     },
  ];
  const donutSvg = svgDonut(pieSlices);

  const typeBars: Bar[] = Object.entries(d.typeCounts)
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => b - a)
    .map(([type, count]) => ({
      label: type.replace("_FULL", ""),
      value: count,
      color: TYPE_HEX[type] ?? "#6366f1",
    }));
  const barSvg = svgBar(typeBars);

  // ── Status bar ─────────────────────────────────────────────────────────────
  const { OPEN, ACKNOWLEDGED, FIXED } = d.statusCounts;
  const statusTotal = OPEN + ACKNOWLEDGED + FIXED || 1;
  const openPct  = Math.round((OPEN         / statusTotal) * 100);
  const ackPct   = Math.round((ACKNOWLEDGED / statusTotal) * 100);
  const fixPct   = Math.round((FIXED        / statusTotal) * 100);

  // ── Severity summary cards ─────────────────────────────────────────────────
  const sevCards = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => `
    <div class="sev-card" style="border-color:${SEV_HEX[sev]};background:${SEV_BG[sev]}">
      <div class="sev-count" style="color:${SEV_HEX[sev]}">${d.sevCounts[sev] ?? 0}</div>
      <div class="sev-label" style="color:${SEV_HEX[sev]}">${SEV_LABEL[sev]}</div>
    </div>`).join("");

  // ── Findings rows ──────────────────────────────────────────────────────────
  const findingRows = d.findings.slice(0, 50).map((f, idx) => {
    const sevColor = SEV_HEX[f.severity] ?? "#6366f1";
    const typeColor = TYPE_HEX[f.scanType] ?? "#6366f1";
    const statusCls = f.status === "OPEN" ? "#dc2626" : f.status === "ACKNOWLEDGED" ? "#d97706" : "#16a34a";
    const loc = f.filePath
      ? `<span class="mono">${esc(f.filePath)}${f.lineStart ? `:${f.lineStart}` : ""}</span>`
      : f.cveId ? `<span class="cve">${esc(f.cveId)}</span>` : "—";
    return `<tr class="${idx % 2 === 0 ? "row-even" : "row-odd"}">
      <td><span class="badge" style="background:${sevColor}10;color:${sevColor};border:1px solid ${sevColor}40">${SEV_LABEL[f.severity] ?? f.severity}</span></td>
      <td><span class="badge" style="background:${typeColor}10;color:${typeColor};border:1px solid ${typeColor}40">${f.scanType.replace("_FULL", "")}</span></td>
      <td class="finding-title">${esc(f.title)}${f.aiSummary ? `<div class="ai-excerpt">${esc(f.aiSummary.slice(0, 120))}…</div>` : ""}</td>
      <td class="loc-cell">${loc}</td>
      <td><span class="status-dot" style="color:${statusCls}">●</span> ${f.status.charAt(0) + f.status.slice(1).toLowerCase()}</td>
      <td class="date-cell">${fmt(f.firstSeen)}</td>
    </tr>`;
  }).join("");

  // ── Scan history rows ──────────────────────────────────────────────────────
  const historyRows = d.scanHistory.map((s) => {
    const total = s.criticalCount + s.highCount + s.mediumCount + s.lowCount + s.infoCount;
    const pills = [
      s.criticalCount ? `<span class="mini-badge" style="background:#fef2f2;color:#dc2626">${s.criticalCount}C</span>` : "",
      s.highCount     ? `<span class="mini-badge" style="background:#fff7ed;color:#ea580c">${s.highCount}H</span>` : "",
      s.mediumCount   ? `<span class="mini-badge" style="background:#fffbeb;color:#d97706">${s.mediumCount}M</span>` : "",
      s.lowCount      ? `<span class="mini-badge" style="background:#f7fee7;color:#65a30d">${s.lowCount}L</span>` : "",
    ].filter(Boolean).join(" ");
    return `<tr>
      <td>${fmtFull(s.completedAt)}</td>
      <td>${s.scanTypes.map((t) => t.replace("_FULL", "")).join(", ")}</td>
      <td>${total}</td>
      <td>${pills || '<span style="color:#16a34a">Clean</span>'}</td>
    </tr>`;
  }).join("");

  // ── Legend ─────────────────────────────────────────────────────────────────
  const pieLegend = pieSlices
    .filter((s) => s.value > 0)
    .map((s) => legendItem(s.color, s.label, s.value))
    .join("");

  const typeLegend = typeBars
    .map((b) => legendItem(b.color, b.label, b.value))
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Report — ${esc(d.targetName)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; font-size: 14px; }
  a    { color: #4f46e5; text-decoration: none; }

  /* ── Layout ── */
  .page    { max-width: 1100px; margin: 0 auto; padding: 0 0 48px; }
  .section { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; margin: 20px 16px; overflow: hidden; }
  .section-header { padding: 16px 24px 14px; border-bottom: 1px solid #f1f5f9; }
  .section-title  { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; }
  .section-body   { padding: 20px 24px; }

  /* ── Report header ── */
  .report-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    color: #fff; padding: 36px 40px 32px; margin-bottom: 0;
  }
  .header-top    { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; }
  .header-brand  { font-size: 11px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: #a5b4fc; margin-bottom: 6px; }
  .header-title  { font-size: 26px; font-weight: 800; color: #fff; line-height: 1.2; }
  .header-target { font-size: 15px; color: #94a3b8; margin-top: 6px; font-family: monospace; }
  .header-meta   { display: flex; gap: 24px; margin-top: 20px; flex-wrap: wrap; }
  .meta-item     { display: flex; flex-direction: column; gap: 2px; }
  .meta-key      { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; }
  .meta-val      { font-size: 13px; color: #cbd5e1; font-weight: 500; }

  /* ── Grade badge ── */
  .grade-badge {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    width: 80px; height: 80px; border-radius: 16px; flex-shrink: 0;
    border: 2px solid; font-family: system-ui;
  }
  .grade-letter { font-size: 36px; font-weight: 900; line-height: 1; }
  .grade-sub    { font-size: 9px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin-top: 2px; }

  /* ── Severity cards ── */
  .sev-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; padding: 20px 16px; }
  .sev-card  { border: 1.5px solid; border-radius: 10px; padding: 16px 12px; text-align: center; }
  .sev-count { font-size: 32px; font-weight: 800; line-height: 1; }
  .sev-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }

  /* ── Charts row ── */
  .charts-row { display: grid; grid-template-columns: 220px 1fr; gap: 0; }
  .chart-cell { padding: 20px 24px; }
  .chart-cell + .chart-cell { border-left: 1px solid #f1f5f9; }
  .chart-label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: #94a3b8; margin-bottom: 14px; }
  .chart-inner { display: flex; align-items: center; gap: 20px; }
  .legend      { display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; }
  .legend-item { display: flex; align-items: center; gap: 7px; font-size: 12px; color: #334155; }
  .legend-dot  { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .legend-label{ flex: 1; }
  .legend-val  { font-weight: 700; color: #0f172a; min-width: 24px; text-align: right; }

  /* ── Status bar ── */
  .status-section { padding: 20px 24px; }
  .status-bar-wrap{ border-radius: 6px; overflow: hidden; height: 22px; display: flex; margin: 10px 0; }
  .status-seg     { height: 100%; transition: width 0.3s; }
  .status-legend  { display: flex; gap: 20px; margin-top: 10px; }
  .status-item    { display: flex; align-items: center; gap: 7px; font-size: 12px; }
  .status-dot-sq  { width: 10px; height: 10px; border-radius: 3px; flex-shrink: 0; }

  /* ── AI risk box ── */
  .risk-box { display: flex; align-items: center; gap: 20px; padding: 18px 24px; background: #f8fafc; border-top: 1px solid #e2e8f0; }
  .risk-score-wrap{ display: flex; flex-direction: column; align-items: center; flex-shrink: 0; }
  .risk-score-num { font-size: 40px; font-weight: 900; line-height: 1; color: #4f46e5; }
  .risk-score-sub { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; margin-top: 2px; }
  .risk-reason    { font-size: 13px; color: #475569; line-height: 1.6; font-style: italic; }

  /* ── Summary bubble ── */
  .ai-summary-box { background: #faf5ff; border: 1px solid #e9d5ff; border-radius: 10px; padding: 14px 18px; margin: 16px 24px; font-size: 13px; color: #4c1d95; line-height: 1.65; }

  /* ── Tables ── */
  table  { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th     { background: #f8fafc; border-bottom: 2px solid #e2e8f0; padding: 10px 12px; text-align: left;
           font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: #64748b; }
  td     { padding: 9px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  .row-even { background: #fff; }
  .row-odd  { background: #fafafa; }
  tr:hover  { background: #f0f9ff !important; }

  .badge     { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .mini-badge{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-right: 2px; }
  .mono      { font-family: monospace; font-size: 11px; color: #4f46e5; word-break: break-all; }
  .cve       { font-family: monospace; font-size: 11px; color: #dc2626; }
  .finding-title { max-width: 360px; font-weight: 500; color: #0f172a; }
  .ai-excerpt{ margin-top: 4px; font-size: 11px; color: #64748b; font-style: italic; line-height: 1.5; font-weight: 400; }
  .loc-cell  { max-width: 200px; word-break: break-all; }
  .date-cell { white-space: nowrap; color: #64748b; font-size: 11px; }
  .status-dot{ font-size: 10px; }

  /* ── Footer ── */
  .footer { text-align: center; padding: 28px 16px; color: #94a3b8; font-size: 11px; }
  .footer strong { color: #64748b; }

  /* ── Print ── */
  @media print {
    body { background: #fff; font-size: 12px; }
    .section { box-shadow: none; break-inside: avoid; }
    .page { max-width: 100%; padding: 0; }
  }
</style>
</head>
<body>
<div class="page">

  <!-- ── Header ─────────────────────────────────────────────────────────── -->
  <div class="report-header">
    <div class="header-top">
      <div>
        <div class="header-brand">BreachLens DevSecOps · Security Report</div>
        <div class="header-title">${esc(d.targetName)}</div>
        <div class="header-target">${d.orgName} · ${d.targetType.charAt(0) + d.targetType.slice(1).toLowerCase()}</div>
      </div>
      <div class="grade-badge" style="background:${gradeBg}20;border-color:${gradeColor}60">
        <div class="grade-letter" style="color:${gradeColor}">${grade}</div>
        <div class="grade-sub"   style="color:${gradeColor}">${gradeLabel}</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item">
        <span class="meta-key">Scan Date</span>
        <span class="meta-val">${fmtFull(d.scanDate)}</span>
      </div>
      <div class="meta-item">
        <span class="meta-key">Scan Types</span>
        <span class="meta-val">${d.scanTypes.map((t) => t.replace("_FULL", "")).join(" · ")}</span>
      </div>
      ${d.riskScore !== null ? `
      <div class="meta-item">
        <span class="meta-key">Risk Score</span>
        <span class="meta-val">${d.riskScore}/100</span>
      </div>` : ""}
      <div class="meta-item">
        <span class="meta-key">Total Findings</span>
        <span class="meta-val">${Object.values(d.sevCounts).reduce((a, b) => a + b, 0)}</span>
      </div>
    </div>
  </div>

  ${d.aiSummary ? `
  <div class="ai-summary-box">
    ✦ <strong>AI Summary:</strong> ${esc(d.aiSummary)}
  </div>` : ""}

  <!-- ── Severity summary cards ─────────────────────────────────────────── -->
  <div class="sev-cards">${sevCards}</div>

  <!-- ── Charts ─────────────────────────────────────────────────────────── -->
  <div class="section">
    <div class="charts-row">
      <div class="chart-cell">
        <div class="chart-label">By Severity</div>
        <div class="chart-inner">
          ${donutSvg}
          <div class="legend">${pieLegend}</div>
        </div>
      </div>
      <div class="chart-cell">
        <div class="chart-label">By Scan Type</div>
        <div class="chart-inner" style="flex-direction:column;align-items:flex-start">
          ${barSvg}
          <div class="legend" style="flex-direction:row;flex-wrap:wrap;gap:10px;margin-top:6px">${typeLegend}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Remediation status ─────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-header"><span class="section-title">Remediation Status</span></div>
    <div class="status-section">
      <div class="status-bar-wrap">
        <div class="status-seg" style="width:${openPct}%;background:#dc2626" title="Open: ${OPEN}"></div>
        <div class="status-seg" style="width:${ackPct}%;background:#d97706"  title="Acknowledged: ${ACKNOWLEDGED}"></div>
        <div class="status-seg" style="width:${fixPct}%;background:#16a34a"  title="Fixed: ${FIXED}"></div>
      </div>
      <div class="status-legend">
        <div class="status-item">
          <div class="status-dot-sq" style="background:#dc2626"></div>
          <span>Open <strong>${OPEN}</strong> (${openPct}%)</span>
        </div>
        <div class="status-item">
          <div class="status-dot-sq" style="background:#d97706"></div>
          <span>Acknowledged <strong>${ACKNOWLEDGED}</strong> (${ackPct}%)</span>
        </div>
        <div class="status-item">
          <div class="status-dot-sq" style="background:#16a34a"></div>
          <span>Fixed <strong>${FIXED}</strong> (${fixPct}%)</span>
        </div>
      </div>
    </div>
  </div>

  ${d.riskScore !== null || d.riskReason ? `
  <!-- ── AI Risk Assessment ──────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-header"><span class="section-title">AI Risk Assessment</span></div>
    <div class="risk-box">
      ${d.riskScore !== null ? `
      <div class="risk-score-wrap">
        <div class="risk-score-num">${d.riskScore}</div>
        <div class="risk-score-sub">Risk Score</div>
      </div>` : ""}
      ${d.riskReason ? `<div class="risk-reason">"${esc(d.riskReason)}"</div>` : ""}
    </div>
  </div>` : ""}

  ${historyRows ? `
  <!-- ── Scan History ───────────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-header"><span class="section-title">Scan History (Last 5)</span></div>
    <div class="section-body" style="padding:0">
      <table>
        <thead><tr>
          <th>Date</th><th>Scan Types</th><th>Total Findings</th><th>Severity Breakdown</th>
        </tr></thead>
        <tbody>${historyRows}</tbody>
      </table>
    </div>
  </div>` : ""}

  <!-- ── Top Findings ───────────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-header">
      <span class="section-title">Findings</span>
      <span style="font-size:12px;color:#94a3b8;margin-left:8px">(${Math.min(d.findings.length, 50)} of ${d.findings.length} shown — severity ordered)</span>
    </div>
    <div class="section-body" style="padding:0">
      ${d.findings.length === 0
        ? `<div style="padding:32px;text-align:center;color:#16a34a;font-size:15px;font-weight:600">✓ No active findings — clean scan!</div>`
        : `<table>
          <thead><tr>
            <th style="width:90px">Severity</th>
            <th style="width:90px">Type</th>
            <th>Title / AI Insight</th>
            <th>Location / CVE</th>
            <th style="width:110px">Status</th>
            <th style="width:90px">First Seen</th>
          </tr></thead>
          <tbody>${findingRows}</tbody>
        </table>`}
    </div>
  </div>

</div><!-- /page -->

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<div class="footer">
  Generated by <strong>BreachLens DevSecOps</strong> on ${fmtFull(new Date())} ·
  This report is confidential and intended for internal use only.
</div>

</body>
</html>`;
}

/** HTML-escape a string for safe insertion into the template */
function esc(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Public: generate + store report ──────────────────────────────────────────

export async function generateTargetReport(scanJobId: string): Promise<void> {
  try {
    // 1. Load scan job with target details
    const scan = await prisma.scanJob.findUnique({
      where: { id: scanJobId },
      include: {
        org:        { select: { name: true } },
        repository: { select: { id: true, fullName: true, url: true, aiRiskScore: true, aiRiskReason: true } },
        container:  { select: { id: true, imageRef: true, aiRiskScore: true, aiRiskReason: true } },
        domain:     { select: { id: true, domain:   true, aiRiskScore: true, aiRiskReason: true } },
      },
    });

    if (!scan || scan.status !== "COMPLETED") return;

    const targetId   = scan.repositoryId ?? scan.containerId ?? scan.domainId;
    if (!targetId) return;

    const targetName = scan.repository?.fullName ?? scan.container?.imageRef ?? scan.domain?.domain ?? targetId;
    const targetUrl  = scan.repository?.url ?? (scan.domain ? `https://${scan.domain.domain}` : null);
    const riskScore  = scan.repository?.aiRiskScore  ?? scan.container?.aiRiskScore  ?? scan.domain?.aiRiskScore  ?? null;
    const riskReason = scan.repository?.aiRiskReason ?? scan.container?.aiRiskReason ?? scan.domain?.aiRiskReason ?? null;

    const targetWhere =
      scan.targetType === "REPOSITORY" ? { repositoryId: targetId } :
      scan.targetType === "CONTAINER"  ? { containerId:  targetId } :
      { domainId: targetId };

    // 2. All active findings for this target
    const allFindings = await prisma.finding.findMany({
      where: { orgId: scan.orgId, ...targetWhere, status: { notIn: ["FALSE_POSITIVE", "IGNORED"] } },
      orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
      select: {
        title: true, severity: true, status: true, scanType: true,
        filePath: true, lineStart: true, cveId: true, packageName: true,
        fixVersion: true, firstSeen: true, aiAnalysis: true,
      },
    });

    // 3. Scan history (last 5 completed for this target)
    const scanHistory = await prisma.scanJob.findMany({
      where: { orgId: scan.orgId, ...targetWhere, status: "COMPLETED" },
      orderBy: { completedAt: "desc" },
      take: 5,
      select: {
        id: true, completedAt: true, scanTypes: true,
        criticalCount: true, highCount: true, mediumCount: true, lowCount: true, infoCount: true,
      },
    });

    // 4. Aggregate counts
    const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const typeCounts: Record<string, number> = {};
    const statusCounts = { OPEN: 0, ACKNOWLEDGED: 0, FIXED: 0 };

    for (const f of allFindings) {
      sevCounts[f.severity]  = (sevCounts[f.severity]  ?? 0) + 1;
      typeCounts[f.scanType] = (typeCounts[f.scanType] ?? 0) + 1;
      if (f.status === "OPEN" || f.status === "ACKNOWLEDGED" || f.status === "FIXED") {
        statusCounts[f.status]++;
      }
    }

    // 5. Build report data, extract AI summaries
    const findings = allFindings.map((f) => {
      const ai = f.aiAnalysis as Record<string, unknown> | null;
      const aiSummary = typeof ai?.["summary"] === "string" ? ai["summary"] as string : null;
      return { ...f, aiSummary };
    });

    const reportData: ReportData = {
      orgName:      scan.org.name,
      targetName,
      targetType:   scan.targetType,
      targetUrl,
      riskScore,
      riskReason,
      scanDate:     scan.completedAt,
      scanTypes:    scan.scanTypes,
      aiSummary:    scan.aiSummary ?? null,
      sevCounts,
      typeCounts,
      statusCounts,
      findings,
      scanHistory,
    };

    // 6. Generate HTML
    const html = buildHtml(reportData);

    // 7. Store in DB
    const totalFindings = Object.values(sevCounts).reduce((a, b) => a + b, 0);
    const { grade } = gradeInfo(riskScore, sevCounts.CRITICAL ?? 0, sevCounts.HIGH ?? 0);

    await prisma.report.create({
      data: {
        orgId:       scan.orgId,
        scanJobId,
        targetType:  scan.targetType,
        targetId,
        trigger:     "ON_SCAN_COMPLETE",
        title:       `${targetName} — Security Report`,
        htmlContent: html,
        metadata: {
          targetName,
          targetType: scan.targetType,
          riskScore,
          riskGrade: grade,
          ...sevCounts,
          totalFindings,
          openCount:         statusCounts.OPEN,
          acknowledgedCount: statusCounts.ACKNOWLEDGED,
          fixedCount:        statusCounts.FIXED,
          scanTypes:         scan.scanTypes,
        },
      },
    });

    logger.info(`[report] generated for scan ${scanJobId} → ${targetName} (${totalFindings} findings, grade ${grade})`);
  } catch (err) {
    // Non-fatal — never block scan completion
    logger.warn(`[report] failed for scan ${scanJobId}: ${(err as Error).message}`);
  }
}
