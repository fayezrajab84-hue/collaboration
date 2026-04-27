/**
 * Evidence export — CSV + HTML for compliance frameworks (Phase 16 Slice E).
 *
 * Two formats, ADMIN-gated at the route level:
 *
 *   buildComplianceCsv(orgId, framework)
 *     → RFC 4180 CSV. One row per (control × finding) tuple. Suitable
 *       for auditor spreadsheets.
 *
 *   buildComplianceHtml(orgId, framework, label)
 *     → self-contained HTML page with inline CSS. Auditors save it as
 *       PDF via browser print. Matches reportHtmlService convention so
 *       BreachLens stays Chromium-free.
 *
 * Both pull the same underlying data (every Finding mapped to every
 * Control in the framework, scoped to the org). The HTML adds visual
 * grouping + summary stats; the CSV is flat.
 */

import prisma from "../db.js";
import type { ComplianceFramework } from "@prisma/client";

// ── Shared data load ────────────────────────────────────────────────────

interface ExportRow {
  controlId:      string;
  controlCode:    string;
  controlName:    string;
  controlCategory:string | null;
  findingId:      string;
  findingTitle:   string;
  severity:       string;
  status:         string;
  scanType:       string;
  cweId:          string | null;
  cveId:          string | null;
  packageName:    string | null;
  packageVersion: string | null;
  filePath:       string | null;
  lineStart:      number | null;
  matchReason:    string;
  firstSeen:      Date;
  lastSeen:       Date;
}

async function loadExportRows(orgId: string, framework: ComplianceFramework): Promise<ExportRow[]> {
  // Single query joining FindingControl → Finding → ComplianceControl,
  // scoped to the org. Returns one row per (finding, control) mapping
  // with every column the export needs.
  const mappings = await prisma.findingControl.findMany({
    where: {
      finding: { orgId },
      control: { framework },
    },
    select: {
      matchReason: true,
      control: {
        select: { id: true, code: true, name: true, category: true, sortOrder: true },
      },
      finding: {
        select: {
          id: true, title: true, severity: true, status: true, scanType: true,
          cweId: true, cveId: true, packageName: true, packageVersion: true,
          filePath: true, lineStart: true, firstSeen: true, lastSeen: true,
        },
      },
    },
    orderBy: [
      { control: { sortOrder: "asc" } },
      { finding: { severity: "asc" } },
    ],
  });

  return mappings.map((m) => ({
    controlId:      m.control.id,
    controlCode:    m.control.code,
    controlName:    m.control.name,
    controlCategory:m.control.category,
    findingId:      m.finding.id,
    findingTitle:   m.finding.title,
    severity:       m.finding.severity,
    status:         m.finding.status,
    scanType:       m.finding.scanType,
    cweId:          m.finding.cweId,
    cveId:          m.finding.cveId,
    packageName:    m.finding.packageName,
    packageVersion: m.finding.packageVersion,
    filePath:       m.finding.filePath,
    lineStart:      m.finding.lineStart,
    matchReason:    m.matchReason,
    firstSeen:      m.finding.firstSeen,
    lastSeen:       m.finding.lastSeen,
  }));
}

// ── CSV ──────────────────────────────────────────────────────────────────

/**
 * RFC 4180 quoting — wrap any field containing comma, quote, CR, or LF in
 * double quotes; escape inner quotes by doubling. Numbers + dates round-trip
 * untouched.
 */
function csvField(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export async function buildComplianceCsv(
  orgId: string,
  framework: ComplianceFramework,
): Promise<string> {
  const rows = await loadExportRows(orgId, framework);

  const header = [
    "framework", "control_code", "control_name", "control_category",
    "finding_id", "finding_title", "severity", "status",
    "scan_type", "cwe_id", "cve_id",
    "package_name", "package_version",
    "file_path", "line_start",
    "match_reason", "first_seen", "last_seen",
  ];

  const lines: string[] = [header.join(",")];
  for (const r of rows) {
    lines.push([
      framework,
      r.controlCode, r.controlName, r.controlCategory ?? "",
      r.findingId, r.findingTitle, r.severity, r.status,
      r.scanType, r.cweId ?? "", r.cveId ?? "",
      r.packageName ?? "", r.packageVersion ?? "",
      r.filePath ?? "", r.lineStart ?? "",
      r.matchReason,
      r.firstSeen.toISOString(),
      r.lastSeen.toISOString(),
    ].map(csvField).join(","));
  }
  // RFC 4180 wants CRLF line endings (most spreadsheet tools handle LF too,
  // but CRLF is the standard so we match it exactly).
  return lines.join("\r\n") + "\r\n";
}

// ── HTML ─────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#b91c1c",
  HIGH:     "#c2410c",
  MEDIUM:   "#a16207",
  LOW:      "#0369a1",
  INFO:     "#6b7280",
};

const STATUS_COLOR: Record<string, string> = {
  OPEN:           "#dc2626",
  ACKNOWLEDGED:   "#ca8a04",
  FIXED:          "#16a34a",
  FALSE_POSITIVE: "#6b7280",
  IGNORED:        "#6b7280",
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

interface HtmlControlSummary {
  code:        string;
  name:        string;
  description: string;
  category:    string | null;
  total:       number;
  open:        number;
  fixed:       number;
  rows:        ExportRow[];
}

export async function buildComplianceHtml(
  orgId: string,
  framework: ComplianceFramework,
  label: string,
): Promise<string> {
  const rows = await loadExportRows(orgId, framework);

  // Group rows by control + load every control in the framework so we can
  // show "0 findings" for clean controls (auditors care about clean
  // controls too — they're evidence of working coverage).
  const allControls = await prisma.complianceControl.findMany({
    where:   { framework },
    orderBy: [{ sortOrder: "asc" }, { code: "asc" }],
  });

  const byControl = new Map<string, HtmlControlSummary>();
  for (const c of allControls) {
    byControl.set(c.id, {
      code:        c.code,
      name:        c.name,
      description: c.description,
      category:    c.category,
      total:       0,
      open:        0,
      fixed:       0,
      rows:        [],
    });
  }
  for (const r of rows) {
    const bucket = byControl.get(r.controlId);
    if (!bucket) continue;
    bucket.total += 1;
    if (r.status === "OPEN")  bucket.open  += 1;
    if (r.status === "FIXED") bucket.fixed += 1;
    bucket.rows.push(r);
  }

  // Top-line summary
  const totalControls = allControls.length;
  const controlsWithFindings = Array.from(byControl.values()).filter((c) => c.total > 0).length;
  const totalOpen  = rows.filter((r) => r.status === "OPEN").length;
  const totalFixed = rows.filter((r) => r.status === "FIXED").length;
  const generated = new Date().toISOString();

  const controlSections = Array.from(byControl.values()).map((c) => `
    <section class="control" id="control-${escapeHtml(c.code)}">
      <header class="control-header">
        ${c.category ? `<div class="category">${escapeHtml(c.category)}</div>` : ""}
        <h2><span class="code">${escapeHtml(c.code)}</span> ${escapeHtml(c.name)}</h2>
        <p class="description">${escapeHtml(c.description)}</p>
        <div class="counts">
          <span class="count count-total">${c.total} mapped</span>
          ${c.open  > 0 ? `<span class="count count-open">${c.open} OPEN</span>` : ""}
          ${c.fixed > 0 ? `<span class="count count-fixed">${c.fixed} fixed</span>` : ""}
          ${c.total === 0 ? `<span class="count count-clean">CLEAN — no findings</span>` : ""}
        </div>
      </header>
      ${c.rows.length === 0 ? "" : `
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Status</th>
              <th>Title</th>
              <th>Scan</th>
              <th>CWE / CVE</th>
              <th>Location</th>
              <th>Match</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            ${c.rows.map((r) => `
              <tr>
                <td><span class="badge sev" style="background:${SEV_COLOR[r.severity] ?? "#6b7280"}">${escapeHtml(r.severity)}</span></td>
                <td><span class="badge stat" style="color:${STATUS_COLOR[r.status] ?? "#6b7280"}">${escapeHtml(r.status)}</span></td>
                <td>${escapeHtml(r.findingTitle)}</td>
                <td>${escapeHtml(r.scanType)}</td>
                <td>${[r.cweId, r.cveId].filter(Boolean).map((x) => escapeHtml(x!)).join(" / ") || "—"}</td>
                <td>${escapeHtml([r.filePath, r.lineStart].filter((x) => x !== null && x !== "").join(":") || (r.packageName ? `${r.packageName}@${r.packageVersion ?? "?"}` : "—"))}</td>
                <td><code class="match">${escapeHtml(r.matchReason)}</code></td>
                <td>${r.firstSeen.toISOString().split("T")[0]}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `}
    </section>
  `).join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(label)} — Compliance Evidence</title>
  <style>
    @page { size: letter; margin: 0.75in; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1f2937; line-height: 1.5; max-width: 850px; margin: 2rem auto; padding: 0 1rem; }
    h1 { font-size: 1.5rem; margin: 0 0 0.25rem; color: #111827; }
    h2 { font-size: 1.1rem; margin: 0; color: #1f2937; font-weight: 600; }
    .subtitle { color: #6b7280; margin: 0 0 1.5rem; font-size: 0.85rem; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin: 1.5rem 0 2rem; }
    .stat-card { padding: 0.75rem 1rem; border: 1px solid #e5e7eb; border-radius: 0.5rem; background: #f9fafb; }
    .stat-card .label { font-size: 0.7rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    .stat-card .value { font-size: 1.5rem; font-weight: 700; color: #111827; margin-top: 0.25rem; }
    .control { margin-bottom: 1.5rem; padding: 1rem; border: 1px solid #e5e7eb; border-radius: 0.5rem; page-break-inside: avoid; }
    .control-header { margin-bottom: 0.75rem; }
    .category { font-size: 0.65rem; color: #4f46e5; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; margin-bottom: 0.25rem; }
    .control h2 { display: flex; align-items: baseline; gap: 0.5rem; }
    .code { font-family: "SF Mono", Menlo, monospace; color: #4f46e5; font-size: 0.85rem; }
    .description { color: #4b5563; font-size: 0.85rem; margin: 0.5rem 0; }
    .counts { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
    .count { padding: 0.15rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; }
    .count-total { background: #f3f4f6; color: #4b5563; }
    .count-open  { background: #fee2e2; color: #b91c1c; }
    .count-fixed { background: #dcfce7; color: #15803d; }
    .count-clean { background: #ecfdf5; color: #047857; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.75rem; }
    th { text-align: left; padding: 0.4rem 0.5rem; background: #f9fafb; color: #6b7280; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #e5e7eb; }
    td { padding: 0.4rem 0.5rem; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
    .badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.03em; }
    .badge.sev { color: white; }
    .badge.stat { background: transparent; }
    .match { font-size: 0.65rem; background: #f3f4f6; padding: 0.05rem 0.3rem; border-radius: 0.2rem; color: #4f46e5; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.7rem; }
    @media print { body { margin: 0; max-width: none; } .control { page-break-inside: avoid; } }
  </style>
</head>
<body>
  <h1>${escapeHtml(label)} — Compliance Evidence</h1>
  <p class="subtitle">Generated by BreachLens on ${escapeHtml(generated)}. Each finding shown is mapped to one or more controls via CWE matching or keyword fallback. Controls with no findings represent clean-coverage evidence.</p>
  <section class="summary">
    <div class="stat-card"><div class="label">Total controls</div><div class="value">${totalControls}</div></div>
    <div class="stat-card"><div class="label">Controls with findings</div><div class="value">${controlsWithFindings}</div></div>
    <div class="stat-card"><div class="label">Open findings</div><div class="value">${totalOpen}</div></div>
    <div class="stat-card"><div class="label">Fixed findings</div><div class="value">${totalFixed}</div></div>
  </section>
  ${controlSections}
  <footer>
    <p>This report is intended for compliance-evidence use. CWE-based mappings are derived from official OWASP Top 10 mappings; SOC 2 + PCI DSS mappings are community-standard interpretations and may be challenged by your auditor — see the seed file (apps/api/src/migrations/seedComplianceControls.ts) for the source of each mapping.</p>
    <p>To save as PDF: print this page (Ctrl/Cmd-P) and choose "Save as PDF" as the destination.</p>
  </footer>
</body>
</html>
`;
}
