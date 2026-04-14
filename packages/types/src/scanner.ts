import type { ScanType, Severity, TargetType } from "./enums.js";

// ── Request sent from API to Python scanner service ───────────────────────

export interface ScanRequest {
  scanJobId: string;
  orgId: string;
  scanType: ScanType;
  targetType: TargetType;

  // Repository target
  repoUrl?: string;
  branch?: string;
  gitToken?: string; // passed over internal Docker network only, never logged

  // Container target
  imageRef?: string;

  // Domain target (DAST / Pentest)
  domain?: string;
}

// ── Normalized finding returned from scanner ─────────────────────────────

export interface NormalizedFinding {
  fingerprint: string; // SHA-256(orgId+targetId+scanType+ruleId+filePath+line)
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  scanType: ScanType;
  scanner: string; // "semgrep" | "trivy" | "trufflehog" | "checkov" | "zap" | "nuclei"

  // Location (code-level findings)
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  codeSnippet?: string;

  // Vulnerability metadata
  cveId?: string;
  cweId?: string;
  packageName?: string;
  packageVersion?: string;
  fixVersion?: string;
  cvssScore?: number;

  // Remediation
  remediation?: string;
  references?: string[];

  // Raw scanner output (for debugging / display)
  rawOutput: Record<string, unknown>;
}

// ── Response from Python scanner service ─────────────────────────────────

export interface ScanResult {
  scanJobId: string;
  scanType: ScanType;
  scanner: string;
  success: boolean;
  findings: NormalizedFinding[];
  error?: string;
  durationMs: number;
}
