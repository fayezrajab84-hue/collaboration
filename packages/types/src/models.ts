import type {
  Confidence,
  FindingStatus,
  IntegrationType,
  OrgType,
  PentestDepth,
  Priority,
  Role,
  ScanStatus,
  ScanType,
  Severity,
  TargetType,
  TicketStatus,
} from "./enums.js";

export interface User {
  id: string;
  githubId: string;
  username: string;
  email: string | null;
  avatarUrl: string | null;
  createdAt: Date;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  type: OrgType;
  createdAt: Date;
}

export interface OrganizationMember {
  userId: string;
  orgId: string;
  role: Role;
  user?: User;
  org?: Organization;
}

export interface FindingCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

export interface Repository {
  id: string;
  orgId: string;
  githubId: number;
  fullName: string;
  url: string;
  defaultBranch: string;
  isPrivate: boolean;
  language: string | null;
  lastScannedAt: Date | null;
  aiRiskScore?: number | null;
  aiRiskReason?: string | null;
  aiRiskScoredAt?: Date | null;
  addedAt: Date;
  findingCounts?: FindingCounts;
}

export interface Container {
  id: string;
  orgId: string;
  imageRef: string;
  registry: string | null;
  lastScannedAt: Date | null;
  aiRiskScore?: number | null;
  aiRiskReason?: string | null;
  aiRiskScoredAt?: Date | null;
  addedAt: Date;
  findingCounts?: FindingCounts;
}

export interface Domain {
  id: string;
  orgId: string;
  domain: string;
  lastScannedAt: Date | null;
  aiRiskScore?: number | null;
  aiRiskReason?: string | null;
  aiRiskScoredAt?: Date | null;
  addedAt: Date;
  findingCounts?: FindingCounts;
  authorized: boolean;
  authorizedAt: Date | null;
  pentestDepth: PentestDepth;
  excludePaths: string[];
}

export interface SubdomainDiscovery {
  id: string;
  domainId: string;
  subdomain: string;
  isLive: boolean;
  statusCode: number | null;
  technologies: string[];
  includedInScan: boolean;
  discoveredAt: Date;
}

export interface ScanJob {
  id: string;
  orgId: string;
  targetType: TargetType;
  targetId: string;
  scanTypes: ScanType[];
  totalScans: number;
  completedScans: number;
  status: ScanStatus;
  startedAt: Date | null;
  completedAt: Date | null;
  error: string | null;
  createdAt: Date;
  // Aggregated counts
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  // AI-generated summary (Phase 2)
  aiSummary?: string | null;
  aiSummarisedAt?: Date | null;
  // Joined target (present in list/detail responses)
  repository?: { id: string; fullName: string } | null;
  container?: { id: string; imageRef: string } | null;
  domain?: { id: string; domain: string } | null;
}

// ── Phase 6: Finding groups ───────────────────────────────────────────────────
export interface FindingGroup {
  key:          string;             // ruleId | cveId | normalised title slug
  label:        string;             // human-readable group name
  scanType:     string;
  count:        number;
  criticalCount: number;
  highCount:    number;
  mediumCount:  number;
  lowCount:     number;
  affectedTargets: string[];        // up to 5 target names
  sampleFindings:  Array<{ id: string; title: string; severity: string; targetName: string }>;
  aiInsight?:   string | null;      // generated on demand
}

export interface Finding {
  id: string;
  orgId: string;
  scanJobId: string;
  targetType: TargetType;
  targetId: string;
  scanType: ScanType;
  title: string;
  description: string;
  severity: Severity;
  status: FindingStatus;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  // Code snippet captured at scan time (SAST/IAC/SECRET)
  codeSnippet: string | null;
  cveId: string | null;
  cweId: string | null;
  packageName: string | null;
  packageVersion: string | null;
  fixVersion: string | null;
  cvssScore: number | null;
  scanner: string;
  ruleId: string | null;
  fingerprint: string;
  remediation: string | null;
  references: string[];
  rawOutput: Record<string, unknown>;
  firstSeen: Date;
  lastSeen: Date;
  resolvedAt: Date | null;
  // Confidence & false-positive triage
  confidence: Confidence;
  evidence: Record<string, unknown> | null;
  verifiedAt: Date | null;
  // AI analysis
  aiAnalysis?: Record<string, unknown> | null;
  aiAnalysedAt?: Date | null;
  // AI false-positive analysis
  aiFpAnalysis?: FpAnalysis | null;
  aiFpAnalysedAt?: Date | null;
  // AI fix suggestion (unified diff)
  aiFixSuggestion?: string | null;
  aiFixSuggestedAt?: Date | null;
  // Joined from related target (present in list/detail responses)
  targetName?: string;
  repository?: { fullName: string; defaultBranch: string } | null;
  container?: { imageRef: string } | null;
  domain?: { domain: string } | null;
  // Joined ticket (present in detail response)
  ticket?: { id: string; status: string; jiraKey: string | null } | null;
}

export interface FpAnalysis {
  verdict:    "LIKELY_FP" | "LIKELY_REAL" | "UNCERTAIN";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reasoning:  string;
  indicators: string[];
}

export interface Ticket {
  id: string;
  orgId: string;
  findingId: string;
  title: string;
  description: string | null;
  status: TicketStatus;
  priority: Priority;
  jiraKey: string | null;
  jiraUrl: string | null;
  slackTs: string | null;
  teamsId: string | null;
  createdById: string;
  createdAt: Date;
  updatedAt: Date;
  finding?: Finding;
  createdBy?: User;
}

export interface Suppression {
  id: string;
  orgId: string;
  fingerprint: string;
  reason: string;
  expiresAt: Date | string | null;
  approvedById: string;
  createdAt: Date | string;
  revokedAt: Date | string | null;
  revokedById: string | null;
  // Joined
  approvedBy?: { username: string };
}

export interface AuditEvent {
  id: string;
  orgId: string;
  userId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date | string;
  user?: { username: string; avatarUrl: string | null };
}

export interface Integration {
  id: string;
  orgId: string;
  type: IntegrationType;
  isActive: boolean;
  createdAt: Date;
  // Config shape per type (returned masked to client)
  maskedConfig?: Record<string, string>;
}
