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
  /**
   * Phase 27 Slice A — operator-declared container image refs this repo builds.
   * Used by the correlation engine to bridge SAST/SCA findings on this repo to
   * CVE/runtime findings on the produced containers.
   */
  buildsContainerImages?: string[];
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
  /**
   * Phase 27 Slice A — operator-declared back-pointer to the source repo. May be
   * inferred in a later slice (Dockerfile presence + image-name parsing) but v1
   * is operator-declared via the AssetLinksPanel.
   */
  sourceRepositoryId?: string | null;
  /** Phase 27 Slice A — domain IDs that route requests to this container. */
  deployedAtDomainIds?: string[];
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
  hasAuthConfig?: boolean;
  hasApiSpec?: boolean;
  /** url count when an ACTIVE recording exists for this domain; null otherwise */
  activeRecordingUrls?: number | null;
  /** Phase 27 Slice A — container IDs that answer requests at this hostname. */
  servesContainerIds?: string[];
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
  // Split of this scan's contribution (present on detail endpoint only).
  //   newThisScan   — findings first seen during this scan run
  //   confirmedCount — findings that pre-existed and were re-observed
  // Tells operators whether "0 new" means "clean scan" vs "re-confirmed backlog"
  newThisScan?: number;
  confirmedCount?: number;
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
  // Phase 14 — package-level reachability (SCA/CONTAINER only). Other
  // scan types are NOT_APPLICABLE; SCA findings that pre-date Phase 14
  // (or were emitted by a scanner image without import-detection) stay
  // UNKNOWN. reachabilityEvidence is the file-path list when REACHABLE.
  reachability?: "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "NOT_APPLICABLE";
  reachabilityEvidence?: string[] | null;
  /** Phase 27 Slice B/C — attack path correlation. Null when not yet computed
   *  or when this finding stands alone (no bridge matched). */
  correlationGroupId?: string | null;
  /** [{toFindingId, bridgeType, confidence, reason}] — drives the AttackPathBadge. */
  correlationEdges?: Array<{
    toFindingId: string;
    bridgeType:  string;
    confidence:  "CONFIRMED" | "LIKELY" | "POSSIBLE";
    reason:      string;
  }> | null;
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
