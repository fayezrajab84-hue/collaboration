import type {
  AgentStatus,
  ApplicationEnv,
  CloudProvider,
  Confidence,
  Criticality,
  FindingStatus,
  GitHubAccountType,
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
  /** Phase 27.5 — Application boundary; null until operator assigns. */
  applicationId?: string | null;
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
  /** Phase 27.5 — Application boundary; null until operator assigns. */
  applicationId?: string | null;
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
  /** Phase 27.5 — Application boundary; null until operator assigns. */
  applicationId?: string | null;
}

// ── Phase 28 Slice B — Wazuh runtime agent (WorkloadAgent) ───────────────
// One row per Wazuh-enrolled host/container the operator wants to surface
// in BreachLens. linkedContainerId is the operator-declared graph edge that
// lets runtimeBridge correlate RUNTIME findings with CONTAINER/DAST findings
// on the same workload.
export interface WorkloadAgent {
  id:                string;
  orgId:             string;
  wazuhAgentId:      string;
  wazuhAgentName:    string;
  status:            AgentStatus;
  linkedContainerId: string | null;
  agentVersion:      string | null;
  lastHeartbeatAt:   Date | string | null;
  lastAlertAt:       Date | string | null;
  lastIngestError:   string | null;
  createdAt:         Date | string;
  updatedAt:         Date | string;
  // List endpoint hydrates these so the table doesn't N+1 fetch.
  linkedContainerImageRef?: string | null;
  runtimeFindingCount?:     number;
}

export interface DiscoveredAgent {
  wazuhAgentId:   string;
  wazuhAgentName: string;
  status:         AgentStatus;
  agentVersion:   string | null;
}

export interface DiscoverAgentsResponse {
  enabled:    boolean;
  reason?:    string;
  discovered: DiscoveredAgent[];
  upserted:   number;
}

export interface IngestSummary {
  enabled:           boolean;
  reason?:           string;
  agentsConsidered:  number;
  agentsPolled:      number;
  alertsIngested:    number;
  findingsTouched:   number;
  errors:            string[];
}

// ── Phase 28 — Runtime evidence shape ─────────────────────────────────
//
// Structured payload stored on `Finding.evidence` when scanType=RUNTIME.
// Produced by `extractRuntimeEvidence` in wazuhIngestService.ts. The
// flat top-level fields are what the Findings table renders as columns;
// the nested groups carry the richer drill-down for the drawer's
// "Threat Hunt" panel.
//
// Every field is optional and best-effort — different Wazuh rule
// classes populate different subsets. The UI handles missing fields
// gracefully (renders "—").
export interface RuntimeEvidence {
  // ── FLAT (column-friendly) ─────────────────────────────────────
  attackerIp?:      string | null;
  attackerIpCount?: number;
  attackerIps?:     string[];
  destIp?:          string | null;
  destPort?:        string | null;
  srcPort?:         string | null;
  userAgent?:       string | null;

  processId?:       number | string | null;
  processName?:     string | null;
  processCommand?:  string | null;
  parentProcessId?: number | string | null;
  workingDir?:      string | null;

  user?:            string | null;

  filePath?:        string | null;
  fileHash?:        string | null;
  fileEvent?:       string | null;
  fileSizeAfter?:   string | number | null;

  wazuhRuleId?:     string;
  wazuhRuleLevel?:  number;
  wazuhAgentName?:  string;
  wazuhAgentId?:    string;
  location?:        string | null;
  fullLog?:         string | null;

  occurrencesInBucket?: number;
  occurrencesTotal?:    number;
  firstAlertAt?:        string | null;
  latestAlertAt?:       string | null;

  // ── NESTED (drawer-rendering) ──────────────────────────────────
  geo?: {
    country?:   string | null;
    city?:      string | null;
    region?:    string | null;
    latitude?:  number | null;
    longitude?: number | null;
    distinctCountries?: string[];
  } | null;

  mitre?: {
    ids:        string[];
    tactics:    string[];
    techniques: string[];
  } | null;

  compliance?: {
    pci_dss:     string[];
    gdpr:        string[];
    hipaa:       string[];
    nist_800_53: string[];
    tsc:         string[];
  } | null;

  vulnerability?: {
    cve?:            string | null;
    cvss3Score?:     number | null;
    packageName?:    string | null;
    packageVersion?: string | null;
    severity?:       string | null;
    status?:         string | null;
    title?:          string | null;
    published?:      string | null;
    updated?:        string | null;
  } | null;

  processTree?: {
    pid?:           number | string | null;
    name?:          string | null;
    executable?:    string | null;
    cmdline?:       string | null;
    parent?:        string | number | null;
    parentName?:    string | null;
    ppid?:          number | string | null;
    ruid?:          number | string | null;
    euid?:          number | string | null;
    privEscalated?: boolean;
  } | null;

  http?: {
    url?:        string | null;
    method?:     string | null;
    statusCode?: string | number | null;
    referrer?:   string | null;
    userAgent?:  string | null;
    tld?:        string | null;
  } | null;

  audit?: {
    type?:    string | null;
    key?:     string | null;
    session?: string | null;
    success?: string | null;
  } | null;

  detection?: {
    ruleId:        string;
    ruleLevel:     number;
    groups:        string[];
    frequency?:    number | null;
    firedTimes?:   number | null;
    decoder?:      string | null;
    manager?:      string | null;
    cluster?:      string | null;
    predecoder?:   string | null;
    agentLabels?:  Record<string, unknown> | null;
  };
}

// ── Phase 29 — Cloud Security Posture Management asset ───────────────────
//
// One CloudAccount = one (provider, scope) the operator authorises BreachLens
// to evaluate. For AZURE that scope is one subscription; for AWS one account;
// for GCP one project. Provider-specific identifier columns (tenantId,
// azureClientId, subscriptionId) are flat for the AZURE-only Slice A; AWS/
// GCP slices will add their own (awsAccountId, gcpProjectId) without
// overloading these.
//
// `credentialsConfigured` is a derived boolean — true when the encrypted
// credential blob is set on the row, false when the operator has only
// pre-created the account record. Drives the UI "credentials needed" hint
// without exposing the encrypted blob to the client.
//
// `lastScanError` surfaces the most recent test-connection / scan failure
// so the UI can show "credentials no longer valid" without operators
// digging in logs.
export interface CloudAccount {
  id:                   string;
  orgId:                string;
  provider:             CloudProvider;
  displayName:          string;
  // Azure-specific. Null for AWS/GCP (or when the operator hasn't
  // populated them yet).
  tenantId:             string | null;
  azureClientId:        string | null;
  subscriptionId:       string | null;
  // True when encryptedCredentials has been set. The encrypted blob
  // itself is never returned to the client.
  credentialsConfigured: boolean;
  isActive:             boolean;
  lastScannedAt:        Date | string | null;
  lastScanError:        string | null;
  addedAt:              Date | string;
  updatedAt:            Date | string;
  findingCounts?:       FindingCounts;
}

// ── Phase 29 Slice C1 — GitHub posture asset ─────────────────────────────
//
// Mirrors the CloudAccount pattern: non-secret identifiers are scalar
// columns; the secret material (encrypted PAT) lives behind
// `credentialsConfigured` and is never exposed to the client. When
// `installationId` is set the auth path is the GitHub App installation
// token (preferred — auto-rotates), and the encrypted PAT may be null.
//
// Org-level Prowler checks (5 of 24) attach findings to this row directly
// via targetType=GITHUB_ACCOUNT. Repo-level + workflow checks (19) attach
// to the linked Repository.
export interface GitHubAccount {
  id:                    string;
  orgId:                 string;
  displayName:           string;
  accountLogin:          string;
  accountType:           GitHubAccountType;
  // GitHub App installation id when auth path is the App. Null when
  // operator chose PAT auth (encryptedCredentials populated instead).
  installationId:        number | null;
  // True when encryptedCredentials has been set OR installationId is
  // present. The encrypted blob itself is never returned to the client.
  credentialsConfigured: boolean;
  isActive:              boolean;
  lastScannedAt:         Date | string | null;
  lastScanError:         string | null;
  addedAt:               Date | string;
  updatedAt:             Date | string;
  findingCounts?:        FindingCounts;
}

// ── Phase 27.5 — Application boundary ────────────────────────────────────
export interface Application {
  id:          string;
  orgId:       string;
  name:        string;
  slug:        string;
  description: string | null;
  environment: ApplicationEnv;
  criticality: Criticality;
  owner:       string | null;
  createdAt:   Date | string;
  updatedAt:   Date | string;
  // Computed counts (only present on detail responses)
  componentCounts?: {
    repositories: number;
    containers:   number;
    domains:      number;
  };
  findingCounts?: FindingCounts;
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
  // Phase 29 — CSPM target (CLOUD scanType findings).
  cloudAccount?: { displayName: string; provider: string; subscriptionId: string | null } | null;
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
