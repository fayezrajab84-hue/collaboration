import type {
  ApplicationEnv,
  Confidence,
  Criticality,
  FindingStatus,
  PentestDepth,
  Priority,
  ScanType,
  TicketStatus,
} from "./enums.js";

// ── Generic wrappers ──────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface ApiError {
  error: string;
  details?: unknown;
  statusCode?: number;
}

// ── Auth ──────────────────────────────────────────────────────────────────

export interface AuthMeResponse {
  id: string;
  username: string;
  email: string | null;
  avatarUrl: string | null;
  // The org that subsequent /api/* calls will be scoped to. Drives the
  // sidebar's org-switcher selection state. Null only if the user has no
  // memberships at all (transient pre-onboarding state).
  activeOrgId: string | null;
  orgs: Array<{
    id: string;
    name: string;
    slug: string;
    type: "PERSONAL" | "TEAM";
    role: string;
  }>;
}

export interface SwitchOrgRequest {
  orgId: string;
}

export interface SwitchOrgResponse {
  activeOrgId: string;
}

// ── Repositories ──────────────────────────────────────────────────────────

export interface CreateRepoRequest {
  githubUrl: string;
  defaultBranch?: string;
}

export interface UpdateRepoRequest {
  defaultBranch?: string;
}

// ── Containers ────────────────────────────────────────────────────────────

export interface CreateContainerRequest {
  imageRef: string;
  registry?: string;
}

export interface UpdateContainerRequest {
  imageRef?: string;
  registry?: string;
}

// ── Domains ───────────────────────────────────────────────────────────────

export interface CreateDomainRequest {
  domain: string;
}

export interface UpdateDomainRequest {
  domain?: string;
  pentestDepth?: PentestDepth;
  excludePaths?: string[];
}

// ── Asset relations (Phase 27 Slice A) ───────────────────────────────────
// Operator-declared linkage between Repository / Container / Domain so the
// correlation engine can walk attack chains across asset types. v1 is
// operator-declared via the AssetLinksPanel; later slices may add CI-based
// inference (Dockerfile presence + image-name parsing). All endpoints are
// PATCH /api/{repos,containers,domains}/:id/asset-links — ADMIN+, audit-logged,
// rejects cross-org references.

/** PATCH /api/repos/:id/asset-links */
export interface UpdateRepoAssetLinksRequest {
  /** Container image refs this repo builds (e.g. ["myorg/api:1.2.3"]). */
  buildsContainerImages?: string[];
}

/** PATCH /api/containers/:id/asset-links */
export interface UpdateContainerAssetLinksRequest {
  /** Repository ID this container is built from, or null to clear. */
  sourceRepositoryId?: string | null;
  /** Domain IDs that route requests to this container. */
  deployedAtDomainIds?: string[];
}

/** PATCH /api/domains/:id/asset-links */
export interface UpdateDomainAssetLinksRequest {
  /** Container IDs that answer requests at this hostname. */
  servesContainerIds?: string[];
}

// ── Applications (Phase 27.5) ─────────────────────────────────────────────
// CRUD + component-assignment endpoints under /api/applications.
// All ADMIN+ for mutations; reads are VIEWER+.

export interface CreateApplicationRequest {
  name:         string;
  slug?:        string;            // optional; auto-derived from name if omitted
  description?: string;
  environment?: ApplicationEnv;    // default PRODUCTION
  criticality?: Criticality;       // default MEDIUM
  owner?:       string;
}

export interface UpdateApplicationRequest {
  name?:        string;
  slug?:        string;
  description?: string | null;
  environment?: ApplicationEnv;
  criticality?: Criticality;
  owner?:       string | null;
}

/**
 * PATCH /api/applications/:id/components — bulk assign assets to this app.
 * Each array REPLACES the current set for its kind (i.e. the operator decides
 * the full membership in one call). Pass an empty array to clear; omit a
 * field to leave that kind untouched. Cross-org references rejected.
 */
export interface UpdateApplicationComponentsRequest {
  repositoryIds?: string[];
  containerIds?:  string[];
  domainIds?:     string[];
}

export interface ApplicationComponentsResponse {
  repositories: Array<{ id: string; fullName: string }>;
  containers:   Array<{ id: string; imageRef: string }>;
  domains:      Array<{ id: string; domain:  string }>;
}

/**
 * Response shape for any asset-link PATCH — returns the updated relation set
 * for that asset only. UI re-renders chips from this; full asset is fetched
 * separately on next list query.
 */
export interface AssetLinksResponse {
  buildsContainerImages?: string[];
  sourceRepositoryId?: string | null;
  deployedAtDomainIds?: string[];
  servesContainerIds?: string[];
}

export interface AuthorizeDomainRequest {
  confirmed: true; // must be exactly true
}

export interface SubdomainToggleRequest {
  includedInScan: boolean;
}

export interface TriggerPentestRequest {
  depth: PentestDepth;
  authorized: true; // must be exactly true — server re-validates
}

export interface ReconSubdomainInfo {
  subdomain: string;
  isLive: boolean;
  statusCode?: number;
  technologies: string[];
}

// ── Scan trigger ──────────────────────────────────────────────────────────

export interface TriggerScanRequest {
  scanTypes?: ScanType[];
  branch?: string;
}

export interface TriggerScanResponse {
  scanJobId: string;
  status: "PENDING";
  scanTypes: ScanType[];
}

// ── Findings ──────────────────────────────────────────────────────────────

export interface FindingFilterParams {
  severity?: string | string[];
  scanType?: ScanType | ScanType[];
  status?: FindingStatus | FindingStatus[];
  confidence?: Confidence | Confidence[];
  // Phase 14 — package-level reachability filter (SCA only). Comma-separated
  // string for the URL form ("REACHABLE,UNKNOWN") or string[] in JSON.
  reachability?: "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "NOT_APPLICABLE" | string;
  repoId?: string;
  containerId?: string;
  domainId?: string;
  /** Phase 27.5 — filter findings to one or more applications. Resolves to
   *  "any finding whose target asset is in this application." Comma-separated
   *  string for the URL form, or string[] in JSON. */
  applicationId?: string | string[];
  scanner?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface UpdateFindingRequest {
  status: FindingStatus;
  note?: string;
}

// ── Tickets ───────────────────────────────────────────────────────────────

export interface CreateTicketRequest {
  findingId: string;
  title: string;
  description?: string;
  priority: Priority;
  createJiraIssue?: boolean;
}

export interface UpdateTicketRequest {
  status?: TicketStatus;
  title?: string;
  description?: string;
  priority?: Priority;
}

// ── Integrations ──────────────────────────────────────────────────────────

export interface JiraIntegrationConfig {
  host: string;
  email: string;
  apiToken: string;
  projectKey: string;
  issueType?: string;
}

export interface SlackIntegrationConfig {
  webhookUrl: string;
  channel?: string;
}

export interface TeamsIntegrationConfig {
  webhookUrl: string;
}

// ── SSE Events ────────────────────────────────────────────────────────────

export type SseEventType = "STATUS_CHANGE" | "FINDINGS_BATCH" | "SCAN_ERROR" | "SCAN_COMPLETE";

export interface SseEvent {
  type: SseEventType;
  scanJobId: string;
  timestamp: string;
  data: Record<string, unknown>;
}

// ── Compliance (Phase 16) ─────────────────────────────────────────────────
// Mirrors the API responses in apps/api/src/routes/compliance/router.ts.
// Imported by the web app's complianceApi client + the CompliancePage UI.

export type ComplianceFramework = "SOC2" | "OWASP_TOP_10" | "PCI_DSS";

export interface FrameworkSummary {
  framework:            ComplianceFramework;
  label:                string;
  controlCount:         number;
  controlsWithFindings: number;
  openFindingCount:     number;
}

export interface FrameworksResponse {
  frameworks: FrameworkSummary[];
}

export interface ControlBreakdown {
  id:           string;
  code:         string;
  name:         string;
  description:  string;
  category:     string | null;
  sortOrder:    number;
  cweIds:       number[];
  total:        number;
  open:         number;
  acknowledged: number;
  fixed:        number;
  falsePositive:number;
  ignored:      number;
  // Severity histogram of OPEN findings only — what's currently broken.
  severity: {
    CRITICAL: number;
    HIGH:     number;
    MEDIUM:   number;
    LOW:      number;
    INFO:     number;
  };
}

export interface FrameworkDashboard {
  framework:     ComplianceFramework;
  label:         string;
  totalMappings: number;
  // Phase 14 — reachability counts across this framework's OPEN findings.
  // Drives the "noise reduction" stat in the dashboard header.
  reachabilitySummary: {
    reachable:     number;
    notReachable:  number;
    unknown:       number;
    notApplicable: number;
  };
  controls:      ControlBreakdown[];
}

// ── Attack paths (Phase 27 Slice C) ──────────────────────────────────────
// Mirrors apps/api/src/services/correlation/attackPathService.ts.

export type AttackPathBridgeType =
  | "cve" | "route" | "port" | "secret"
  | "runtime" | "waf_bypass" | "db_access" | "egress_c2"
  | "dns_resolution" | "c2_beacon" | "agent_tool" | "llm_attack"
  | "cloud_east_west" | "flow_data_access";

export interface AttackPathNode {
  findingId:  string;
  title:      string;
  severity:   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  scanType:   string;
  confidence: "CONFIRMED" | "LIKELY" | "POSSIBLE";
  targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN";
  targetName: string | null;
  filePath:   string | null;
  evidence:   Record<string, unknown> | null;
  /** Phase 27.5.x — scan-type-specific specifics so the operator can see
   *  WHICH vulnerability inline without opening the drawer. */
  lineStart:      number | null;     // SAST/IAC/SECRET source-line
  ruleId:         string | null;     // Semgrep / Trivy / nuclei rule
  cveId:          string | null;     // SCA / CONTAINER CVE
  cweId:          string | null;
  packageName:    string | null;     // SCA / CONTAINER affected package
  packageVersion: string | null;
  fixVersion:     string | null;     // SCA — what to bump to
  cvssScore:      number | null;
}

export interface AttackPathEdge {
  fromFindingId: string;
  toFindingId:   string;
  bridgeType:    AttackPathBridgeType;
  reason:        string;
  confidence:    "CONFIRMED" | "LIKELY" | "POSSIBLE";
}

export interface AttackPathSummary {
  groupId:        string;
  /** Phase 27.5.x — heuristic title (highest-severity, source-side preferred).
   *  Always populated. Used as the chain card headline. */
  title:          string;
  /** Phase 27.5.x — AI-generated short headline (~6 words). Populated only
   *  when an AI summary has been generated for this chain. UI prefers this
   *  over the heuristic title when present. */
  aiTitle:        string | null;
  score:          number;
  length:         number;
  maxSeverity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  hasConfirmed:   boolean;
  externalReach:  number;
  /** Phase 27.5.x — Application IDs whose components contributed to this
   *  chain. Powers the /attack-paths Application MultiSelect filter. */
  applicationIds: string[];
  nodes:          AttackPathNode[];
  edges:          AttackPathEdge[];
}

export interface AttackPathsListResponse {
  paths: AttackPathSummary[];
}

// ── AI summary for an attack path (Phase 27.5.x) ─────────────────────────
// Generated on-demand by POST /api/attack-paths/:groupId/summarise.
// Cached by content-hash; UI shows the regenerate button when stale.
export interface AttackPathSummaryAI {
  groupId:      string;
  title:        string | null; // ~6-word headline (Phase 27.5.x); null on legacy rows
  tldr:         string;       // 1-line summary (max 280 chars)
  narrative:    string;       // 2-3 paragraphs (max 2000 chars)
  providerType: string;       // "ANTHROPIC" | "OPENAI" | "GEMINI" | "OLLAMA"
  model:        string;       // resolved model id used for this generation
  contentHash:  string;       // chain-content fingerprint at gen time
  generatedAt:  string;
  cached:       boolean;      // true on cache-hit, false when freshly generated
  stale:        boolean;      // true when chain content has changed since generation
}

/** Chain detail response (GET /api/attack-paths/:groupId) — extends list shape with summary. */
export interface AttackPathDetailResponse extends AttackPathSummary {
  summary: AttackPathSummaryAI | null;
}

export interface ControlFindingsResponse {
  control: {
    id:          string;
    framework:   ComplianceFramework;
    code:        string;
    name:        string;
    description: string;
    category:    string | null;
  };
  findings: Array<{
    id:              string;
    title:           string;
    description:     string;
    severity:        string;
    status:          string;
    scanType:        string;
    scanner:         string;
    cweId:           string | null;
    cveId:           string | null;
    packageName:     string | null;
    packageVersion:  string | null;
    fixVersion:      string | null;
    filePath:        string | null;
    lineStart:       number | null;
    firstSeen:       string;
    lastSeen:        string;
    repositoryId:    string | null;
    containerId:     string | null;
    domainId:        string | null;
    confidence:      string;
    // Phase 14 — package-level reachability + supporting evidence.
    reachability:        "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "NOT_APPLICABLE";
    reachabilityEvidence:string[] | null;
  }>;
  total: number;
  page:  number;
  limit: number;
}
