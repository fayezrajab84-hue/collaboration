import type { Confidence, FindingStatus, PentestDepth, Priority, ScanType, TicketStatus } from "./enums.js";

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
  repoId?: string;
  containerId?: string;
  domainId?: string;
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
