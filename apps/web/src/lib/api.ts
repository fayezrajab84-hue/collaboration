import axios from "axios";
import type {
  Repository, Container, Domain, ScanJob, Finding, FindingGroup, FpAnalysis, Ticket, Integration, SubdomainDiscovery,
  CreateRepoRequest, UpdateRepoRequest,
  CreateContainerRequest, UpdateContainerRequest,
  CreateDomainRequest, UpdateDomainRequest,
  AuthorizeDomainRequest, TriggerPentestRequest, SubdomainToggleRequest,
  TriggerScanRequest, TriggerScanResponse,
  FindingFilterParams, UpdateFindingRequest,
  CreateTicketRequest, UpdateTicketRequest,
  JiraIntegrationConfig, SlackIntegrationConfig, TeamsIntegrationConfig,
  PaginatedResponse, AuthMeResponse, SwitchOrgResponse,
  ComplianceFramework, FrameworksResponse, FrameworkDashboard, ControlFindingsResponse,
  UpdateRepoAssetLinksRequest, UpdateContainerAssetLinksRequest, UpdateDomainAssetLinksRequest,
  AssetLinksResponse,
  AttackPathSummary, AttackPathsListResponse,
} from "@devsecops/types";

export const apiClient = axios.create({
  baseURL: "/api",
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

// Redirect to login on 401
apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

// ── Auth ──────────────────────────────────────────────────────────────────

export const authApi = {
  me: () => axios.get<AuthMeResponse>("/auth/me", { withCredentials: true }).then((r) => r.data),
  logout: () => axios.post("/auth/logout", {}, { withCredentials: true }),
  switchOrg: (orgId: string) =>
    axios
      .post<SwitchOrgResponse>("/auth/org/switch", { orgId }, { withCredentials: true })
      .then((r) => r.data),
};

// ── Repositories ──────────────────────────────────────────────────────────

export interface GitHubRepoSummary {
  id:            number;
  fullName:      string;
  url:           string;
  defaultBranch: string;
  isPrivate:     boolean;
  language:      string | null;
  added:         boolean;
}

export const reposApi = {
  list: () => apiClient.get<Repository[]>("/repos").then((r) => r.data),
  listGitHub: (page = 1) =>
    apiClient.get<GitHubRepoSummary[]>("/repos/github", { params: { page } }).then((r) => r.data),
  get: (id: string) => apiClient.get<Repository>(`/repos/${id}`).then((r) => r.data),
  create: (data: CreateRepoRequest) => apiClient.post<Repository>("/repos", data).then((r) => r.data),
  update: (id: string, data: UpdateRepoRequest) => apiClient.patch<Repository>(`/repos/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/repos/${id}`),
  triggerScan: (id: string, data?: TriggerScanRequest) =>
    apiClient.post<TriggerScanResponse>(`/repos/${id}/scan`, data ?? {}).then((r) => r.data),
  /** Phase 27 Slice A — declare which container images this repo builds. */
  updateAssetLinks: (id: string, data: UpdateRepoAssetLinksRequest) =>
    apiClient.patch<AssetLinksResponse>(`/repos/${id}/asset-links`, data).then((r) => r.data),
};

// ── Containers ────────────────────────────────────────────────────────────

export const containersApi = {
  list: () => apiClient.get<Container[]>("/containers").then((r) => r.data),
  get: (id: string) => apiClient.get<Container>(`/containers/${id}`).then((r) => r.data),
  create: (data: CreateContainerRequest) => apiClient.post<Container>("/containers", data).then((r) => r.data),
  update: (id: string, data: UpdateContainerRequest) => apiClient.patch<Container>(`/containers/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/containers/${id}`),
  triggerScan: (id: string) =>
    apiClient.post<TriggerScanResponse>(`/containers/${id}/scan`).then((r) => r.data),
  /** Phase 27 Slice A — link this container to its source repo + serving domains. */
  updateAssetLinks: (id: string, data: UpdateContainerAssetLinksRequest) =>
    apiClient.patch<AssetLinksResponse>(`/containers/${id}/asset-links`, data).then((r) => r.data),
};

// ── Domains ───────────────────────────────────────────────────────────────

export const domainsApi = {
  list: () => apiClient.get<Domain[]>("/domains").then((r) => r.data),
  get: (id: string) => apiClient.get<Domain>(`/domains/${id}`).then((r) => r.data),
  create: (data: CreateDomainRequest) => apiClient.post<Domain>("/domains", data).then((r) => r.data),
  update: (id: string, data: UpdateDomainRequest) => apiClient.patch<Domain>(`/domains/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/domains/${id}`),
  triggerScan: (id: string) =>
    apiClient.post<TriggerScanResponse>(`/domains/${id}/scan`).then((r) => r.data),
  authorize: (id: string, data: AuthorizeDomainRequest) =>
    apiClient.post<Domain>(`/domains/${id}/authorize`, data).then((r) => r.data),
  recon: (id: string) =>
    apiClient.post<{ domain: string; subdomains: SubdomainDiscovery[] }>(`/domains/${id}/recon`).then((r) => r.data),
  getSubdomains: (id: string) =>
    apiClient.get<SubdomainDiscovery[]>(`/domains/${id}/subdomains`).then((r) => r.data),
  toggleSubdomain: (id: string, subId: string, data: SubdomainToggleRequest) =>
    apiClient.patch<SubdomainDiscovery>(`/domains/${id}/subdomains/${subId}`, data).then((r) => r.data),
  triggerPentest: (id: string, data: TriggerPentestRequest) =>
    apiClient.post<TriggerScanResponse>(`/domains/${id}/pentest`, data).then((r) => r.data),
  getAuth: (id: string) =>
    apiClient.get<DomainAuthConfigView | null>(`/domains/${id}/auth`).then((r) => r.data),
  saveAuth: (id: string, data: DomainAuthConfigInput) =>
    apiClient.put(`/domains/${id}/auth`, data).then((r) => r.data),
  deleteAuth: (id: string) =>
    apiClient.delete(`/domains/${id}/auth`).then((r) => r.data),
  getApiSpec: (id: string) =>
    apiClient.get<DomainApiSpecView | null>(`/domains/${id}/apispec`).then((r) => r.data),
  saveApiSpec: (id: string, data: { filename: string; specJson: Record<string, unknown> }) =>
    apiClient.put<DomainApiSpecView>(`/domains/${id}/apispec`, data).then((r) => r.data),
  /**
   * Upload raw OpenAPI / Swagger file content (YAML or JSON). The server
   * parses + validates, so we don't ship a YAML lib in the bundle and shape
   * validation stays centralized.
   */
  importApiSpec: (id: string, fileText: string, filename: string) => {
    // Sniff content type so the API uses the right body parser. JSON files
    // come through express.json; YAML through express.text — getting this
    // wrong yields an empty req.body, not a clear error.
    const trimmed = fileText.trimStart();
    const isJson = trimmed.startsWith("{") || trimmed.startsWith("[");
    return apiClient
      .post<DomainApiSpecView>(
        `/domains/${id}/apispec/import`,
        fileText,
        {
          params:  { filename },
          headers: { "Content-Type": isJson ? "application/json" : "application/yaml" },
          // Stop axios from JSON.stringify-ing our raw text body
          transformRequest: [(d) => d],
        },
      )
      .then((r) => r.data);
  },
  deleteApiSpec: (id: string) =>
    apiClient.delete(`/domains/${id}/apispec`).then((r) => r.data),
  // Interactive DAST recording
  recordingStart: (id: string) =>
    apiClient.post<RecordingSessionView>(`/domains/${id}/recording/start`).then((r) => r.data),
  recordingStatus: (id: string) =>
    apiClient.get<RecordingSessionView | null>(`/domains/${id}/recording/status`).then((r) => r.data),
  recordingScan: (id: string) =>
    apiClient.post<TriggerScanResponse>(`/domains/${id}/recording/scan`).then((r) => r.data),
  recordingStop: (id: string) =>
    apiClient.post(`/domains/${id}/recording/stop`).then((r) => r.data),
  recordingPromote: (id: string, depth: "STANDARD" | "AGGRESSIVE" = "STANDARD") =>
    apiClient
      .post<TriggerScanResponse & { urlCount: number }>(
        `/domains/${id}/recording/promote`,
        { depth },
      )
      .then((r) => r.data),
  /** Phase 27 Slice A — link this domain to backing containers. */
  updateAssetLinks: (id: string, data: UpdateDomainAssetLinksRequest) =>
    apiClient.patch<AssetLinksResponse>(`/domains/${id}/asset-links`, data).then((r) => r.data),
};

export interface RecordingSessionView {
  sessionId: string;
  contextId: string;
  contextName: string;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  caUrl: string;
  status: string;
  urlCount?: number;
  alertCount?: number;
  startedAt?: string;
  lastActivityAt?: string;
  scanJobId?: string | null;
  scanJobStatus?: string | null;
  promotedScanJobId?: string | null;
  promotedScanJobStatus?: string | null;
}

export interface DomainAuthConfigView {
  id: string;
  authType: "FORM" | "HEADER" | "COOKIE" | "OAUTH2";
  loginUrl?: string | null;
  usernameField: string;
  passwordField: string;
  loggedInPattern: string;
  loggedOutPattern: string;
  headerName?: string | null;
  // OAuth2 non-secret fields (returned from API)
  oauth2TokenUrl?: string | null;
  oauth2ClientId?: string | null;
  oauth2Scope?: string | null;
  oauth2GrantType?: string | null;
  hasCredentials: boolean;
}

export interface DomainAuthConfigInput {
  authType: "FORM" | "HEADER" | "COOKIE" | "OAUTH2";
  loginUrl?: string;
  usernameField?: string;
  passwordField?: string;
  username?: string;
  password?: string;
  loggedInPattern?: string;
  loggedOutPattern?: string;
  headerName?: string;
  headerValue?: string;
  // OAuth2 fields
  oauth2TokenUrl?: string;
  oauth2ClientId?: string;
  oauth2ClientSecret?: string;
  oauth2Scope?: string;
  oauth2GrantType?: "client_credentials" | "password";
}

export interface DomainApiSpecView {
  id: string;
  domainId: string;
  filename: string;
  endpoints: number;
  createdAt: string;
  updatedAt: string;
}

// ── Scans ─────────────────────────────────────────────────────────────────

export const scansApi = {
  list: (page = 1, limit = 20) =>
    apiClient.get<PaginatedResponse<ScanJob>>("/scans", { params: { page, limit } }).then((r) => r.data),
  get: (id: string) => apiClient.get<ScanJob>(`/scans/${id}`).then((r) => r.data),
  cancel: (id: string) => apiClient.post<{ success: boolean }>(`/scans/${id}/cancel`).then((r) => r.data),
  delete: (id: string) => apiClient.delete<{ success: boolean }>(`/scans/${id}`).then((r) => r.data),
  clearFailed: () => apiClient.delete<{ count: number }>("/scans", { params: { status: "FAILED" } }).then((r) => r.data),
  generateSummary: (id: string) => apiClient.post<{ queued: boolean }>(`/scans/${id}/summary`).then((r) => r.data),
  diff: (id: string, compareTo?: string) =>
    apiClient.get<{
      scanA: {
        id: string; startedAt: string | null; completedAt: string | null;
        status?: string; scanTypes?: string[]; failedScanTypes?: string[];
        // Number of URLs the scanner actually examined this run; null when
        // not captured (legacy scans, code-only scan types).
        targetUrlCount?: number | null;
      } | null;
      scanB: {
        id: string; startedAt: string | null; completedAt: string | null;
        status?: string; scanTypes?: string[]; failedScanTypes?: string[];
        targetUrlCount?: number | null;
      };
      added:        Array<Pick<Finding, "id"|"title"|"severity"|"scanType"|"fingerprint"|"filePath"|"lineStart">>;
      removed:      Array<Pick<Finding, "id"|"title"|"severity"|"scanType"|"fingerprint"|"filePath"|"lineStart">>;
      // Scope-aware additions: findings whose URL was NOT in the other
      // scan's recorded URL list — meaning we can't claim they were
      // "fixed" (URL never re-visited) or "newly introduced" (URL never
      // visited before). Empty arrays when neither scan recorded URLs.
      outOfScopeAdded:   Array<Pick<Finding, "id"|"title"|"severity"|"scanType"|"fingerprint"|"filePath"|"lineStart">>;
      outOfScopeRemoved: Array<Pick<Finding, "id"|"title"|"severity"|"scanType"|"fingerprint"|"filePath"|"lineStart">>;
      // True when at least one scan has a recorded URL list; the UI can
      // hide the out-of-scope buckets entirely when this is false.
      scopeAware?: boolean;
      unchangedCount: number;
      // Populated when one or both scans are FAILED, when scanTypes don't
      // overlap, or when every shared type failed in either scan. The UI
      // displays this in place of the diff body.
      effectiveScanTypes?: string[];
      reason?: string;
    }>(`/scans/${id}/diff`, { params: compareTo ? { compareTo } : {} }).then((r) => r.data),
};

// ── Findings ──────────────────────────────────────────────────────────────

export const findingsApi = {
  list: (params?: FindingFilterParams) =>
    apiClient.get<PaginatedResponse<Finding>>("/findings", { params }).then((r) => r.data),
  get: (id: string) => apiClient.get<Finding>(`/findings/${id}`).then((r) => r.data),
  httpMessage: (id: string, messageId: string) =>
    apiClient.get<{
      message_id:      string;
      request_header:  string | null;
      request_body:    string | null;
      response_header: string | null;
      response_body:   string | null;
    }>(`/findings/${id}/http-message/${messageId}`).then((r) => r.data),
  update: (id: string, data: UpdateFindingRequest) =>
    apiClient.patch<Finding>(`/findings/${id}`, data).then((r) => r.data),
  verify: (id: string) =>
    apiClient.post<{
      confirmed: boolean;
      confidence: string;
      evidence: Record<string, unknown>;
      finding: Finding;
    }>(`/findings/${id}/verify`).then((r) => r.data),
  analyse: (id: string, force = false) =>
    apiClient.post<{
      analysis: {
        summary:      string;
        impact:       string;
        remediation:  string[];
        risk_context: string;
      };
      aiAnalysedAt: string;
    }>(
      `/findings/${id}/analyse`,
      {},
      { params: force ? { force: "true" } : undefined, timeout: 200_000 },
    ).then((r) => r.data),
  /**
   * Dashboard summary counts. Pass `scanType` (comma-joined) to scope
   * severity / status / confidence breakdowns to a subset (e.g. "code"
   * vs "web" tab). `scanTypeCounts` always returns the full unfiltered
   * breakdown so the tab badges themselves don't depend on the active tab.
   */
  stats: (scanType?: string) =>
    apiClient.get<{
      severityCounts: Array<{ severity: string; _count: number }>;
      scanTypeCounts: Array<{ scanType: string; _count: number }>;
      statusCounts: Array<{ status: string; _count: number }>;
      confidenceCounts: Array<{ confidence: string; _count: number }>;
    }>("/findings/summary/stats", { params: scanType ? { scanType } : undefined }).then((r) => r.data),
  topTargets: (limit = 5) =>
    apiClient.get<Array<{
      targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN";
      targetId:   string;
      targetName: string;
      count:      number;
    }>>("/findings/summary/top-targets", { params: { limit } }).then((r) => r.data),
  topRules: (limit = 5) =>
    apiClient.get<Array<{
      ruleId:   string;
      scanType: string;
      title:    string;
      count:    number;
    }>>("/findings/summary/top-rules", { params: { limit } }).then((r) => r.data),
  // Bulk status update; `status` applies to all ids in one request
  bulkUpdate: (ids: string[], status: "OPEN"|"ACKNOWLEDGED"|"FALSE_POSITIVE"|"FIXED"|"IGNORED") =>
    apiClient.post<{ updated: number }>("/findings/bulk", { ids, status }).then((r) => r.data),
  // Bulk create internal tickets from findings (skips findings already ticketed)
  bulkCreateTickets: (ids: string[]) =>
    apiClient.post<{ created: number; skipped: number }>("/findings/bulk-tickets", { ids }).then((r) => r.data),
  // Per-sub-issue status change (merged SAST/DAST/PENTEST/SECRET only).
  // Returns the updated map so callers can reconcile without a refetch.
  updateSubStatus: (id: string, subIndex: number, status: "OPEN"|"ACKNOWLEDGED"|"FALSE_POSITIVE"|"FIXED"|"IGNORED") =>
    apiClient.patch<{ id: string; subIndex: number; status: string; subStatus: Record<string, string> }>(
      `/findings/${id}/sub/${subIndex}`,
      { status },
    ).then((r) => r.data),
  // CSV export (returns the browser-facing URL so callers can trigger download)
  exportCsvUrl: (params?: FindingFilterParams) => {
    const usp = new URLSearchParams();
    Object.entries(params ?? {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === "") return;
      if (Array.isArray(v)) v.forEach((x) => usp.append(k, String(x)));
      else usp.append(k, String(v));
    });
    return `/api/findings/export.csv${usp.toString() ? `?${usp.toString()}` : ""}`;
  },
  // Phase 6 — Finding groups
  groups: () =>
    apiClient.get<FindingGroup[]>("/findings/groups").then((r) => r.data),
  groupInsight: (groupKey: string) =>
    apiClient.post<{ insight: string }>("/findings/groups/insight", { groupKey }, { timeout: 300_000 })
      .then((r) => r.data),
  // FP detection
  checkFp: (id: string, force = false) =>
    apiClient.post<{ analysis: FpAnalysis; aiFpAnalysedAt: string }>(
      `/findings/${id}/check-fp`,
      {},
      { params: force ? { force: "true" } : undefined, timeout: 200_000 },
    ).then((r) => r.data),
  // Fix suggestion. Pass `locationIndex` to generate a per-sub-location diff
  // for merged SAST findings (each sub-issue gets its own targeted fix
  // instead of all sharing the primary location's diff).
  fixSuggestion: (id: string, force = false, locationIndex?: number) =>
    apiClient.post<{ diff: string; aiFixSuggestedAt: string }>(
      `/findings/${id}/fix`,
      {},
      {
        params: {
          ...(force ? { force: "true" } : {}),
          ...(locationIndex != null ? { locationIndex: String(locationIndex) } : {}),
        },
        timeout: 700_000, // 10 min — qwen2.5-coder:7b cold call ~520s + buffer
      },
    ).then((r) => r.data),
};

// ── Tickets ───────────────────────────────────────────────────────────────

export const ticketsApi = {
  list: (params?: { status?: string; page?: number; limit?: number }) =>
    apiClient.get<PaginatedResponse<Ticket>>("/tickets", { params }).then((r) => r.data),
  get: (id: string) => apiClient.get<Ticket>(`/tickets/${id}`).then((r) => r.data),
  create: (data: CreateTicketRequest) =>
    apiClient.post<Ticket>("/tickets", data).then((r) => r.data),
  update: (id: string, data: UpdateTicketRequest) =>
    apiClient.patch<Ticket>(`/tickets/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/tickets/${id}`),
};

// ── Reports ───────────────────────────────────────────────────────────────

export interface ReportMeta {
  id:          string;
  scanJobId:   string | null;
  targetType:  string;
  targetId:    string;
  trigger:     "ON_SCAN_COMPLETE" | "MANUAL";
  title:       string;
  generatedAt: string;
  metadata: {
    targetName:        string;
    targetType:        string;
    riskScore:         number | null;
    riskGrade:         string;
    CRITICAL:          number;
    HIGH:              number;
    MEDIUM:            number;
    LOW:               number;
    INFO:              number;
    totalFindings:     number;
    openCount:         number;
    acknowledgedCount: number;
    fixedCount:        number;
    scanTypes:         string[];
  };
}

export const reportsApi = {
  list: (page = 1, limit = 20) =>
    apiClient.get<{ data: ReportMeta[]; total: number; page: number; pages: number }>(
      "/reports", { params: { page, limit } }
    ).then((r) => r.data),

  downloadUrl: (id: string) => `/api/reports/${id}/html`,

  generate: (scanJobId: string) =>
    apiClient.post<{ queued: boolean; message: string }>("/reports/generate", { scanJobId })
      .then((r) => r.data),

  delete: (id: string) =>
    apiClient.delete<{ success: boolean }>(`/reports/${id}`).then((r) => r.data),
};

// ── Suppressions ──────────────────────────────────────────────────────────

export interface Suppression {
  id:           string;
  orgId:        string;
  fingerprint:  string;
  reason:       string;
  expiresAt:    string | null;
  approvedById: string;
  createdAt:    string;
  revokedAt:    string | null;
  revokedById:  string | null;
}

export const suppressionsApi = {
  list: (active = true) =>
    apiClient.get<Suppression[]>("/suppressions", { params: { active } }).then((r) => r.data),
  create: (data: { fingerprint: string; reason: string; expiresAt?: string | null }) =>
    apiClient.post<Suppression>("/suppressions", data).then((r) => r.data),
  revoke: (id: string) => apiClient.delete(`/suppressions/${id}`).then((r) => r.data),
};

// ── SBOM ──────────────────────────────────────────────────────────────────

export type SbomFormat = "cyclonedx" | "spdx";

export const sbomApi = {
  repoUrl:      (id: string, format: SbomFormat = "cyclonedx") =>
                  `/api/repos/${id}/sbom${format === "spdx" ? "?format=spdx" : ""}`,
  containerUrl: (id: string, format: SbomFormat = "cyclonedx") =>
                  `/api/containers/${id}/sbom${format === "spdx" ? "?format=spdx" : ""}`,
};

// ── Integrations ──────────────────────────────────────────────────────────

export const integrationsApi = {
  getJira: () => apiClient.get<Integration | null>("/integrations/jira").then((r) => r.data),
  saveJira: (data: JiraIntegrationConfig) =>
    apiClient.put("/integrations/jira", data).then((r) => r.data),
  deleteJira: () => apiClient.delete("/integrations/jira"),

  getSlack: () => apiClient.get<Integration | null>("/integrations/slack").then((r) => r.data),
  saveSlack: (data: SlackIntegrationConfig) =>
    apiClient.put("/integrations/slack", data).then((r) => r.data),
  deleteSlack: () => apiClient.delete("/integrations/slack"),

  getTeams: () => apiClient.get<Integration | null>("/integrations/teams").then((r) => r.data),
  saveTeams: (data: TeamsIntegrationConfig) =>
    apiClient.put("/integrations/teams", data).then((r) => r.data),
  deleteTeams: () => apiClient.delete("/integrations/teams"),
};

// ── AI Providers ──────────────────────────────────────────────────────────

export type AIProviderType   = "ANTHROPIC" | "OPENAI" | "GEMINI" | "OLLAMA";
export type AIServiceName    =
  | "ANALYSE_FINDING" | "FP_TRIAGE" | "FIX_SUGGESTION"
  | "SCAN_SUMMARY"    | "RISK_SCORE" | "CHAT" | "GROUP_INSIGHT";

export interface AIProvider {
  id:           string;
  type:         AIProviderType;
  defaultModel: string;
  baseUrl:      string | null;
  isActive:     boolean;
  isDefault:    boolean;
  hasApiKey:    boolean;
  createdAt:    string;
  updatedAt:    string;
}

export interface AIProviderUpsert {
  apiKey?:      string;
  defaultModel: string;
  baseUrl?:     string;
  isDefault?:   boolean;
}

export interface AIServiceRouting {
  id:            string;
  service:       AIServiceName;
  providerId:    string;
  providerType:  AIProviderType;
  modelOverride: string | null;
  defaultModel:  string;
}

export interface AITestResult {
  ok:        boolean;
  provider?: AIProviderType;
  model?:    string;
  latencyMs?: number;
  tokens?:   { input: number; output: number };
  error?:    string;
  message?:  string;
}

export interface AIUsageRollup {
  since:      string;
  totals: {
    _count: number;
    _sum: { inputTokens: number | null; outputTokens: number | null;
            cachedInputTokens: number | null; costUsd: string | null; };
  } | null;
  byService:  Array<{
    service: AIServiceName;
    _count: number;
    _sum: { inputTokens: number | null; outputTokens: number | null; costUsd: string | null };
  }>;
  byProvider: Array<{
    providerType: AIProviderType;
    model:        string;
    _count: number;
    _sum: { inputTokens: number | null; outputTokens: number | null; costUsd: string | null };
  }>;
}

export const aiProvidersApi = {
  list:     () => apiClient.get<AIProvider[]>("/ai-providers").then((r) => r.data),
  upsert:   (type: AIProviderType, data: AIProviderUpsert) =>
              apiClient.put(`/ai-providers/${type}`, data).then((r) => r.data),
  remove:   (type: AIProviderType) => apiClient.delete(`/ai-providers/${type}`),
  setDefault: (type: AIProviderType) =>
              apiClient.post(`/ai-providers/${type}/default`).then((r) => r.data),
  test:     (type: AIProviderType) =>
              apiClient.post<AITestResult>(`/ai-providers/${type}/test`).then((r) => r.data),

  routings:        () => apiClient.get<AIServiceRouting[]>("/ai-providers/routings").then((r) => r.data),
  setRouting:      (service: AIServiceName, data: { providerId: string; modelOverride?: string }) =>
                     apiClient.put(`/ai-providers/routings/${service}`, data).then((r) => r.data),
  clearRouting:    (service: AIServiceName) =>
                     apiClient.delete(`/ai-providers/routings/${service}`).then((r) => r.data),

  usage: () => apiClient.get<AIUsageRollup>("/ai-providers/usage").then((r) => r.data),
};

// ── Audit log ─────────────────────────────────────────────────────────────

export interface AuditEvent {
  id:           string;
  orgId:        string;
  userId:       string;
  action:       string;
  resourceType: string;
  resourceId:   string | null;
  metadata:     Record<string, unknown>;
  createdAt:    string;
  user:         { id: string; username: string; avatarUrl: string | null } | null;
}

export interface AuditListResponse {
  rows:   AuditEvent[];
  total:  number;
  limit:  number;
  offset: number;
}

export interface AuditFilters {
  actionPrefix?: string;
  resourceType?: string;
  userId?:       string;
  fromDate?:     string;
  toDate?:       string;
  limit?:        number;
  offset?:       number;
}

export const auditApi = {
  list: (filters: AuditFilters = {}) =>
    apiClient
      .get<AuditListResponse>("/audit", { params: filters })
      .then((r) => r.data),

  /** Returns the export URL — caller should `window.location` to it (sets attachment headers). */
  exportCsvUrl: (filters: AuditFilters = {}): string => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(filters)) {
      if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
    }
    const qs = params.toString();
    return `/api/audit/export.csv${qs ? `?${qs}` : ""}`;
  },
};

// ── Members + invitations ─────────────────────────────────────────────────

export type MemberRole = "OWNER" | "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";

export interface Member {
  userId:    string;
  username:  string;
  email:     string | null;
  avatarUrl: string | null;
  role:      MemberRole;
  joinedAt:  string;
  isYou:     boolean;
}

export interface Invitation {
  id:             string;
  githubUsername: string;
  role:           MemberRole;
  expiresAt:      string;
  createdAt:      string;
  invitedBy:      { id: string; username: string; avatarUrl: string | null } | null;
}

export const membersApi = {
  list:        () => apiClient.get<{ members: Member[] }>("/members").then((r) => r.data.members),
  changeRole:  (userId: string, role: MemberRole) =>
                 apiClient.patch(`/members/${userId}`, { role }).then((r) => r.data),
  remove:      (userId: string) => apiClient.delete(`/members/${userId}`).then((r) => r.data),

  listInvitations: () =>
    apiClient.get<{ invitations: Invitation[] }>("/members/invitations").then((r) => r.data.invitations),
  createInvitation: (data: { githubUsername: string; role: MemberRole; expiresInDays?: number }) =>
    apiClient.post<Invitation>("/members/invitations", data).then((r) => r.data),
  revokeInvitation: (id: string) =>
    apiClient.delete(`/members/invitations/${id}`).then((r) => r.data),
};

// ── SSO (OIDC) configuration ─────────────────────────────────────────────

export interface SsoConfigView {
  id:                  string;
  issuerUrl:           string;
  clientId:            string;
  clientSecretSet:     boolean;
  allowedEmailDomains: string[];
  groupRoleMapping:    Record<string, MemberRole>;
  defaultRole:         MemberRole;
  isActive:            boolean;
  updatedAt:           string;
}

/**
 * Response shape from GET /api/sso. The redirect URI is server-derived
 * (API_PUBLIC_URL + /auth/sso/callback) so the UI can display the exact
 * URL the operator must register at their IdP — returned even when no
 * config exists yet (operator needs it BEFORE saving BreachLens config).
 */
export interface SsoSettingsResponse {
  redirectUri: string;
  config:      SsoConfigView | null;
}

export interface SsoUpsert {
  issuerUrl:           string;
  clientId:            string;
  /** Optional on update — omit to preserve the existing encrypted value. */
  clientSecret?:       string;
  allowedEmailDomains: string[];
  groupRoleMapping:    Record<string, MemberRole>;
  defaultRole:         MemberRole;
  isActive:            boolean;
}

export interface SsoTestResult {
  ok:                    boolean;
  error?:                string;
  message?:              string;
  latencyMs:             number;
  issuer?:               string;
  authorizationEndpoint?: string;
  tokenEndpoint?:        string;
  userinfoEndpoint?:     string | null;
  jwksUri?:              string;
  scopesSupported?:      string[];
}

export const ssoApi = {
  get:    () => apiClient.get<SsoSettingsResponse>("/sso").then((r) => r.data),
  save:   (data: SsoUpsert) => apiClient.put("/sso", data).then((r) => r.data),
  remove: () => apiClient.delete("/sso").then((r) => r.data),
  test:   (issuerUrl: string) =>
            apiClient.post<SsoTestResult>("/sso/test", { issuerUrl }).then((r) => r.data),
};

// ── Admin (queues) ────────────────────────────────────────────────────────

export interface QueueCounts {
  waiting:   number;
  active:    number;
  completed: number;
  failed:    number;
  delayed:   number;
  paused:    number;
}

export interface FailedJob {
  id:           string;
  name:         string;
  attemptsMade: number;
  failedReason: string | null;
  timestamp:    number;
  finishedOn:   number | null;
  data:         unknown;
  stacktrace:   string[] | null;
}

export const adminApi = {
  listQueues: () =>
    apiClient.get<Array<{ name: string; counts: QueueCounts }>>("/admin/queues").then((r) => r.data),
  listFailed: (name: string, limit = 50) =>
    apiClient.get<FailedJob[]>(`/admin/queues/${name}/failed`, { params: { limit } }).then((r) => r.data),
  retryJob:   (name: string, jobId: string) =>
    apiClient.post<{ ok: boolean }>(`/admin/queues/${name}/jobs/${jobId}/retry`).then((r) => r.data),
  deleteJob:  (name: string, jobId: string) =>
    apiClient.delete<{ ok: boolean }>(`/admin/queues/${name}/jobs/${jobId}`).then((r) => r.data),
};

// ── Attack paths (Phase 27 Slice C) ──────────────────────────────────────

export const attackPathsApi = {
  list: (limit = 50) =>
    apiClient.get<AttackPathsListResponse>("/attack-paths", { params: { limit } }).then((r) => r.data),
  get: (groupId: string) =>
    apiClient.get<AttackPathSummary>(`/attack-paths/${encodeURIComponent(groupId)}`).then((r) => r.data),
};

// ── Compliance (Phase 16) ────────────────────────────────────────────────

export const complianceApi = {
  frameworks: () =>
    apiClient.get<FrameworksResponse>("/compliance/frameworks").then((r) => r.data),

  dashboard: (framework: ComplianceFramework) =>
    apiClient.get<FrameworkDashboard>(`/compliance/${framework}/dashboard`).then((r) => r.data),

  controlFindings: (
    framework: ComplianceFramework,
    code: string,
    opts: { status?: string; page?: number; limit?: number } = {},
  ) =>
    apiClient
      .get<ControlFindingsResponse>(
        `/compliance/${framework}/controls/${encodeURIComponent(code)}/findings`,
        { params: { status: opts.status ?? "OPEN", page: opts.page ?? 1, limit: opts.limit ?? 20 } },
      )
      .then((r) => r.data),
};
