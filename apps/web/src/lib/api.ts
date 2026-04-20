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
  PaginatedResponse, AuthMeResponse,
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
};

// ── Repositories ──────────────────────────────────────────────────────────

export const reposApi = {
  list: () => apiClient.get<Repository[]>("/repos").then((r) => r.data),
  get: (id: string) => apiClient.get<Repository>(`/repos/${id}`).then((r) => r.data),
  create: (data: CreateRepoRequest) => apiClient.post<Repository>("/repos", data).then((r) => r.data),
  update: (id: string, data: UpdateRepoRequest) => apiClient.patch<Repository>(`/repos/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/repos/${id}`),
  triggerScan: (id: string, data?: TriggerScanRequest) =>
    apiClient.post<TriggerScanResponse>(`/repos/${id}/scan`, data ?? {}).then((r) => r.data),
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
  deleteApiSpec: (id: string) =>
    apiClient.delete(`/domains/${id}/apispec`).then((r) => r.data),
};

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
};

// ── Findings ──────────────────────────────────────────────────────────────

export const findingsApi = {
  list: (params?: FindingFilterParams) =>
    apiClient.get<PaginatedResponse<Finding>>("/findings", { params }).then((r) => r.data),
  get: (id: string) => apiClient.get<Finding>(`/findings/${id}`).then((r) => r.data),
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
  stats: () =>
    apiClient.get<{
      severityCounts: Array<{ severity: string; _count: number }>;
      scanTypeCounts: Array<{ scanType: string; _count: number }>;
      statusCounts: Array<{ status: string; _count: number }>;
      confidenceCounts: Array<{ confidence: string; _count: number }>;
    }>("/findings/summary/stats").then((r) => r.data),
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
  // Fix suggestion
  fixSuggestion: (id: string, force = false) =>
    apiClient.post<{ diff: string; aiFixSuggestedAt: string }>(
      `/findings/${id}/fix`,
      {},
      { params: force ? { force: "true" } : undefined, timeout: 300_000 },
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
