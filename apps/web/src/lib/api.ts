import axios from "axios";
import type {
  Repository, Container, Domain, ScanJob, Finding, Ticket, Integration,
  CreateRepoRequest, CreateContainerRequest, CreateDomainRequest,
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
  me: () => apiClient.get<AuthMeResponse>("/../../auth/me").then((r) => r.data),
  logout: () => apiClient.post("/../../auth/logout"),
};

// ── Repositories ──────────────────────────────────────────────────────────

export const reposApi = {
  list: () => apiClient.get<Repository[]>("/repos").then((r) => r.data),
  get: (id: string) => apiClient.get<Repository>(`/repos/${id}`).then((r) => r.data),
  create: (data: CreateRepoRequest) => apiClient.post<Repository>("/repos", data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/repos/${id}`),
  triggerScan: (id: string, data?: TriggerScanRequest) =>
    apiClient.post<TriggerScanResponse>(`/repos/${id}/scan`, data ?? {}).then((r) => r.data),
};

// ── Containers ────────────────────────────────────────────────────────────

export const containersApi = {
  list: () => apiClient.get<Container[]>("/containers").then((r) => r.data),
  get: (id: string) => apiClient.get<Container>(`/containers/${id}`).then((r) => r.data),
  create: (data: CreateContainerRequest) => apiClient.post<Container>("/containers", data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/containers/${id}`),
  triggerScan: (id: string) =>
    apiClient.post<TriggerScanResponse>(`/containers/${id}/scan`).then((r) => r.data),
};

// ── Domains ───────────────────────────────────────────────────────────────

export const domainsApi = {
  list: () => apiClient.get<Domain[]>("/domains").then((r) => r.data),
  get: (id: string) => apiClient.get<Domain>(`/domains/${id}`).then((r) => r.data),
  create: (data: CreateDomainRequest) => apiClient.post<Domain>("/domains", data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/domains/${id}`),
  triggerScan: (id: string) =>
    apiClient.post<TriggerScanResponse>(`/domains/${id}/scan`).then((r) => r.data),
};

// ── Scans ─────────────────────────────────────────────────────────────────

export const scansApi = {
  list: (page = 1, limit = 20) =>
    apiClient.get<PaginatedResponse<ScanJob>>("/scans", { params: { page, limit } }).then((r) => r.data),
  get: (id: string) => apiClient.get<ScanJob>(`/scans/${id}`).then((r) => r.data),
};

// ── Findings ──────────────────────────────────────────────────────────────

export const findingsApi = {
  list: (params?: FindingFilterParams) =>
    apiClient.get<PaginatedResponse<Finding>>("/findings", { params }).then((r) => r.data),
  get: (id: string) => apiClient.get<Finding>(`/findings/${id}`).then((r) => r.data),
  update: (id: string, data: UpdateFindingRequest) =>
    apiClient.patch<Finding>(`/findings/${id}`, data).then((r) => r.data),
  stats: () =>
    apiClient.get<{
      severityCounts: Array<{ severity: string; _count: number }>;
      scanTypeCounts: Array<{ scanType: string; _count: number }>;
      statusCounts: Array<{ status: string; _count: number }>;
    }>("/findings/summary/stats").then((r) => r.data),
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
