export type ScanType =
  | "SAST" | "SCA" | "SECRET" | "IAC" | "CONTAINER" | "DAST" | "PENTEST" | "PENTEST_FULL"
  // Phase 28 Slice A — Wazuh runtime alerts ingested as Findings.
  | "RUNTIME"
  // Phase 29 Slice A — Cloud Security Posture Management.
  | "CLOUD"
  // Phase 29 Slice C1 — GitHub posture audit via Prowler `--provider github`.
  // 24 checks across organization (5) + repository (18) + githubactions (1).
  | "GITHUB_POSTURE";

// Phase 28 Slice A — Wazuh agent health.
export type AgentStatus = "HEALTHY" | "STALE" | "OFFLINE" | "UNKNOWN";

// Phase 27.5 — Application boundary for correlation.
export type ApplicationEnv = "DEVELOPMENT" | "STAGING" | "PRODUCTION";
export type Criticality    = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type PentestDepth = "QUICK" | "STANDARD" | "AGGRESSIVE";
export type Confidence = "CONFIRMED" | "LIKELY" | "POSSIBLE";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "FALSE_POSITIVE" | "FIXED" | "IGNORED";

export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";

export type TargetType = "REPOSITORY" | "CONTAINER" | "DOMAIN" | "CLOUD_ACCOUNT" | "GITHUB_ACCOUNT";

// Phase 29 — Cloud provider enumeration. AZURE is Slice A; AWS/GCP are
// future-slice expansions reusing the CloudAccount model.
export type CloudProvider = "AZURE" | "AWS" | "GCP";

// Phase 29 Slice C1 — distinguishes a personal GitHub user account from
// an organization. Some Prowler checks (e.g. MFA required) only fire on
// ORGANIZATION accounts.
export type GitHubAccountType = "USER" | "ORGANIZATION";

export type TicketStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "CLOSED";

export type Priority = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type IntegrationType = "JIRA" | "SLACK" | "MICROSOFT_TEAMS";

export type OrgType = "PERSONAL" | "TEAM";

export type Role = "OWNER" | "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER" | "MEMBER";

// Role hierarchy — higher number = more permissions. MEMBER is legacy = DEVELOPER.
export const ROLE_RANK: Record<Role, number> = {
  OWNER:     5,
  ADMIN:     4,
  SECURITY:  3,
  DEVELOPER: 2,
  MEMBER:    2,
  VIEWER:    1,
};

export function roleAtLeast(role: Role, min: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}
