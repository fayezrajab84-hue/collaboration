export type ScanType =
  | "SAST" | "SCA" | "SECRET" | "IAC" | "CONTAINER" | "DAST" | "PENTEST" | "PENTEST_FULL"
  // Phase 28 Slice A — Wazuh runtime alerts ingested as Findings.
  | "RUNTIME";

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

export type TargetType = "REPOSITORY" | "CONTAINER" | "DOMAIN";

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
