export enum ScanType {
  SAST = "SAST",
  SCA = "SCA",
  SECRET = "SECRET",
  IAC = "IAC",
  CONTAINER = "CONTAINER",
  DAST = "DAST",
  PENTEST = "PENTEST",
}

export enum Severity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO",
}

export enum FindingStatus {
  OPEN = "OPEN",
  ACKNOWLEDGED = "ACKNOWLEDGED",
  FALSE_POSITIVE = "FALSE_POSITIVE",
  FIXED = "FIXED",
}

export enum ScanStatus {
  PENDING = "PENDING",
  RUNNING = "RUNNING",
  COMPLETED = "COMPLETED",
  FAILED = "FAILED",
  CANCELLED = "CANCELLED",
}

export enum TargetType {
  REPOSITORY = "REPOSITORY",
  CONTAINER = "CONTAINER",
  DOMAIN = "DOMAIN",
}

export enum TicketStatus {
  OPEN = "OPEN",
  IN_PROGRESS = "IN_PROGRESS",
  RESOLVED = "RESOLVED",
  CLOSED = "CLOSED",
}

export enum Priority {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
}

export enum IntegrationType {
  JIRA = "JIRA",
  SLACK = "SLACK",
  MICROSOFT_TEAMS = "MICROSOFT_TEAMS",
}

export enum OrgType {
  PERSONAL = "PERSONAL",
  TEAM = "TEAM",
}

export enum Role {
  OWNER = "OWNER",
  ADMIN = "ADMIN",
  MEMBER = "MEMBER",
}
