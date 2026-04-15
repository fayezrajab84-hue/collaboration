import type {
  FindingStatus,
  IntegrationType,
  OrgType,
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
  addedAt: Date;
  findingCounts?: FindingCounts;
}

export interface Container {
  id: string;
  orgId: string;
  imageRef: string;
  registry: string | null;
  lastScannedAt: Date | null;
  addedAt: Date;
  findingCounts?: FindingCounts;
}

export interface Domain {
  id: string;
  orgId: string;
  domain: string;
  lastScannedAt: Date | null;
  addedAt: Date;
  findingCounts?: FindingCounts;
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
  firstSeen: Date;
  lastSeen: Date;
  resolvedAt: Date | null;
  // Joined from related target (present in list/detail responses)
  targetName?: string;
  repository?: { fullName: string } | null;
  container?: { imageRef: string } | null;
  domain?: { domain: string } | null;
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

export interface Integration {
  id: string;
  orgId: string;
  type: IntegrationType;
  isActive: boolean;
  createdAt: Date;
  // Config shape per type (returned masked to client)
  maskedConfig?: Record<string, string>;
}
