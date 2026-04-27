/**
 * Seed compliance controls for Phase 16.
 *
 * Idempotent: re-running won't duplicate (uses upsert on the unique
 * (framework, code) constraint). Safe to run on every deploy or by
 * hand during development.
 *
 * What's seeded:
 *   - OWASP Top 10 2021 (10 controls — official CWE mappings from owasp.org)
 *   - SOC 2 Trust Services Criteria — CC6, CC7, CC8 (the AppSec-relevant
 *     subset; mappings are community-standard, no official CWE↔SOC2
 *     mapping exists)
 *   - PCI DSS 4.0 — Req 6 / 8 / 11 (AppSec subset; same caveat — no
 *     official CWE↔PCI mapping)
 *
 * Sources documented inline so an auditor can challenge specific
 * mappings and we can point at where they came from.
 *
 * Run with:
 *   docker compose exec -T -w //app/apps/api api node --import tsx \
 *     src/migrations/seedComplianceControls.ts
 */

import prisma from "../db.js";
import { logger } from "../logger.js";
import type { ComplianceFramework } from "@prisma/client";

interface ControlSeed {
  code:        string;
  name:        string;
  description: string;
  category?:   string;
  cweIds:      number[];
  keywordTags?: string[];
}

interface FrameworkSeed {
  framework: ComplianceFramework;
  controls:  ControlSeed[];
}

// ── OWASP Top 10 2021 — official CWE mappings from
//    https://owasp.org/Top10/A0X_2021-…/  (each page lists its CWEs)
const OWASP_TOP_10_2021: FrameworkSeed = {
  framework: "OWASP_TOP_10",
  controls: [
    {
      code:        "A01:2021",
      name:        "Broken Access Control",
      description: "Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers exploit these flaws to access unauthorized functionality and/or data.",
      cweIds:      [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
      keywordTags: ["broken access control", "idor", "directory traversal", "missing authorization"],
    },
    {
      code:        "A02:2021",
      name:        "Cryptographic Failures",
      description: "Failures related to cryptography (or lack thereof) which often lead to exposure of sensitive data.",
      cweIds:      [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
      keywordTags: ["weak crypto", "cleartext", "tls", "ssl", "weak hash", "weak cipher"],
    },
    {
      code:        "A03:2021",
      name:        "Injection",
      description: "User-supplied data is not validated, filtered, or sanitised by the application. Includes SQL, NoSQL, OS command, LDAP, and other injection types.",
      cweIds:      [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
      keywordTags: ["sql injection", "sqli", "xss", "command injection", "ldap injection", "xxe"],
    },
    {
      code:        "A04:2021",
      name:        "Insecure Design",
      description: "Risks related to design and architectural flaws — missing or ineffective control design, threat modelling, secure design patterns.",
      cweIds:      [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
      keywordTags: ["insecure design", "missing rate limiting", "business logic"],
    },
    {
      code:        "A05:2021",
      name:        "Security Misconfiguration",
      description: "Missing appropriate security hardening, improperly configured permissions, default accounts/passwords still active, error handling that reveals stack traces.",
      cweIds:      [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
      keywordTags: ["misconfiguration", "default password", "verbose error", "cors", "exposed admin"],
    },
    {
      code:        "A06:2021",
      name:        "Vulnerable and Outdated Components",
      description: "Using components (libraries, frameworks, modules) with known vulnerabilities. Common in SCA findings — the library has a CVE, the app uses it.",
      cweIds:      [937, 1035, 1104],
      keywordTags: ["outdated", "vulnerable dependency", "cve-", "deprecated"],
    },
    {
      code:        "A07:2021",
      name:        "Identification and Authentication Failures",
      description: "Confirmation of user's identity, authentication, and session management — when these are weak or missing, attackers can impersonate users.",
      cweIds:      [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
      keywordTags: ["weak authentication", "session fixation", "credential stuffing", "hardcoded password"],
    },
    {
      code:        "A08:2021",
      name:        "Software and Data Integrity Failures",
      description: "Code and infrastructure that does not protect against integrity violations — e.g. relying on plugins/libraries from untrusted CDNs, insecure CI/CD pipeline, insecure deserialisation.",
      cweIds:      [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
      keywordTags: ["deserialization", "supply chain", "integrity", "unsigned"],
    },
    {
      code:        "A09:2021",
      name:        "Security Logging and Monitoring Failures",
      description: "Insufficient logging, detection, monitoring, and active response — attackers can probe and exploit without being detected.",
      cweIds:      [117, 223, 532, 778],
      keywordTags: ["logging", "missing audit", "log injection"],
    },
    {
      code:        "A10:2021",
      name:        "Server-Side Request Forgery (SSRF)",
      description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL — attackers can coerce the application to send requests to unintended destinations.",
      cweIds:      [918],
      keywordTags: ["ssrf", "server-side request forgery"],
    },
  ],
};

// ── SOC 2 — Common Criteria CC6 / CC7 / CC8 ──────────────────────────────
// SOC 2 has no official CWE mapping (it's a controls framework, not a vuln
// taxonomy). Mappings below are community-standard interpretations — the
// CWE list per control reflects which findings would constitute evidence
// of a control gap. Auditors can challenge any specific mapping; the seed
// is a defensible starting point.
const SOC_2: FrameworkSeed = {
  framework: "SOC2",
  controls: [
    {
      code:        "CC6.1",
      name:        "Logical and physical access controls",
      description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [284, 285, 862, 863, 939, 1244],
      keywordTags: ["broken access control", "missing authorization", "idor"],
    },
    {
      code:        "CC6.2",
      name:        "User registration and authorization",
      description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [287, 290, 304, 306, 307, 521, 798, 916],
      keywordTags: ["weak authentication", "default credentials", "hardcoded password"],
    },
    {
      code:        "CC6.3",
      name:        "Access removal and lifecycle",
      description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [613, 384],
      keywordTags: ["session expiration", "session fixation", "stale session"],
    },
    {
      code:        "CC6.6",
      name:        "Logical access security from external sources",
      description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [200, 201, 918, 601, 444],
      keywordTags: ["ssrf", "open redirect", "info disclosure", "request smuggling"],
    },
    {
      code:        "CC6.7",
      name:        "Transmission of confidential information",
      description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [319, 326, 327, 757, 720],
      keywordTags: ["cleartext", "weak tls", "weak ssl", "unencrypted"],
    },
    {
      code:        "CC6.8",
      name:        "Prevention and detection of unauthorized software",
      description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
      category:    "CC6 — Logical and Physical Access Controls",
      cweIds:      [494, 502, 829, 830, 506],
      keywordTags: ["deserialization", "supply chain", "unsigned download"],
    },
    {
      code:        "CC7.1",
      name:        "Detection of new vulnerabilities",
      description: "To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
      category:    "CC7 — System Operations",
      cweIds:      [937, 1035, 1104, 16],
      keywordTags: ["outdated", "vulnerable dependency", "cve-", "misconfiguration"],
    },
    {
      code:        "CC7.2",
      name:        "System monitoring for anomalies",
      description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events.",
      category:    "CC7 — System Operations",
      cweIds:      [117, 223, 532, 778],
      keywordTags: ["logging", "missing audit", "log injection"],
    },
    {
      code:        "CC7.3",
      name:        "Security incident response",
      description: "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.",
      category:    "CC7 — System Operations",
      cweIds:      [223, 778],
      keywordTags: ["incident", "missing alerting"],
    },
    {
      code:        "CC8.1",
      name:        "Change management — secure software development",
      description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
      category:    "CC8 — Change Management",
      // Maps broadly to OWASP Top 10 — every AppSec finding is evidence of a
      // gap in the secure-development control. Use a wide CWE set.
      cweIds:      [20, 22, 78, 79, 89, 94, 287, 306, 319, 327, 352, 502, 611, 798, 862, 863, 918],
      keywordTags: ["sql injection", "xss", "command injection", "csrf", "ssrf", "deserialization"],
    },
  ],
};

// ── PCI DSS 4.0 — Requirement 6 / 8 / 11 (AppSec subset) ──────────────────
// Same caveat as SOC 2 — PCI DSS doesn't publish official CWE mappings.
// Mappings below interpret each requirement against the most direct CWE
// matches (e.g. Req 6.2.4 "common software attacks" → OWASP Top 10 CWEs).
const PCI_DSS_4: FrameworkSeed = {
  framework: "PCI_DSS",
  controls: [
    {
      code:        "Req-6.2.4",
      name:        "Software engineered to prevent common attacks",
      description: "Bespoke and custom software is developed to prevent the common types of software attacks: injection, broken access control, sensitive data exposure, etc.",
      category:    "Req 6 — Develop and Maintain Secure Systems and Software",
      // Catch-all: the OWASP Top 10 union covers what PCI calls "common attacks"
      cweIds:      [22, 78, 79, 89, 90, 94, 200, 287, 306, 326, 327, 352, 502, 611, 862, 863, 918],
      keywordTags: ["sql injection", "xss", "command injection", "broken access control"],
    },
    {
      code:        "Req-6.3.1",
      name:        "Identify security vulnerabilities",
      description: "Security vulnerabilities are identified and addressed via a defined process that includes assigning a risk ranking, identifying new vulnerabilities, and addressing them via patches or risk treatment.",
      category:    "Req 6 — Develop and Maintain Secure Systems and Software",
      cweIds:      [937, 1035, 1104],
      keywordTags: ["outdated", "vulnerable dependency", "cve-"],
    },
    {
      code:        "Req-6.4.1",
      name:        "Public-facing web app threats addressed",
      description: "Public-facing web applications are protected against attacks via either an automated technical solution that detects and prevents web-based attacks (WAF) OR a manual / automated vulnerability assessment.",
      category:    "Req 6 — Develop and Maintain Secure Systems and Software",
      cweIds:      [22, 79, 89, 352, 444, 601, 918],
      keywordTags: ["xss", "sql injection", "csrf", "ssrf", "open redirect"],
    },
    {
      code:        "Req-8.3.6",
      name:        "Authentication factors not transmitted in cleartext",
      description: "Authentication factors are not transmitted in cleartext or stored using reversible encryption.",
      category:    "Req 8 — Identify Users and Authenticate Access",
      cweIds:      [319, 326, 327, 916, 798],
      keywordTags: ["cleartext password", "weak hash", "hardcoded credentials"],
    },
    {
      code:        "Req-8.3.7",
      name:        "Strong cryptography for authentication",
      description: "Authentication factors are protected during storage using strong cryptography. Account lockout, MFA, and other strong-auth controls are in place.",
      category:    "Req 8 — Identify Users and Authenticate Access",
      cweIds:      [287, 290, 307, 521, 798, 916],
      keywordTags: ["weak authentication", "missing mfa", "default credentials"],
    },
    {
      code:        "Req-11.3.1",
      name:        "Internal vulnerability scans run regularly",
      description: "Internal vulnerability scans are performed at least once every three months and after any significant change. All high-risk and critical vulnerabilities (per the entity's vulnerability risk rankings) are resolved.",
      category:    "Req 11 — Test Security of Systems and Networks Regularly",
      // Maps to anything an SCA / SAST scan would surface — broad
      cweIds:      [937, 1035, 1104, 78, 79, 89, 798],
      keywordTags: ["outdated", "vulnerable dependency", "sql injection", "xss"],
    },
  ],
};

// ── Run ──────────────────────────────────────────────────────────────────

async function main() {
  const allSeeds = [OWASP_TOP_10_2021, SOC_2, PCI_DSS_4];
  let total = 0;
  let created = 0;
  let updated = 0;

  for (const fs of allSeeds) {
    for (let i = 0; i < fs.controls.length; i++) {
      const c = fs.controls[i]!;
      const existing = await prisma.complianceControl.findUnique({
        where: { framework_code: { framework: fs.framework, code: c.code } },
      });

      await prisma.complianceControl.upsert({
        where: { framework_code: { framework: fs.framework, code: c.code } },
        update: {
          name:        c.name,
          description: c.description,
          category:    c.category ?? null,
          cweIds:      c.cweIds,
          keywordTags: c.keywordTags ?? [],
          sortOrder:   i,
        },
        create: {
          framework:   fs.framework,
          code:        c.code,
          name:        c.name,
          description: c.description,
          category:    c.category ?? null,
          cweIds:      c.cweIds,
          keywordTags: c.keywordTags ?? [],
          sortOrder:   i,
        },
      });

      total++;
      if (existing) updated++;
      else created++;
    }
  }

  logger.info("[seed] compliance controls upserted", {
    total,
    created,
    updated,
    frameworks: allSeeds.map((s) => s.framework),
  });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    logger.error("[seed] compliance controls failed", { error: (err as Error).message });
    process.exit(1);
  });
