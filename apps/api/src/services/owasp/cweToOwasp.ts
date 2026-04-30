/**
 * Phase 29 Slice C1.5b — CWE → OWASP Top 10 (2021) family mapping.
 *
 * Operators recognise OWASP categories instantly ("we have an A03
 * Injection problem") in a way they don't recognise raw CWE numbers.
 * This service compresses the ~120 most-common CWEs in our scanner
 * output into the 10 OWASP families so the dashboard can surface
 * "where does my risk concentrate?" in audit-recognisable terms.
 *
 * Source: official OWASP Top 10 2021 contributing-CWE lists, cross-
 * referenced against CWE entries Semgrep / Trivy / Checkov / TruffleHog
 * actually emit on real codebases. Curated rather than exhaustive —
 * adding niche CWEs that never appear in our output would add noise
 * to the chart without affecting any operator triage decision.
 *
 * The pattern follows `services/mitre/cweToAttack.ts` (same shape:
 * curated lookup → fall-through default). Updates are intentional
 * code changes, not auto-derived from upstream — OWASP refines the
 * contributing CWEs occasionally and we want to control when those
 * refinements roll into our UI.
 */

export type OwaspFamily =
  | "A01" | "A02" | "A03" | "A04" | "A05"
  | "A06" | "A07" | "A08" | "A09" | "A10";

export interface OwaspFamilyMeta {
  code:        OwaspFamily;
  name:        string;
  description: string;
}

export const OWASP_FAMILIES: Record<OwaspFamily, OwaspFamilyMeta> = {
  A01: { code: "A01", name: "Broken Access Control",         description: "Authorization, IDOR, path traversal, privilege escalation" },
  A02: { code: "A02", name: "Cryptographic Failures",        description: "Weak crypto, cleartext sensitive data, missing TLS, hardcoded secrets in transit" },
  A03: { code: "A03", name: "Injection",                     description: "SQLi · XSS · command injection · eval · LDAP · NoSQL" },
  A04: { code: "A04", name: "Insecure Design",               description: "Threat modelling gaps, business logic flaws, missing rate limits" },
  A05: { code: "A05", name: "Security Misconfiguration",     description: "Default creds, verbose errors, missing hardening, XXE, exposed admin" },
  A06: { code: "A06", name: "Vulnerable & Outdated Components", description: "Known-CVE deps and libraries (most SCA findings live here)" },
  A07: { code: "A07", name: "Identification & Auth Failures", description: "Weak passwords, session fixation, missing MFA, broken auth flows" },
  A08: { code: "A08", name: "Software & Data Integrity Failures", description: "Insecure deserialization, supply-chain tampering, unsigned updates" },
  A09: { code: "A09", name: "Security Logging & Monitoring Failures", description: "Insufficient logs, log injection, leaked logs in error messages" },
  A10: { code: "A10", name: "Server-Side Request Forgery (SSRF)", description: "Untrusted URLs fetched server-side; cloud-metadata pivots" },
};

// Curated CWE → OWASP family lookup. CWEs not in the table fall through
// to the heuristic in `classifyCwe()` below. Updated quarterly as we see
// new CWEs land in scanner output.
const CWE_TO_OWASP: Record<string, OwaspFamily> = {
  // ── A01 Broken Access Control ────────────────────────────────────────
  "CWE-22":  "A01", // Path traversal
  "CWE-23":  "A01",
  "CWE-35":  "A01",
  "CWE-59":  "A01", // Symbolic link following
  "CWE-200": "A01", // Information exposure
  "CWE-201": "A01",
  "CWE-219": "A01",
  "CWE-264": "A01", // Permissions / privileges
  "CWE-275": "A01",
  "CWE-276": "A01",
  "CWE-284": "A01",
  "CWE-285": "A01", // Improper authorization
  "CWE-352": "A01", // CSRF
  "CWE-359": "A01",
  "CWE-377": "A01",
  "CWE-402": "A01",
  "CWE-425": "A01", // Direct request / forced browsing
  "CWE-441": "A01",
  "CWE-497": "A01",
  "CWE-538": "A01",
  "CWE-540": "A01",
  "CWE-548": "A01", // Directory listing
  "CWE-552": "A01",
  "CWE-566": "A01",
  "CWE-601": "A01", // Open redirect — sometimes A01, sometimes A04 — keeping with access
  "CWE-639": "A01", // IDOR
  "CWE-651": "A01",
  "CWE-668": "A01",
  "CWE-706": "A01",
  "CWE-862": "A01", // Missing authorization
  "CWE-863": "A01", // Incorrect authorization
  "CWE-913": "A01",
  "CWE-922": "A01",

  // ── A02 Cryptographic Failures ───────────────────────────────────────
  "CWE-261":  "A02",
  "CWE-296":  "A02",
  "CWE-310":  "A02",
  "CWE-311":  "A02", // Missing encryption of sensitive data
  "CWE-312":  "A02", // Cleartext storage of sensitive info
  "CWE-319":  "A02", // Cleartext transmission
  "CWE-321":  "A02", // Hardcoded crypto key
  "CWE-322":  "A02",
  "CWE-323":  "A02",
  "CWE-324":  "A02",
  "CWE-325":  "A02",
  "CWE-326":  "A02", // Inadequate encryption strength
  "CWE-327":  "A02", // Broken/risky crypto algorithm
  "CWE-328":  "A02", // Weak hash
  "CWE-329":  "A02",
  "CWE-330":  "A02", // Insufficient randomness
  "CWE-331":  "A02",
  "CWE-335":  "A02",
  "CWE-336":  "A02",
  "CWE-337":  "A02",
  "CWE-338":  "A02", // Cryptographic PRNG weakness
  "CWE-340":  "A02",
  "CWE-347":  "A02", // Improper signature verification
  "CWE-523":  "A02",
  "CWE-720":  "A02",
  "CWE-757":  "A02",
  "CWE-759":  "A02", // Use of one-way hash without salt
  "CWE-760":  "A02",
  "CWE-780":  "A02", // RSA without OAEP
  "CWE-818":  "A02",
  "CWE-916":  "A02", // Password hash too computationally cheap

  // ── A03 Injection ────────────────────────────────────────────────────
  "CWE-20":   "A03", // Improper input validation (broad — defaulting to A03 since most scanner output here is taint)
  "CWE-74":   "A03",
  "CWE-75":   "A03",
  "CWE-77":   "A03", // Command injection
  "CWE-78":   "A03", // OS command injection
  "CWE-79":   "A03", // XSS
  "CWE-80":   "A03",
  "CWE-83":   "A03",
  "CWE-87":   "A03",
  "CWE-88":   "A03", // Argument injection
  "CWE-89":   "A03", // SQL injection
  "CWE-90":   "A03", // LDAP injection
  "CWE-91":   "A03", // XML injection
  "CWE-93":   "A03",
  "CWE-94":   "A03", // Code injection
  "CWE-95":   "A03", // Eval injection
  "CWE-96":   "A03",
  "CWE-97":   "A03",
  "CWE-98":   "A03",
  "CWE-99":   "A03",
  "CWE-113":  "A03", // HTTP response splitting
  "CWE-116":  "A03",
  "CWE-138":  "A03",
  "CWE-184":  "A03",
  "CWE-470":  "A03", // Reflection injection
  "CWE-471":  "A03",
  "CWE-564":  "A03", // SQL injection: hibernate
  "CWE-643":  "A03", // XPath injection
  "CWE-644":  "A03",
  "CWE-652":  "A03", // XQuery injection
  "CWE-917":  "A03", // EL injection
  "CWE-943":  "A03", // NoSQL / other injection

  // ── A04 Insecure Design ──────────────────────────────────────────────
  "CWE-73":   "A04",
  "CWE-183":  "A04",
  "CWE-209":  "A04", // Information exposure through error messages
  "CWE-213":  "A04",
  "CWE-235":  "A04",
  "CWE-256":  "A04",
  "CWE-257":  "A04",
  "CWE-266":  "A04",
  "CWE-269":  "A04",
  "CWE-280":  "A04",
  "CWE-311":  "A04",
  "CWE-313":  "A04",
  "CWE-316":  "A04",
  "CWE-419":  "A04",
  "CWE-430":  "A04",
  "CWE-434":  "A04", // Unrestricted file upload
  "CWE-444":  "A04",
  "CWE-451":  "A04",
  "CWE-472":  "A04",
  "CWE-501":  "A04",
  "CWE-522":  "A04", // Insufficiently protected credentials
  "CWE-525":  "A04",
  "CWE-539":  "A04",
  "CWE-579":  "A04",
  "CWE-598":  "A04",
  "CWE-602":  "A04",
  "CWE-642":  "A04",
  "CWE-646":  "A04",
  "CWE-650":  "A04",
  "CWE-653":  "A04",
  "CWE-656":  "A04",
  "CWE-657":  "A04",
  "CWE-799":  "A04",
  "CWE-807":  "A04",
  "CWE-840":  "A04",
  "CWE-841":  "A04",
  "CWE-927":  "A04",
  "CWE-1021": "A04",
  "CWE-1173": "A04",
  "CWE-1333": "A04", // Inefficient regex (ReDoS) — design problem

  // ── A05 Security Misconfiguration ────────────────────────────────────
  "CWE-2":    "A05",
  "CWE-11":   "A05",
  "CWE-13":   "A05",
  "CWE-15":   "A05",
  "CWE-16":   "A05", // Configuration
  "CWE-260":  "A05",
  "CWE-315":  "A05",
  "CWE-520":  "A05",
  "CWE-526":  "A05",
  "CWE-537":  "A05",
  "CWE-541":  "A05",
  "CWE-547":  "A05",
  "CWE-611":  "A05", // XXE
  "CWE-614":  "A05",
  "CWE-756":  "A05",
  "CWE-776":  "A05",
  "CWE-942":  "A05", // Permissive CORS
  "CWE-1004": "A05",
  "CWE-1032": "A05",
  "CWE-1174": "A05",

  // ── A06 Vulnerable & Outdated Components ─────────────────────────────
  // Most SCA findings get here via the `defaultForScanType()` branch
  // below; CWE-1104 is the headline indicator.
  "CWE-1104": "A06",
  "CWE-937":  "A06",

  // ── A07 Identification & Authentication Failures ─────────────────────
  "CWE-255":  "A07",
  "CWE-259":  "A07", // Hardcoded password
  "CWE-287":  "A07", // Improper authentication
  "CWE-288":  "A07",
  "CWE-290":  "A07",
  "CWE-294":  "A07", // Authentication bypass by capture-replay
  "CWE-295":  "A07", // Improper certificate validation
  "CWE-297":  "A07",
  "CWE-300":  "A07",
  "CWE-302":  "A07",
  "CWE-304":  "A07",
  "CWE-306":  "A07", // Missing authentication for critical function
  "CWE-307":  "A07", // Improper restriction of excessive auth attempts
  "CWE-346":  "A07",
  "CWE-384":  "A07", // Session fixation
  "CWE-521":  "A07", // Weak password requirements
  "CWE-613":  "A07", // Insufficient session expiration
  "CWE-620":  "A07",
  "CWE-640":  "A07",
  "CWE-798":  "A07", // Hardcoded credentials
  "CWE-940":  "A07",
  "CWE-1216": "A07",

  // ── A08 Software & Data Integrity Failures ───────────────────────────
  "CWE-345":  "A08",
  "CWE-353":  "A08",
  "CWE-426":  "A08", // Untrusted search path
  "CWE-494":  "A08", // Download of code without integrity check
  "CWE-502":  "A08", // Deserialization of untrusted data
  "CWE-565":  "A08",
  "CWE-784":  "A08",
  "CWE-829":  "A08",
  "CWE-830":  "A08",
  "CWE-915":  "A08",

  // ── A09 Security Logging & Monitoring Failures ───────────────────────
  "CWE-117":  "A09",
  "CWE-223":  "A09",
  "CWE-532":  "A09", // Information exposure through log files
  "CWE-778":  "A09",

  // ── A10 Server-Side Request Forgery ──────────────────────────────────
  "CWE-918":  "A10",
};

/**
 * Extract a CWE identifier from a finding's cweId field.
 * Our findings store cweId in a few shapes:
 *   "CWE-89"
 *   "CWE-89: Improper Neutralization of …"
 *   "cwe-89" (rare lowercase)
 * Returns the upper-cased prefix or null on miss.
 */
export function extractCweCode(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const m = raw.match(/^cwe-?\s*(\d+)/i);
  if (!m) return null;
  return `CWE-${m[1]}`;
}

/**
 * Best-effort classification. Returns null when the CWE doesn't map and
 * no scan-type fallback applies — the chart hides null buckets.
 */
export function classifyCwe(
  cweRaw: string | null | undefined,
  scanType?: string,
): OwaspFamily | null {
  const cwe = extractCweCode(cweRaw);
  if (cwe && CWE_TO_OWASP[cwe]) return CWE_TO_OWASP[cwe];

  // Scan-type fallback for findings without a CWE.
  //   SCA + CONTAINER (CVE-driven) → A06 (vulnerable components)
  //   SECRET (credentials in code) → A07 (auth failures)
  // Prevents most operator-relevant findings from going unmapped just
  // because the scanner doesn't always populate cweId.
  if (scanType === "SCA" || scanType === "CONTAINER") return "A06";
  if (scanType === "SECRET") return "A07";

  return null;
}
