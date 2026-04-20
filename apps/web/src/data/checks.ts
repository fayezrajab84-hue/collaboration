export type CheckSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface CheckDefinition {
  id: string;
  name: string;
  description: string;
  severity: CheckSeverity;
  authenticatedOnly?: boolean;
  scanner?: string;
}

// ── Repository checks ────────────────────────────────────────────────────────

export const REPO_CHECKS: CheckDefinition[] = [
  {
    id: "sast",
    name: "Static Application Security Testing (SAST)",
    description:
      "Scans source code for security vulnerabilities without executing the program. Detects injection flaws, insecure APIs, hardcoded credentials, dangerous function calls, and dozens of other code-level weaknesses across all languages in the repository.",
    severity: "HIGH",
    scanner: "Semgrep",
  },
  {
    id: "sca",
    name: "Open Source Dependency Monitoring (SCA)",
    description:
      "Monitors third-party packages declared in lockfiles (package-lock.json, requirements.txt, go.sum, etc.) for known CVEs. Reports installed vs. fixed version, CVSS score, and available upgrade path for every vulnerable dependency.",
    severity: "CRITICAL",
    scanner: "Trivy (filesystem)",
  },
  {
    id: "secrets",
    name: "Exposed Secrets & Credentials",
    description:
      "Scans the entire commit history and working tree for accidentally committed secrets — API keys, tokens, passwords, private keys, and cloud credentials. Verified (active) secrets are flagged as Critical; unverified as High.",
    severity: "CRITICAL",
    scanner: "TruffleHog",
  },
  {
    id: "iac",
    name: "Infrastructure as Code (IaC) Security",
    description:
      "Checks Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, Helm charts, and Bicep files for misconfigurations — overly permissive IAM policies, open security groups, unencrypted storage, missing network policies, and more.",
    severity: "HIGH",
    scanner: "Checkov",
  },
];

// ── Container checks ─────────────────────────────────────────────────────────

export const CONTAINER_CHECKS: CheckDefinition[] = [
  {
    id: "container-vuln",
    name: "OS & Package Vulnerability Scanning",
    description:
      "Scans every OS package and application library inside the container image against the NVD, GitHub Advisory, and OS-specific advisory databases. Reports CVE ID, installed version, fixed version, and CVSS score for each vulnerability.",
    severity: "CRITICAL",
    scanner: "Trivy (image)",
  },
  {
    id: "container-secret",
    name: "Secrets Inside Container Images",
    description:
      "Detects secrets baked into container layers — API keys, tokens, and credentials that were added during the Docker build process and may not be visible in the Dockerfile itself.",
    severity: "CRITICAL",
    scanner: "Trivy (image)",
  },
  {
    id: "container-misconfig",
    name: "Container Misconfigurations",
    description:
      "Checks the container image for security misconfigurations: running as root, world-writable file system, setuid/setgid binaries, missing USER instruction, exposed sensitive directories, and Dockerfile best-practice violations.",
    severity: "HIGH",
    scanner: "Trivy (image)",
  },
  {
    id: "container-eol",
    name: "End-of-Life Base Images & Runtimes",
    description:
      "Identifies base images (e.g. ubuntu:18.04, node:14) and language runtimes that have reached end-of-life and no longer receive security patches, leaving all vulnerabilities in those packages permanently unpatched.",
    severity: "HIGH",
    scanner: "Trivy (image)",
  },
];

// ── Domain / API checks ───────────────────────────────────────────────────────

export const DOMAIN_CHECKS: CheckDefinition[] = [
  // Critical
  {
    id: "jwt-weak-secret",
    name: "JWT Authorization Token Has Weak Secret",
    description:
      "The JWT authorization token returned by your server has a secret which is weak or is a known compromised secret. This can allow attackers to forge their own tokens to get unauthorized access to personal information.",
    severity: "CRITICAL",
    authenticatedOnly: true,
  },
  {
    id: "jwt-invalid-signature",
    name: "Server Accepts Invalid JWT Tokens",
    description:
      "The server accepts tokens with an invalid signature. The signature of a JWT confirms that the token was issued by a trusted source and has not been tampered with. A failure in this verification process means a bad actor could alter the JWT payload (identity or permissions) without detection.",
    severity: "CRITICAL",
    authenticatedOnly: true,
  },
  {
    id: "heartbleed",
    name: "Heartbleed OpenSSL Vulnerability",
    description:
      "The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read.",
    severity: "CRITICAL",
  },
  {
    id: "csp-missing",
    name: "Content Security Policy (CSP) Header Not Set",
    description:
      "Content Security Policy (CSP) is a first line of defense against XSS and data injection attacks. Without it, browsers will execute any script served alongside the page. CSP lets you whitelist trusted sources for JavaScript, CSS, fonts, images, and embeddable objects.",
    severity: "CRITICAL",
  },
  {
    id: "csp-report-only",
    name: "Content Security Policy (CSP) Report-Only Header Found",
    description:
      "The response contained a Content-Security-Policy-Report-Only header. This may indicate a work-in-progress implementation or an oversight where pre-production configuration was promoted to production — the policy is not enforced.",
    severity: "CRITICAL",
  },
  {
    id: "hsts-not-enforced",
    name: "TLS Not Enforced With Valid HSTS Header",
    description:
      "HTTP Strict Transport Security (HSTS) forces browsers to interact with the server using only HTTPS. Without it, users are vulnerable to SSL-stripping man-in-the-middle attacks where attackers can downgrade connections from HTTPS to HTTP.",
    severity: "CRITICAL",
  },
  {
    id: "directory-listing",
    name: "Directory Browsing Detected",
    description:
      "It is possible to view a listing of the directory contents. Directory listings may reveal hidden scripts, include files, backup source files, etc., which can be accessed to expose sensitive information or attack surface.",
    severity: "CRITICAL",
  },
  {
    id: "env-exposed",
    name: ".env File Publicly Readable",
    description:
      "One or more .env files are accessible on the server. These files often expose infrastructure or administrative account credentials, API keys, APP secrets, database connection strings, or other sensitive configuration information.",
    severity: "CRITICAL",
  },
  {
    id: "htaccess-exposed",
    name: ".htaccess File Publicly Readable",
    description:
      "An .htaccess file is accessible. These files alter the configuration of the Apache Web Server and may reveal internal rewrite rules, authentication settings, IP allowlists, or other configuration details useful to an attacker.",
    severity: "CRITICAL",
  },
  {
    id: "jwt-none-algorithm",
    name: "Server Accepts Tokens With 'none' Algorithm",
    description:
      "The server accepts JWT tokens signed with the 'none' algorithm, meaning it does not verify the signature at all. This allows bad actors to forge their own tokens and send them to obtain personal details or escalate privileges.",
    severity: "CRITICAL",
    authenticatedOnly: true,
  },
  {
    id: "jwt-self-signed-jwk",
    name: "Server Accepts Tokens With Self-Signed JWK",
    description:
      "The server accepts tokens that include a self-signed JWK key in the header. Bad actors could craft JWTs that appear to be signed by a trusted authority, granting access to restricted areas or sensitive information.",
    severity: "CRITICAL",
    authenticatedOnly: true,
  },
  // High
  {
    id: "hsts-missing",
    name: "HSTS Header Is Missing",
    description:
      "HTTP Strict Transport Security (HSTS) is missing. Without it, browsers may allow HTTP connections, exposing users to man-in-the-middle attacks and SSL-stripping.",
    severity: "HIGH",
  },
  {
    id: "session-cookie-insecure",
    name: "Session Cookie Is Not Secured",
    description:
      "The session token cookie is missing the 'httpOnly' and/or 'secure' attributes. Without these, the cookie is accessible from JavaScript (risk of XSS theft) or sent over unencrypted connections (risk of interception).",
    severity: "HIGH",
    authenticatedOnly: true,
  },
  {
    id: "session-in-storage",
    name: "Session Token Found in Browser Storage",
    description:
      "The session token is stored in localStorage or sessionStorage. Neither provides protection against injected third-party scripts, which can freely read and exfiltrate these tokens.",
    severity: "HIGH",
    authenticatedOnly: true,
  },
  {
    id: "csp-unsafe-inline-js",
    name: "CSP Config Allows Inline JavaScript",
    description:
      "Your CSP header is set but allows inline JavaScript ('unsafe-inline'). Inline JS is one of the most common XSS techniques. Blocking it eliminates an entire class of injection attacks with minimal development effort.",
    severity: "HIGH",
  },
  {
    id: "ssl-cert-expiry",
    name: "Domain SSL Certificate Expiration",
    description:
      "The TLS certificate for this domain is expiring soon. Expired certificates break HTTPS connections, causing browsers to show security warnings, leading to service disruption, loss of user trust, and exposure to man-in-the-middle attacks.",
    severity: "HIGH",
  },
  {
    id: "csp-allows-eval",
    name: "CSP Policy Does Not Block eval()",
    description:
      "Your CSP is set but does not block eval(), setTimeout() with string arguments, and similar functions that can execute arbitrary code. Blocking eval() eliminates a whole class of code-injection attacks.",
    severity: "HIGH",
  },
  {
    id: "csp-no-fallback",
    name: "CSP Policy Does Not Define a Fallback Directive",
    description:
      "Your CSP does not define a fallback (default-src) for one or more directives. Browsers treat missing directives as unrestricted, allowing content from any origin for that resource type.",
    severity: "HIGH",
  },
  {
    id: "aspnet-version-leak",
    name: "X-AspNet-Version Response Header Leak",
    description:
      "The server leaks ASP.NET/ASP.NET MVC version information via response headers. Attackers can use this to identify the exact framework version and target known vulnerabilities specific to that release.",
    severity: "HIGH",
  },
  {
    id: "cookie-no-secure",
    name: "Cookie Can Be Sent Over Unencrypted Connection",
    description:
      "A cookie is set without the 'Secure' flag, meaning it may be transmitted over HTTP. An attacker positioned on the same network can intercept the unencrypted request and steal the cookie.",
    severity: "HIGH",
  },
  {
    id: "cookie-no-httponly",
    name: "Cookie Missing HttpOnly Flag",
    description:
      "A cookie is set without the 'HttpOnly' flag, making it accessible from JavaScript. Malicious scripts injected via XSS can read and exfiltrate the cookie, potentially enabling full session takeover.",
    severity: "HIGH",
  },
  // Medium
  {
    id: "csp-not-restrictive",
    name: "CSP Configuration Is Not Restrictive Enough",
    description:
      "Your CSP header is present but too permissive — for example, allowing wildcard origins or unsafe-hashes. While it provides some protection, it can still be bypassed by a determined attacker.",
    severity: "MEDIUM",
  },
  {
    id: "path-traversal",
    name: "Source Code Disclosure — Path Traversal / File Inclusion",
    description:
      "The Path Traversal attack technique allows an attacker to access files, directories, and commands outside the web root. Manipulating URL parameters can cause the server to reveal or execute arbitrary files.",
    severity: "MEDIUM",
  },
  {
    id: "cookie-poisoning",
    name: "Cookie Poisoning Attack May Be Possible",
    description:
      "URL query string parameters or POST data can control cookie values, enabling cookie poisoning attacks. Attackers may be able to manipulate session behavior, bypass controls, or inject malicious values.",
    severity: "MEDIUM",
  },
  {
    id: "reverse-tabnabbing",
    name: "Reverse Tabnabbing Attack Possible via Anchor Tag",
    description:
      "Links on this page open in a new tab without 'noopener noreferrer', allowing the target page to control this page via window.opener. Attackers can replace this page with a phishing clone.",
    severity: "MEDIUM",
  },
  {
    id: "cookie-broad-domain",
    name: "Cookie May Be Accessed From Other Subdomains",
    description:
      "A cookie is scoped to the parent domain (e.g. .example.com) rather than a specific subdomain. Any subdomain — including potentially compromised ones — can read this cookie.",
    severity: "MEDIUM",
  },
  {
    id: "auth-cookie-subdomain-leak",
    name: "Authentication Cookie Can Be Leaked to Any Subdomain",
    description:
      "The authentication cookie is scoped to the parent domain. A compromised or attacker-controlled subdomain can access this cookie, potentially allowing session hijacking.",
    severity: "MEDIUM",
    authenticatedOnly: true,
  },
  {
    id: "missing-clickjacking-header",
    name: "Missing Anti-Clickjacking Header",
    description:
      "The response does not include Content-Security-Policy with 'frame-ancestors' or X-Frame-Options. Without these, attackers can embed this page in an invisible iframe to trick users into clicking hidden buttons (clickjacking).",
    severity: "MEDIUM",
  },
  {
    id: "xfo-multiple",
    name: "Multiple X-Frame-Options Header Entries",
    description:
      "Multiple X-Frame-Options headers were returned. When conflicting headers are present, browser behavior is undefined — some browsers use the first, others the last, making the protection unpredictable.",
    severity: "MEDIUM",
  },
  {
    id: "xfo-malformed",
    name: "X-Frame-Options Setting Malformed",
    description:
      "An X-Frame-Options header is present but the value is invalid (not DENY, SAMEORIGIN, or ALLOW-FROM). Browsers may ignore the header entirely, leaving the page unprotected against framing attacks.",
    severity: "MEDIUM",
  },
  {
    id: "xfo-via-meta",
    name: "X-Frame-Options Defined via META Tag",
    description:
      "X-Frame-Options was set via an HTML META tag rather than an HTTP response header. The spec (RFC 7034) explicitly states that META tags must be ignored for XFO — this provides no protection.",
    severity: "MEDIUM",
  },
  {
    id: "obsolete-csp-header",
    name: "Obsolete Content Security Policy (CSP) Header Found",
    description:
      "The 'X-Content-Security-Policy' or 'X-WebKit-CSP' headers are present. These are legacy, non-standard headers that are no longer supported by modern browsers. Replace with the standard Content-Security-Policy header.",
    severity: "MEDIUM",
  },
  {
    id: "server-header-app",
    name: "Server Leaks Webserver Application via 'Server' Header",
    description:
      "The 'Server' HTTP response header discloses the web server software name. Attackers can use this to target known vulnerabilities in that specific software.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-disabled",
    name: "HSTS Header Is Disabled",
    description:
      "The server explicitly disables HSTS (e.g. max-age=0), allowing downgrade attacks. Connections may fall back to unencrypted HTTP, exposing users to man-in-the-middle interception.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-multiple",
    name: "Multiple HSTS Headers Are Being Set",
    description:
      "Multiple Strict-Transport-Security response headers were detected. Conflicting headers create undefined browser behavior and may weaken the HSTS protection intended.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-malformed-directive",
    name: "HSTS Header Has Malformed Directive",
    description:
      "The Strict-Transport-Security header contains a malformed directive. Browsers may reject or partially enforce the header, reducing the effectiveness of HSTS protection.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-via-meta",
    name: "HSTS Header Is Defined via Meta Tag",
    description:
      "HSTS was configured via an HTML META tag. The HSTS specification requires it to be set via HTTP response headers — META tags are ignored, providing no actual transport security enforcement.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-bad-max-age",
    name: "HSTS Header Has Malformed Max-Age Directive",
    description:
      "The max-age directive in the HSTS header is malformed or missing. Without a valid max-age, browsers cannot determine how long to enforce HTTPS-only connections.",
    severity: "MEDIUM",
  },
  {
    id: "hsts-malformed-content",
    name: "HSTS Header Has Malformed Content",
    description:
      "The Strict-Transport-Security header value is malformed. This may cause browsers to ignore the header entirely, negating HSTS protection.",
    severity: "MEDIUM",
  },
  {
    id: "x-backend-header",
    name: "X-Backend-Server Header Information Leak",
    description:
      "The server leaks internal backend hostnames or IP addresses via the X-Backend-Server header. This information helps attackers map internal infrastructure and launch more targeted attacks.",
    severity: "MEDIUM",
  },
  {
    id: "git-source-exposed",
    name: "Source Code Exposed Online — Git",
    description:
      "The .git directory is accessible from the web. Attackers can reconstruct the full source code, commit history, and any secrets ever committed, even if they were later removed.",
    severity: "MEDIUM",
  },
  {
    id: "svn-source-exposed",
    name: "Source Code Exposed Online — SVN",
    description:
      "The .svn directory is accessible from the web, allowing full source code reconstruction from SVN metadata and working copy files.",
    severity: "MEDIUM",
  },
  {
    id: "x-powered-by-leak",
    name: "Server Leaks Framework Info via 'X-Powered-By' Header",
    description:
      "The 'X-Powered-By' header reveals the application framework (e.g. PHP/7.4.3, Express, ASP.NET). Attackers can use this to identify framework-specific vulnerabilities to exploit.",
    severity: "MEDIUM",
  },
  {
    id: "server-version-leak",
    name: "Server Leaks Version Info via 'Server' Header",
    description:
      "The 'Server' header exposes both the web server software name and its exact version. This makes it trivial for attackers to find and exploit version-specific CVEs.",
    severity: "MEDIUM",
  },
  // Low
  {
    id: "csp-unsafe-inline-css",
    name: "CSP Config Allows Inline CSS",
    description:
      "Your CSP allows inline CSS ('unsafe-inline' for style-src). While less critical than inline JS, injected CSS can be used to exfiltrate data via CSS attribute selectors, aid phishing, or manipulate UI to confuse users.",
    severity: "LOW",
  },
  {
    id: "app-crash-error",
    name: "App Crash May Disclose Error Information",
    description:
      "An error page discloses sensitive information such as file paths, stack traces, database queries, or server internals. Attackers can use this information to understand the application architecture and craft more precise attacks.",
    severity: "LOW",
  },
  {
    id: "sri-missing",
    name: "Sub-Resource Integrity (SRI) Attribute Missing",
    description:
      "A script or stylesheet is loaded from an external server without an integrity attribute. If that external server is compromised, attackers can inject malicious code that runs on your page without detection.",
    severity: "LOW",
  },
];

// ── Full Pentest checks ───────────────────────────────────────────────────────

export const PENTEST_CHECKS: CheckDefinition[] = [
  {
    id: "bac-bola-idor",
    name: "Broken Access Control (BOLA / IDOR)",
    description:
      "Identifies unauthorized data access vulnerabilities. Explicitly checks for cross-tenant data leaks, authorization issues, Insecure Direct Object References (IDOR), and Improper Access Control — where authenticated users can access other users' data by manipulating IDs or parameters.",
    severity: "CRITICAL",
  },
  {
    id: "code-command-injection",
    name: "Code & Command Injection",
    description:
      "Detects if untrusted user input can execute system commands on the server. Focuses on Remote Code Execution (RCE) and OS Command Injection vulnerabilities that can give attackers full control of the underlying server.",
    severity: "CRITICAL",
  },
  {
    id: "sql-injection",
    name: "SQL & Database Injection",
    description:
      "Identifies injection flaws in database queries that allow attackers to read, modify, or delete data. Covers SQL injection, NoSQL injection (MongoDB, Redis), XPath injection, and LDAP injection.",
    severity: "CRITICAL",
  },
  {
    id: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    description:
      "Tests whether the server can be tricked into making HTTP requests to internal infrastructure (e.g. cloud metadata endpoints, internal APIs, databases) or external systems it should not be reaching.",
    severity: "CRITICAL",
  },
  {
    id: "secrets-cryptography",
    name: "Secrets & Cryptography",
    description:
      "Finds hardcoded credentials and passwords in API responses, weak cryptographic implementations, JWT verification bypasses (none algorithm, weak secrets, algorithm confusion), and sensitive data exposed in responses.",
    severity: "CRITICAL",
  },
  {
    id: "auth-session",
    name: "Authentication & Session Management",
    description:
      "Validates the security of login flows and session handling. Checks for brute force weakness (no rate limiting, no lockout), missing or bypassable authentication, insecure session token generation, and cookie integrity issues.",
    severity: "HIGH",
  },
  {
    id: "llm-prompt-injection",
    name: "LLM & Prompt Injection",
    description:
      "Secures AI-powered endpoints against manipulation. Detects prompt injection attacks, jailbreaking attempts, and techniques to leak the system prompt or override AI behavior to extract sensitive data or bypass safety controls.",
    severity: "HIGH",
  },
  {
    id: "client-side-attacks",
    name: "Client-Side Attacks",
    description:
      "Secures the browser-facing layer. Scans for Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Open Redirects, Web Cache Poisoning, and clickjacking vulnerabilities.",
    severity: "HIGH",
  },
  {
    id: "insecure-deserialization-ssti",
    name: "Insecure Deserialization & SSTI",
    description:
      "Probes for unsafe handling of serialized objects and template rendering. Specifically targets Insecure Deserialization (Java, PHP, Python pickle) and Server-Side Template Injection (Jinja2, Twig, Freemarker) which can lead to RCE.",
    severity: "HIGH",
  },
  {
    id: "business-logic",
    name: "Business Logic & Input Validation",
    description:
      "AI-driven logic testing that catches complex flaws static scanners miss: negative price attacks, workflow bypass, mass assignment, integer overflow, race conditions, and general input validation errors that violate expected application behavior.",
    severity: "HIGH",
  },
  {
    id: "files-misconfigs",
    name: "Files & Misconfigurations",
    description:
      "Scans for file system risks including Local File Inclusion (LFI), Unrestricted File Upload (leading to RCE), Directory Traversal, Path Control vulnerabilities, debug endpoints, and verbose error messages leaking internal details.",
    severity: "MEDIUM",
  },
  {
    id: "hardening",
    name: "Security Hardening",
    description:
      "Identifies missing or misconfigured defensive controls: GraphQL introspection/batching enabled in production, CORS misconfigurations allowing credential theft, TLS configuration issues (weak ciphers, deprecated protocols), and incorrect HTTP security headers (CSP, HSTS, X-Frame-Options).",
    severity: "MEDIUM",
  },
];
