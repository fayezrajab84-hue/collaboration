# Security policy

BreachLens is a self-hosted DevSecOps platform that orchestrates security
scanners across repositories, container images, domains, and cloud accounts.
We take security in our own product seriously — that's the table stakes for
running tools that find security issues in everyone else's.

This document covers how to report a vulnerability you've discovered in
BreachLens itself.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report them privately via one of these channels:

- **Email:** `security@breachlens.dev`
- **GitHub Security Advisory:** [Report a vulnerability](../../security/advisories/new) (preferred — gives you a private channel coupled with the codebase)

Either channel is monitored. We aim to acknowledge reports within **2
business days** and provide a substantive response (triage + initial
plan) within **5 business days**.

### What to include

A useful report typically contains:

1. A clear description of the issue and its impact
2. Steps to reproduce, ideally with a minimal proof-of-concept
3. Affected versions / commits / deployment shapes (self-hosted vs hosted)
4. Whether you've already disclosed this to anyone else
5. (Optional) Your preferred name + handle for credit in the eventual advisory

If you're uncertain whether something is a vulnerability, err on the side
of reporting — we'd rather receive a few false positives than miss a real
issue.

---

## Coordinated disclosure

We follow a **90-day coordinated disclosure** model:

| Day | Phase |
|---|---|
| **0** | Report received; we acknowledge within 2 business days |
| **0–14** | Triage + impact assessment + reproduction |
| **14–60** | Fix development + internal testing |
| **60–75** | Fix released; affected deployments notified privately |
| **75–90** | Embargo period for self-hosters to update |
| **90+** | Public disclosure (CVE filing if applicable, security advisory published) |

If a vulnerability is being actively exploited in the wild, we may
shorten this timeline and coordinate emergency disclosure. If a fix
requires significant architectural change, we may negotiate an extension
with the reporter.

We will credit the reporter in any resulting advisory unless they prefer
to remain anonymous.

---

## Scope

### In scope

The following components and their direct dependencies, as deployed via
the official `docker-compose.yml`:

- `apps/api/` — Express + Prisma + BullMQ backend
- `apps/web/` — React + Vite frontend
- `apps/scanner/` — FastAPI scanner orchestrator
- `apps/crawler/` — Playwright crawler sidecar
- `packages/types/` — shared TypeScript contracts
- `docker/` — official Dockerfiles + compose configurations

### Out of scope

The following are NOT in scope for this policy and should be reported
upstream:

- **Underlying scanner tools** (Semgrep, Trivy, ZAP, Nuclei, Prowler,
  Wazuh, TruffleHog, Checkov, Nikto, sqlmap, etc.) — report to their
  respective maintainers
- **Demo / test applications** intentionally shipped with vulnerabilities
  for QA purposes (`apps/scanner/qa/fixtures/vulnerable_repo/`) — these
  are *meant* to be vulnerable
- **Third-party integrations** (GitHub, Azure, Jira, Slack, Microsoft
  Teams APIs) — report to the respective vendor
- **Self-imposed limitations** (e.g. "free tier rate limits aren't
  enforced") — these are product feedback, not vulnerabilities
- **Misconfigurations in your own deployment** — operational issues, not
  product vulnerabilities

### Categories we are particularly interested in

- Authentication or authorization bypass (cross-org data access, RBAC
  bypass, privilege escalation)
- Injection vulnerabilities (SQL, NoSQL, command, LDAP)
- Server-side request forgery (SSRF) — particularly in the scanner
  orchestrator's repo-cloning paths
- Insecure cryptographic storage (encryption-at-rest for credentials)
- Container escape from any of our Dockerfiles
- Supply-chain integrity issues (image digest pinning, dependency
  vulnerabilities)
- Path traversal in scan-workspace handling
- Token / credential leakage in logs, error messages, or API responses

---

## Safe-harbor

We will not pursue legal action against security researchers who:

1. Make a good-faith effort to comply with this policy
2. Report vulnerabilities responsibly via the channels above
3. Avoid exfiltrating or destroying data
4. Avoid degrading the service for other users (no DoS, mass scraping,
   etc.)
5. Avoid social engineering of staff or customers

Researchers acting in good faith will be credited and thanked
publicly (with permission).

---

## Hardening checklist for self-hosters

If you are running BreachLens, the following operational practices will
limit blast radius regardless of any product vulnerability:

- Run BreachLens behind a TLS-terminating reverse proxy (Cloudflare
  Tunnel, Traefik, Caddy)
- Put an authentication challenge in front of the application
  (Cloudflare Access, oauth2-proxy, or equivalent) — limits exposure
  to the URL even if it leaks
- Enable hardware MFA on the cloud account that controls your DNS /
  edge / tunnel
- Rotate `ENCRYPTION_KEY` periodically and immediately if there is any
  suspicion it has leaked
- Pin all container image digests in production `docker-compose.yml`
  (the official compose file is updated regularly with new digests)
- Restrict outbound network egress from scanner containers where
  possible — most scanners only need access to GitHub / public registries
- Enable Postgres backups and *test the restore* quarterly
- Monitor authentication failures and rate-limit aggressively at the
  edge

---

## Acknowledgements

We will list confirmed reporters here once we have any:

_None yet — be the first._

---

## Changes to this policy

We may update this policy as the project evolves. Material changes will
be communicated in the project's release notes. The current version of
this document always lives at `SECURITY.md` in the repository root.

Last updated: 2026-04-30
