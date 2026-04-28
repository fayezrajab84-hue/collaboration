/**
 * Correlation engine pure-function tests. The full engine talks to Prisma
 * (integration territory); these unit tests guard the bridge logic + the
 * union-find data structure so behaviour regressions fail loudly.
 */
import { describe, it, expect } from "vitest";
import type { Finding } from "@prisma/client";
import { cveBridge } from "./cveBridge.js";
import { _testing as routeTesting } from "./routeBridge.js";
import { secretBridge } from "./secretBridge.js";
import { containerExposureBridge } from "./containerExposureBridge.js";
import { runtimeBridge } from "./runtimeBridge.js";
import { _testing as engineTesting } from "./correlationService.js";
import type { BridgeContext } from "./bridgeInterface.js";

const EMPTY_CTX: BridgeContext = {
  containerById:             new Map(),
  containersByImageRef:      new Map(),
  domainById:                new Map(),
  containerIdByWazuhAgentId: new Map(),
};

function fakeFinding(over: Partial<Finding>): Finding {
  return {
    id:                    over.id ?? `f-${Math.random().toString(36).slice(2, 8)}`,
    orgId:                 "org1",
    scanJobId:             "scan1",
    targetType:            "REPOSITORY",
    repositoryId:          null,
    containerId:           null,
    domainId:              null,
    scanType:              "SCA",
    title:                 "fake",
    description:           "fake",
    severity:              "HIGH",
    status:                "OPEN",
    filePath:              null,
    lineStart:             null,
    lineEnd:               null,
    codeSnippet:           null,
    cveId:                 null,
    cweId:                 null,
    packageName:           null,
    packageVersion:        null,
    fixVersion:            null,
    cvssScore:             null,
    scanner:               "trivy",
    ruleId:                null,
    fingerprint:           Math.random().toString(36),
    remediation:           null,
    references:            [],
    rawOutput:             {},
    firstSeen:             new Date(),
    lastSeen:              new Date(),
    resolvedAt:            null,
    confidence:            "POSSIBLE",
    evidence:              null,
    verifiedAt:            null,
    aiAnalysis:            null,
    aiAnalysedAt:          null,
    aiFpAnalysis:          null,
    aiFpAnalysedAt:        null,
    aiFixSuggestion:       null,
    aiFixSuggestedAt:      null,
    snoozedUntil:          null,
    absenceCount:          0,
    reachability:          "NOT_APPLICABLE",
    reachabilityEvidence:  null,
    correlationGroupId:    null,
    correlationEdges:      null,
    correlationComputedAt: null,
    ...over,
  } as unknown as Finding;
}

describe("cveBridge", () => {
  it("matches when both findings share a CVE across target types", () => {
    const a = fakeFinding({ id: "a", targetType: "REPOSITORY", repositoryId: "r1", cveId: "CVE-2024-9999" });
    const b = fakeFinding({ id: "b", targetType: "CONTAINER",  containerId: "c1", cveId: "CVE-2024-9999" });
    const m = cveBridge.match(a, b, EMPTY_CTX);
    expect(m).not.toBeNull();
    expect(m?.bridgeType).toBe("cve");
    expect(m?.confidence).toBe("LIKELY"); // no asset link
  });

  it("upgrades to CONFIRMED when repo→container linkage exists", () => {
    const a = fakeFinding({ id: "a", targetType: "REPOSITORY", repositoryId: "r1", cveId: "CVE-X" });
    const b = fakeFinding({ id: "b", targetType: "CONTAINER",  containerId: "c1", cveId: "CVE-X" });
    const ctx: BridgeContext = {
      containerById: new Map([
        ["c1", { id: "c1", imageRef: "myorg/app:1", sourceRepositoryId: "r1", deployedAtDomainIds: [] }],
      ]),
      containersByImageRef:      new Map(),
      domainById:                new Map(),
      containerIdByWazuhAgentId: new Map(),
    };
    const m = cveBridge.match(a, b, ctx);
    expect(m?.confidence).toBe("CONFIRMED");
  });

  it("returns null for the same CVE on the same target", () => {
    const a = fakeFinding({ targetType: "REPOSITORY", repositoryId: "r1", cveId: "CVE-1" });
    const b = fakeFinding({ targetType: "REPOSITORY", repositoryId: "r1", cveId: "CVE-1" });
    expect(cveBridge.match(a, b, EMPTY_CTX)).toBeNull();
  });

  it("rejects cross-org pairs as a defence-in-depth measure", () => {
    const a = fakeFinding({ orgId: "orgA", targetType: "REPOSITORY", repositoryId: "r1", cveId: "CVE-1" });
    const b = fakeFinding({ orgId: "orgB", targetType: "CONTAINER",  containerId: "c1", cveId: "CVE-1" });
    expect(cveBridge.match(a, b, EMPTY_CTX)).toBeNull();
  });
});

describe("routeBridge.urlContainsFileToken", () => {
  const { urlContainsFileToken } = routeTesting;

  it("matches via the SPECIFIC vuln-type token (sqli), not the prefix", () => {
    // The good link — same vulnerability type on URL + source file.
    expect(urlContainsFileToken(
      "https://dvwa/vulnerabilities/sqli/?id=1",
      "vulnerabilities/sqli/source/low.php",
    )).toBe(true);
  });

  it("does NOT cross-link different vuln types just because they share a prefix", () => {
    // Phase 27.5.x bug fix: previously this returned true because both paths
    // share the token `vulnerabilities`. That collapsed every DVWA SAST
    // finding into the same chain as every DAST finding regardless of
    // which vuln type they were on, producing a 42-node mega-chain. The
    // expanded COMMON_NOISE list makes `vulnerabilities` + `source`
    // non-discriminating, so the matcher requires a specific token like
    // `sqli` or `xss_r` — and these two paths don't share one.
    expect(urlContainsFileToken(
      "https://dvwa/vulnerabilities/xss_r/?name=x",
      "vulnerabilities/sqli/source/low.php",
    )).toBe(false);
  });

  it("ignores common framework noise like /api or /v1", () => {
    expect(urlContainsFileToken(
      "https://app/api/v1/users",
      "src/routes/users/index.ts",
    )).toBe(true);
    // Verify a noise-only URL produces false:
    expect(urlContainsFileToken(
      "https://app/api/v1",
      "src/server.ts",
    )).toBe(false);
  });

  it("returns false when no segment matches", () => {
    expect(urlContainsFileToken(
      "https://example.com/billing/checkout",
      "src/auth/login.ts",
    )).toBe(false);
  });

  it("requires tokens at least MIN_TOKEN_LENGTH chars (3) — 2-char tokens are noise", () => {
    // 2-char tokens like `id` would have falsely linked DAST and source
    // files (legacy queries always have ?id=). 3-char minimum kills these
    // while keeping real vuln-type categories like `csp`, `bac`, `xss`.
    expect(urlContainsFileToken(
      "https://app/id/handler",
      "src/id/handler.ts",
    )).toBe(true);  // `handler` (7 chars) matches; `id` (2) doesn't gate it
    expect(urlContainsFileToken(
      "https://app/id",
      "src/id/index.ts",
    )).toBe(false); // only `id` available (2 chars), filtered out
  });

  it("matches DVWA's 3-char vuln-type tokens like csp / bac", () => {
    expect(urlContainsFileToken(
      "https://dvwa/vulnerabilities/csp/source/low.php",
      "vulnerabilities/csp/source/medium.php",
    )).toBe(true);
  });

  it("treats DVWA security-level words (low/medium/high/impossible) as noise", () => {
    // Two unrelated bugs both have `source/low.php` in their path. Without
    // adding `low` to the noise list, the chain merger collapsed them into
    // one chain via the shared (but meaningless) token. The fix:
    expect(urlContainsFileToken(
      "http://dvwa/vulnerabilities/open_redirect/source/low.php?redirect=x",
      "vulnerabilities/bac/source/low.php",
    )).toBe(false);
    // But the SAME-feature link should still hold (same vuln-type token):
    expect(urlContainsFileToken(
      "http://dvwa/vulnerabilities/bac/source/low.php",
      "vulnerabilities/bac/source/low.php",
    )).toBe(true);
  });

  it("strips file extensions from URL segments before matching", () => {
    // Phase 27.5.x bug: `/login.php` URL never matched `login.php` SAST
    // file path because URL token was `login.php` (with extension) but
    // file token was `login` (extension stripped). Symmetric stripping
    // fixes it — and unlocks the whole "classic LAMP / PHP-style URL"
    // chain class that DVWA, WordPress, Drupal, etc. all rely on.
    expect(urlContainsFileToken(
      "http://dvwa/login.php",
      "login.php",
    )).toBe(true);
    expect(urlContainsFileToken(
      "http://dvwa/instructions.php",
      "instructions.php",
    )).toBe(true);
  });
});

describe("secretBridge", () => {
  it("matches when both findings share the same secret hash", () => {
    const hash = "a".repeat(64);
    const a = fakeFinding({ id: "a", scanType: "SECRET",    evidence: { secret_hash: hash } });
    const b = fakeFinding({ id: "b", scanType: "CONTAINER", evidence: { secret_hash: hash } });
    const m = secretBridge.match(a, b, EMPTY_CTX);
    expect(m).not.toBeNull();
    expect(m?.confidence).toBe("CONFIRMED");
  });

  it("returns null when hashes differ", () => {
    const a = fakeFinding({ id: "a", scanType: "SECRET",    evidence: { secret_hash: "a".repeat(64) } });
    const b = fakeFinding({ id: "b", scanType: "CONTAINER", evidence: { secret_hash: "b".repeat(64) } });
    expect(secretBridge.match(a, b, EMPTY_CTX)).toBeNull();
  });

  it("ignores non-SHA-256-shaped hashes", () => {
    const a = fakeFinding({ id: "a", scanType: "SECRET",    evidence: { secret_hash: "shortvalue" } });
    const b = fakeFinding({ id: "b", scanType: "CONTAINER", evidence: { secret_hash: "shortvalue" } });
    expect(secretBridge.match(a, b, EMPTY_CTX)).toBeNull();
  });
});

describe("containerExposureBridge", () => {
  // Phase 27.5.x — links CONTAINER findings to DAST/PENTEST findings on a
  // domain the container is operator-declared to serve.
  const ctxLinked: BridgeContext = {
    containerById: new Map([
      ["c1", { id: "c1", imageRef: "myorg/api:1.0", sourceRepositoryId: null, deployedAtDomainIds: ["d1"] }],
    ]),
    containersByImageRef: new Map(),
    domainById: new Map([
      ["d1", { id: "d1", domain: "api.example.com", servesContainerIds: ["c1"] }],
    ]),
    containerIdByWazuhAgentId: new Map(),
  };
  const ctxUnlinked: BridgeContext = {
    containerById: new Map([
      ["c1", { id: "c1", imageRef: "myorg/api:1.0", sourceRepositoryId: null, deployedAtDomainIds: [] }],
    ]),
    containersByImageRef: new Map(),
    domainById: new Map([
      ["d1", { id: "d1", domain: "api.example.com", servesContainerIds: [] }],
    ]),
    containerIdByWazuhAgentId: new Map(),
  };

  it("links CONTAINER + DAST when both sides are HIGH+ and asset graph linked", () => {
    const c = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-2024-1234", packageName: "libssl3" });
    const d = fakeFinding({ id: "d", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "HIGH" });
    const m = containerExposureBridge.match(c, d, ctxLinked);
    expect(m).not.toBeNull();
    expect(m?.bridgeType).toBe("container_exposure");
    expect(m?.confidence).toBe("LIKELY"); // CRITICAL container side upgrades
    expect(m?.reason).toContain("CVE-2024-1234");
    expect(m?.reason).toContain("myorg/api:1.0");
  });

  it("returns POSSIBLE for HIGH-severity container findings", () => {
    const c = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "HIGH", cveId: "CVE-2024-9999" });
    const d = fakeFinding({ id: "d", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "HIGH" });
    const m = containerExposureBridge.match(c, d, ctxLinked);
    expect(m?.confidence).toBe("POSSIBLE");
  });

  it("does NOT fire when container side is below HIGH (severity gate)", () => {
    const cMed = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "MEDIUM", cveId: "CVE-X" });
    const cLow = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "LOW",    cveId: "CVE-X" });
    const d   = fakeFinding({ id: "d", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "HIGH" });
    expect(containerExposureBridge.match(cMed, d, ctxLinked)).toBeNull();
    expect(containerExposureBridge.match(cLow, d, ctxLinked)).toBeNull();
  });

  it("does NOT fire when web side is below HIGH (severity gate)", () => {
    const c = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-X" });
    const dMed = fakeFinding({ id: "d", scanType: "DAST", targetType: "DOMAIN", domainId: "d1", severity: "MEDIUM" });
    expect(containerExposureBridge.match(c, dMed, ctxLinked)).toBeNull();
  });

  it("returns null when the operator hasn't linked the container to that domain", () => {
    const c = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-X" });
    const d = fakeFinding({ id: "d", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "MEDIUM" });
    expect(containerExposureBridge.match(c, d, ctxUnlinked)).toBeNull();
  });

  it("rejects cross-org pairs (defence-in-depth)", () => {
    const c = fakeFinding({ id: "c", orgId: "orgA", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-X" });
    const d = fakeFinding({ id: "d", orgId: "orgB", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "HIGH" });
    expect(containerExposureBridge.match(c, d, ctxLinked)).toBeNull();
  });

  it("requires PENTEST or DAST on the web side — ignores CONTAINER ↔ CONTAINER", () => {
    const c1 = fakeFinding({ id: "c1", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-X" });
    const c2 = fakeFinding({ id: "c2", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "HIGH",     cveId: "CVE-Y" });
    expect(containerExposureBridge.match(c1, c2, ctxLinked)).toBeNull();
  });

  it("skips RUNTIME findings on the container side (runtimeBridge covers that link)", () => {
    // Phase 28 Slice C iteration: RUNTIME findings carry targetType=CONTAINER
    // + containerId so runtimeBridge can match them, but they're not
    // container CVEs. Letting containerExposureBridge fire on them would
    // produce duplicate edges (~16/run on DVWA). runtimeBridge already
    // covers RUNTIME ↔ DAST/PENTEST_FULL with better reason text.
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "CRITICAL", ruleId: "5715",
    });
    const d = fakeFinding({
      id: "d", scanType: "DAST", targetType: "DOMAIN",
      domainId: "d1", severity: "HIGH",
    });
    expect(containerExposureBridge.match(r, d, ctxLinked)).toBeNull();
    // Symmetric — order shouldn't matter:
    expect(containerExposureBridge.match(d, r, ctxLinked)).toBeNull();
  });

  it("is symmetric — match(c, d) === match(d, c)", () => {
    const c = fakeFinding({ id: "c", scanType: "CONTAINER", targetType: "CONTAINER", containerId: "c1", severity: "CRITICAL", cveId: "CVE-X" });
    const d = fakeFinding({ id: "d", scanType: "DAST",      targetType: "DOMAIN",    domainId:    "d1", severity: "HIGH" });
    const ab = containerExposureBridge.match(c, d, ctxLinked);
    const ba = containerExposureBridge.match(d, c, ctxLinked);
    expect(ab).toEqual(ba);
  });
});

describe("runtimeBridge", () => {
  // Phase 28 Slice C — links RUNTIME findings (Wazuh alerts) to other
  // findings on the same Container, or on the Domain that container serves.
  const ctxAgentLinked: BridgeContext = {
    containerById: new Map([
      ["c1", { id: "c1", imageRef: "myorg/web:2.0", sourceRepositoryId: null, deployedAtDomainIds: ["d1"] }],
    ]),
    containersByImageRef:      new Map(),
    domainById:                new Map([
      ["d1", { id: "d1", domain: "app.example.com", servesContainerIds: ["c1"] }],
    ]),
    // Wazuh agent "001" monitors container c1
    containerIdByWazuhAgentId: new Map([["001", "c1"]]),
  };

  it("links RUNTIME → CONTAINER finding on the same container (direct)", () => {
    // Direct case: RUNTIME finding has containerId set (post-fix ingestion).
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5715",
    });
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "CRITICAL", cveId: "CVE-2024-X",
    });
    const m = runtimeBridge.match(r, c, ctxAgentLinked);
    expect(m).not.toBeNull();
    expect(m?.bridgeType).toBe("runtime");
    expect(m?.confidence).toBe("LIKELY"); // HIGH severity → LIKELY
    expect(m?.reason).toContain("Wazuh rule 5715");
  });

  it("resolves containerId via WorkloadAgent map when Finding.containerId is null", () => {
    // Legacy case: RUNTIME finding ingested before operator linked the agent
    // — containerId is null but rawOutput.agent_id matches a linked agent.
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: null, severity: "CRITICAL", ruleId: "5503",
      rawOutput: { source: "wazuh", agent_id: "001" },
    });
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    const m = runtimeBridge.match(r, c, ctxAgentLinked);
    expect(m).not.toBeNull();
    expect(m?.confidence).toBe("LIKELY"); // CRITICAL severity → LIKELY
  });

  it("links RUNTIME → DAST finding on Domain served by container when both HIGH+", () => {
    // Indirect case: RUNTIME on container c1 → DAST on domain d1 (which c1 serves).
    // Both sides must be HIGH+ post-severity-gate; DAST is HIGH here.
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "31100",
    });
    const d = fakeFinding({
      id: "d", scanType: "DAST", targetType: "DOMAIN",
      domainId: "d1", severity: "HIGH",
    });
    const m = runtimeBridge.match(r, d, ctxAgentLinked);
    expect(m).not.toBeNull();
    expect(m?.bridgeType).toBe("runtime");
    expect(m?.reason).toContain("domain served by container myorg/web:2.0");
  });

  it("does NOT fire when runtime side is below HIGH (severity gate)", () => {
    // Phase 28 Slice C iteration: severity gate added to prevent union-find
    // amplification. A single MEDIUM/LOW Wazuh alert was pulling 80
    // unrelated container CVEs + 60 DAST findings into one mega-chain on
    // the DVWA dataset.
    const rMed = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "MEDIUM", ruleId: "1002",
    });
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    expect(runtimeBridge.match(rMed, c, ctxAgentLinked)).toBeNull();
  });

  it("does NOT fire when other side is below HIGH (severity gate)", () => {
    // Mirror of the above: a HIGH runtime alert against a LOW container
    // CVE shouldn't form an edge — the LOW CVE wouldn't be exploited as
    // the same incident as the runtime activity.
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5715",
    });
    const cLow = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "LOW", cveId: "CVE-LOW",
    });
    expect(runtimeBridge.match(r, cLow, ctxAgentLinked)).toBeNull();
  });

  it("indirect domain match returns POSSIBLE (weaker than direct container LIKELY)", () => {
    // Direct container = LIKELY; indirect via domain = POSSIBLE. The
    // runtime alert may not actually be related to the HTTP-level vuln on
    // the served domain, so the weaker confidence is honest.
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "31100",
    });
    const d = fakeFinding({
      id: "d", scanType: "DAST", targetType: "DOMAIN",
      domainId: "d1", severity: "HIGH",
    });
    const m = runtimeBridge.match(r, d, ctxAgentLinked);
    expect(m?.confidence).toBe("POSSIBLE");
  });

  it("returns null when RUNTIME finding has no resolvable container", () => {
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: null, severity: "HIGH", ruleId: "5715",
      rawOutput: { source: "wazuh", agent_id: "999" }, // not in map
    });
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    expect(runtimeBridge.match(r, c, ctxAgentLinked)).toBeNull();
  });

  it("returns null for RUNTIME ↔ RUNTIME (no self-tier bridging)", () => {
    // Two runtime alerts on the same container shouldn't form an edge —
    // wazuhIngestService already merges same-hour alerts into one Finding,
    // so distinct rows mean different rules; keeping them separate avoids
    // chain inflation from runtime noise.
    const r1 = fakeFinding({
      id: "r1", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5715",
    });
    const r2 = fakeFinding({
      id: "r2", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5503",
    });
    expect(runtimeBridge.match(r1, r2, ctxAgentLinked)).toBeNull();
  });

  it("rejects cross-org pairs (defence-in-depth)", () => {
    const r = fakeFinding({
      id: "r", orgId: "orgA", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5715",
    });
    const c = fakeFinding({
      id: "c", orgId: "orgB", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    expect(runtimeBridge.match(r, c, ctxAgentLinked)).toBeNull();
  });

  it("is symmetric — match(r, c) === match(c, r)", () => {
    const r = fakeFinding({
      id: "r", scanType: "RUNTIME", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", ruleId: "5715",
    });
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    const ab = runtimeBridge.match(r, c, ctxAgentLinked);
    const ba = runtimeBridge.match(c, r, ctxAgentLinked);
    expect(ab).toEqual(ba);
  });

  it("returns null when neither side is RUNTIME", () => {
    const c = fakeFinding({
      id: "c", scanType: "CONTAINER", targetType: "CONTAINER",
      containerId: "c1", severity: "HIGH", cveId: "CVE-X",
    });
    const d = fakeFinding({
      id: "d", scanType: "DAST", targetType: "DOMAIN",
      domainId: "d1", severity: "HIGH",
    });
    expect(runtimeBridge.match(c, d, ctxAgentLinked)).toBeNull();
  });
});

describe("UnionFind", () => {
  const { UnionFind } = engineTesting;

  it("starts with each element in its own set", () => {
    const uf = new UnionFind<string>();
    expect(uf.find("a")).toBe("a");
    expect(uf.find("b")).toBe("b");
  });

  it("groups elements after union and produces a stable root", () => {
    const uf = new UnionFind<string>();
    uf.union("a", "b");
    uf.union("b", "c");
    const root = uf.find("a");
    expect(uf.find("b")).toBe(root);
    expect(uf.find("c")).toBe(root);
  });

  it("produces deterministic roots regardless of union order", () => {
    const uf1 = new UnionFind<string>();
    uf1.union("c", "a");
    uf1.union("b", "c");
    const uf2 = new UnionFind<string>();
    uf2.union("a", "b");
    uf2.union("a", "c");
    expect(uf1.find("a")).toBe(uf2.find("a"));
  });
});
