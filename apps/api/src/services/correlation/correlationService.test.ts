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
import { _testing as engineTesting } from "./correlationService.js";
import type { BridgeContext } from "./bridgeInterface.js";

const EMPTY_CTX: BridgeContext = {
  containerById:        new Map(),
  containersByImageRef: new Map(),
  domainById:           new Map(),
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
      containersByImageRef: new Map(),
      domainById:           new Map(),
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
