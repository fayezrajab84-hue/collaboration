/**
 * complianceMappingService — unit tests for the CWE / keyword matching
 * logic. Pure-function tests use fixture controls (no DB dependency)
 * since matchControls() is the security-sensitive bit and needs to be
 * exhaustively covered.
 */

import { describe, it, expect } from "vitest";
import { matchControls, parseCweInt } from "./complianceMappingService.js";
import type { ComplianceControl, ComplianceFramework } from "@prisma/client";

// ── parseCweInt ──────────────────────────────────────────────────────────

describe("parseCweInt", () => {
  it("parses canonical CWE form (CWE-79)", () => {
    expect(parseCweInt("CWE-79")).toBe(79);
  });

  it("accepts lowercase prefix (cwe-79)", () => {
    expect(parseCweInt("cwe-79")).toBe(79);
  });

  it("accepts bare numeric ('79')", () => {
    expect(parseCweInt("79")).toBe(79);
  });

  it("accepts very-large CWE numbers (CWE-1275)", () => {
    expect(parseCweInt("CWE-1275")).toBe(1275);
  });

  it("returns null for non-CWE prefixes (Foo-79)", () => {
    expect(parseCweInt("Foo-79")).toBeNull();
  });

  it("returns null for null/undefined/empty", () => {
    expect(parseCweInt(null)).toBeNull();
    expect(parseCweInt(undefined)).toBeNull();
    expect(parseCweInt("")).toBeNull();
  });

  it("returns null for malformed input (CWE-abc)", () => {
    expect(parseCweInt("CWE-abc")).toBeNull();
  });

  it("returns null for whitespace-padded input (defensive)", () => {
    // Today the regex doesn't handle padding; if scanners start emitting
    // " CWE-79 " we'll need a trim. Lock current behaviour explicitly so
    // the change is intentional, not accidental.
    expect(parseCweInt(" CWE-79 ")).toBeNull();
  });
});

// ── matchControls ────────────────────────────────────────────────────────

function fixtureControl(opts: {
  id?:          string;
  framework?:   ComplianceFramework;
  code?:        string;
  cweIds?:      number[];
  keywordTags?: string[];
}): ComplianceControl {
  return {
    id:           opts.id ?? `control-${Math.random().toString(36).slice(2, 8)}`,
    framework:    opts.framework ?? "OWASP_TOP_10",
    code:         opts.code ?? "TEST",
    name:         "Test control",
    description:  "Test description",
    category:     null,
    cweIds:       opts.cweIds ?? [],
    keywordTags:  opts.keywordTags ?? [],
    sortOrder:    0,
    createdAt:    new Date(),
    updatedAt:    new Date(),
  };
}

describe("matchControls", () => {
  it("returns empty array when no controls match", () => {
    const controls = [fixtureControl({ cweIds: [22, 35] })];
    const matches = matchControls({ cweId: "CWE-79", title: "Some finding" }, controls);
    expect(matches).toEqual([]);
  });

  it("returns empty array when controls list is empty", () => {
    const matches = matchControls({ cweId: "CWE-79", title: "SQL injection" }, []);
    expect(matches).toEqual([]);
  });

  it("matches a single control by CWE", () => {
    const c = fixtureControl({ id: "c-injection", cweIds: [79, 89, 90] });
    const matches = matchControls({ cweId: "CWE-79", title: "XSS" }, [c]);
    expect(matches).toEqual([{ controlId: "c-injection", matchReason: "cwe-match" }]);
  });

  it("matches the same finding against MULTIPLE controls — one finding satisfies multiple frameworks", () => {
    // CWE-79 (XSS) appears in OWASP A03 + SOC 2 CC8.1 + PCI Req-6.4.1.
    // A finding for it should produce 3 mappings.
    const owasp = fixtureControl({ id: "owasp-a03", framework: "OWASP_TOP_10", code: "A03:2021", cweIds: [79, 89] });
    const soc2  = fixtureControl({ id: "soc2-cc8.1", framework: "SOC2", code: "CC8.1", cweIds: [79, 287] });
    const pci   = fixtureControl({ id: "pci-6.4.1", framework: "PCI_DSS", code: "Req-6.4.1", cweIds: [79, 22] });

    const matches = matchControls({ cweId: "CWE-79", title: "Reflected XSS" }, [owasp, soc2, pci]);

    expect(matches.length).toBe(3);
    expect(matches.map((m) => m.controlId).sort()).toEqual(["owasp-a03", "pci-6.4.1", "soc2-cc8.1"]);
    expect(matches.every((m) => m.matchReason === "cwe-match")).toBe(true);
  });

  it("falls back to keyword match when CWE is null", () => {
    // DAST findings often lack CWE — the keyword tag rescue them.
    const c = fixtureControl({
      id:          "c-injection",
      cweIds:      [79, 89],
      keywordTags: ["sql injection", "xss"],
    });
    const matches = matchControls({ cweId: null, title: "SQL Injection in /api/login" }, [c]);
    expect(matches).toEqual([{ controlId: "c-injection", matchReason: "keyword" }]);
  });

  it("keyword match is case-insensitive", () => {
    const c = fixtureControl({
      id:          "c-1",
      keywordTags: ["SSRF"],
    });
    const matches = matchControls({ cweId: null, title: "Possible ssrf vulnerability detected" }, [c]);
    expect(matches[0]?.matchReason).toBe("keyword");
  });

  it("CWE match takes precedence over keyword for the same control", () => {
    // Don't double-count: if CWE matched, don't ALSO emit a keyword
    // match for the same control.
    const c = fixtureControl({
      id:          "c-1",
      cweIds:      [79],
      keywordTags: ["xss"],
    });
    const matches = matchControls({ cweId: "CWE-79", title: "XSS in profile page" }, [c]);
    expect(matches.length).toBe(1);
    expect(matches[0]?.matchReason).toBe("cwe-match");
  });

  it("does NOT match a control with empty cweIds and empty keywordTags", () => {
    const c = fixtureControl({ id: "c-empty", cweIds: [], keywordTags: [] });
    const matches = matchControls({ cweId: "CWE-79", title: "XSS" }, [c]);
    expect(matches).toEqual([]);
  });

  it("returns empty when CWE doesn't match and title doesn't contain any keyword", () => {
    const c = fixtureControl({
      id:          "c-1",
      cweIds:      [22],
      keywordTags: ["directory traversal"],
    });
    const matches = matchControls({ cweId: "CWE-79", title: "Some unrelated finding" }, [c]);
    expect(matches).toEqual([]);
  });

  it("handles partial-string keyword matches (substring, not whole word)", () => {
    // "sql injection" is a substring of "SQL Injection in /admin". We
    // intentionally use substring not word-boundary matching because
    // scanner titles vary too much for word-level precision to be useful.
    const c = fixtureControl({
      id:          "c-1",
      keywordTags: ["sql injection"],
    });
    const matches = matchControls(
      { cweId: null, title: "SQL Injection in /admin/lookup endpoint" },
      [c],
    );
    expect(matches[0]?.matchReason).toBe("keyword");
  });

  it("dedup: never emits duplicate controlId entries even with overlapping match paths", () => {
    // Two keyword tags both match the title — should still produce ONE
    // entry for that control, not two.
    const c = fixtureControl({
      id:          "c-1",
      keywordTags: ["xss", "cross-site"],
    });
    const matches = matchControls(
      { cweId: null, title: "Reflected XSS via cross-site script tag" },
      [c],
    );
    expect(matches.length).toBe(1);
    expect(matches[0]?.controlId).toBe("c-1");
  });

  it("scales: 100 controls × 1 finding completes in < 50ms (sanity perf check)", () => {
    // Cheap insurance against accidentally O(N²) regression in the
    // matching loop. 100 controls is 4× the current seed size.
    const controls = Array.from({ length: 100 }, (_, i) =>
      fixtureControl({ id: `c-${i}`, cweIds: [i, i + 1000], keywordTags: [`tag-${i}`] }),
    );
    const start = Date.now();
    matchControls({ cweId: "CWE-79", title: "XSS finding" }, controls);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(50);
  });
});
