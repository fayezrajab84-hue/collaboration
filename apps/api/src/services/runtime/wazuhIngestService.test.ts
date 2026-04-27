/**
 * wazuhIngestService — pure-function tests for the parts that don't need a
 * live database. The full ingestion path (which exercises Prisma) is left
 * to integration tests; these unit tests guard the *contract* helpers so
 * regressions in mapping/dedup arithmetic fail loudly.
 */
import { describe, it, expect } from "vitest";
import { mapWazuhLevelToSeverity, _testing } from "./wazuhIngestService.js";

describe("mapWazuhLevelToSeverity", () => {
  it("maps Wazuh's standard severity buckets", () => {
    // Boundaries documented in the Phase 28 scope doc Slice A.
    expect(mapWazuhLevelToSeverity(15)).toBe("CRITICAL");
    expect(mapWazuhLevelToSeverity(13)).toBe("CRITICAL");
    expect(mapWazuhLevelToSeverity(12)).toBe("HIGH");
    expect(mapWazuhLevelToSeverity(10)).toBe("HIGH");
    expect(mapWazuhLevelToSeverity(9)).toBe("MEDIUM");
    expect(mapWazuhLevelToSeverity(7)).toBe("MEDIUM");
    expect(mapWazuhLevelToSeverity(6)).toBe("LOW");
    expect(mapWazuhLevelToSeverity(4)).toBe("LOW");
    expect(mapWazuhLevelToSeverity(3)).toBe("INFO");
    expect(mapWazuhLevelToSeverity(0)).toBe("INFO");
  });

  it("never returns undefined for negative or oversized input", () => {
    // Real-world Wazuh sometimes emits non-spec levels through plugins;
    // we want the worst case to be INFO/CRITICAL, never a runtime crash.
    expect(mapWazuhLevelToSeverity(-1)).toBe("INFO");
    expect(mapWazuhLevelToSeverity(99)).toBe("CRITICAL");
  });
});

describe("healthFromHeartbeat", () => {
  const { healthFromHeartbeat } = _testing;

  it("returns UNKNOWN for never-reported agents", () => {
    expect(healthFromHeartbeat(null)).toBe("UNKNOWN");
  });

  it("returns HEALTHY for heartbeats inside 2 minutes", () => {
    expect(healthFromHeartbeat(new Date(Date.now() - 30 * 1000))).toBe("HEALTHY");
    expect(healthFromHeartbeat(new Date(Date.now() - 119 * 1000))).toBe("HEALTHY");
  });

  it("returns STALE for the 2-10min warning band", () => {
    expect(healthFromHeartbeat(new Date(Date.now() - 3 * 60 * 1000))).toBe("STALE");
    expect(healthFromHeartbeat(new Date(Date.now() - 9 * 60 * 1000))).toBe("STALE");
  });

  it("returns OFFLINE once we cross 10 minutes", () => {
    expect(healthFromHeartbeat(new Date(Date.now() - 11 * 60 * 1000))).toBe("OFFLINE");
    expect(healthFromHeartbeat(new Date(Date.now() - 60 * 60 * 1000))).toBe("OFFLINE");
  });
});

describe("hourly-bucket fingerprint", () => {
  const { sha256 } = _testing;

  it("produces stable + deterministic IDs for the same inputs", () => {
    expect(sha256("org|001|5402|2026-4-27T15")).toBe(sha256("org|001|5402|2026-4-27T15"));
  });

  it("changes when any component changes", () => {
    const a = sha256("org|001|5402|2026-4-27T15");
    const b = sha256("org|001|5402|2026-4-27T16"); // different hour
    const c = sha256("org|002|5402|2026-4-27T15"); // different agent
    const d = sha256("org|001|5500|2026-4-27T15"); // different rule
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
    expect(a).not.toBe(d);
  });
});
