/**
 * Pure-function unit tests for applicationService. The full service hits
 * Prisma so the integration of pickSlug / assignComponents lives in
 * end-to-end tests; these guard the pure helpers + the validation-error
 * predicate so behaviour regressions fail loudly.
 */
import { describe, it, expect } from "vitest";
import {
  ApplicationComponentValidationError,
  isApplicationComponentValidationError,
  deriveSlug,
} from "./applicationService.js";

describe("deriveSlug", () => {
  it("lowercases and dasherises plain input", () => {
    expect(deriveSlug("Customer Portal")).toBe("customer-portal");
    expect(deriveSlug("ACME Customer Portal")).toBe("acme-customer-portal");
  });

  it("collapses runs of non-alphanumerics into a single dash", () => {
    expect(deriveSlug("foo___bar")).toBe("foo-bar");
    expect(deriveSlug("foo / bar // baz")).toBe("foo-bar-baz");
  });

  it("strips leading and trailing dashes", () => {
    expect(deriveSlug("--foo--")).toBe("foo");
    expect(deriveSlug("__foo__")).toBe("foo");
  });

  it("falls back to 'app' when nothing alphanumeric remains", () => {
    expect(deriveSlug("!!!")).toBe("app");
    expect(deriveSlug("    ")).toBe("app");
    expect(deriveSlug("")).toBe("app");
  });

  it("preserves already-valid slugs verbatim (modulo case)", () => {
    expect(deriveSlug("auth-service")).toBe("auth-service");
    expect(deriveSlug("api-v2")).toBe("api-v2");
  });
});

describe("ApplicationComponentValidationError", () => {
  it("captures the missing IDs in details for the API error response", () => {
    const err = new ApplicationComponentValidationError("missing", { missing: ["a", "b"], kind: "container" });
    expect(err.name).toBe("ApplicationComponentValidationError");
    expect(err.details["missing"]).toEqual(["a", "b"]);
    expect(err.details["kind"]).toBe("container");
  });

  it("isApplicationComponentValidationError narrows the type for routes", () => {
    const e: unknown = new ApplicationComponentValidationError("x");
    expect(isApplicationComponentValidationError(e)).toBe(true);
    expect(isApplicationComponentValidationError(new Error("x"))).toBe(false);
    expect(isApplicationComponentValidationError("x")).toBe(false);
    expect(isApplicationComponentValidationError(null)).toBe(false);
  });
});
