/**
 * OpenAPI / Swagger spec → URL list extractor.
 *
 * Used by scanWorker to expand an imported `DomainApiSpec` into a list of
 * concrete URLs the DAST / pentest scanners hit.
 *
 * Improvements over the previous inline implementation:
 *   - One URL per *operation* (path × method) rather than per path, so
 *     downstream tools see every documented operation as a distinct target.
 *   - Type-aware path & query parameter substitution using the parameter
 *     schema (integer→1, uuid→zero-uuid, email format→test@example.com,
 *     date→2024-01-01, etc.) — much less likely to short-circuit a 404
 *     handler that only triggers on validly-shaped IDs.
 *   - Required query parameters appended as `?k=v&...` so endpoints that
 *     400 on missing params are reachable.
 *   - OpenAPI 3.x `servers[]` *and* Swagger 2.x `host`+`basePath`+`schemes`
 *     both honoured; relative server URLs resolved against the target.
 *
 * Note: only URL strings are produced — Phase 1 deliberately keeps the
 * scanner contract (`api_spec_urls: string[]`) backward-compatible. Phase
 * 2/3 will introduce a richer `ApiSpecRequest[]` shape with method/body
 * for sqlmap / xsstrike payload replay.
 */

type Json = Record<string, unknown>;

const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "options", "head"] as const;
type Method = (typeof HTTP_METHODS)[number];

interface OpenApiParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  schema?: { type?: string; format?: string; enum?: unknown[]; default?: unknown };
  // Swagger 2.x style — schema fields live directly on the parameter
  type?: string;
  format?: string;
  enum?: unknown[];
  default?: unknown;
  example?: unknown;
}

/**
 * Pick a deterministic, schema-respecting sample value for a parameter.
 * The goal isn't realism — it's "shaped so the server's validator accepts
 * it and routes the request through". Hard-coded "1" for everything was
 * causing 404s on UUID-style routes, so we bias toward type-correctness.
 */
function sampleValue(p: OpenApiParameter): string {
  if (p.example !== undefined) return String(p.example);
  if (p.default !== undefined) return String(p.default);

  const enumVals = p.schema?.enum ?? p.enum;
  if (Array.isArray(enumVals) && enumVals.length > 0) {
    return String(enumVals[0]);
  }

  const type = p.schema?.type ?? p.type ?? "string";
  const format = p.schema?.format ?? p.format ?? "";

  switch (type) {
    case "integer":
    case "number":
      return "1";
    case "boolean":
      return "true";
    case "array":
      return "1"; // single-element fallback; tools query-string repeat as needed
    default:
      // string + format-aware substitutions
      switch (format) {
        case "uuid":      return "00000000-0000-0000-0000-000000000000";
        case "email":     return "test@example.com";
        case "date":      return "2024-01-01";
        case "date-time": return "2024-01-01T00:00:00Z";
        case "uri":
        case "url":       return "http://example.com";
        case "ipv4":      return "127.0.0.1";
        case "byte":      return "dGVzdA==";  // base64 "test"
        case "binary":    return "test";
        case "hostname":  return "example.com";
        default:          return "test";
      }
  }
}

/**
 * Resolve the base URL for spec-derived requests.
 * - OpenAPI 3.x: prefer `servers[0].url`. If relative, anchor on the target domain.
 * - Swagger 2.x: synthesize from `schemes[0]` + `host` + `basePath`.
 * - Fallback: `http://${targetDomain}`.
 *
 * `serverVarDefaults` resolves `{variables}` in `servers[].url` using the
 * declared default value — most public specs use these for environments.
 */
function resolveBaseUrl(spec: Json, targetDomain: string): string {
  const fallback = `http://${targetDomain}`;

  const servers = spec["servers"] as Array<{ url: string; variables?: Record<string, { default?: string }> }> | undefined;
  if (servers?.length) {
    let url = servers[0]!.url;
    // Substitute {variable} placeholders with their default
    const vars = servers[0]!.variables ?? {};
    url = url.replace(/\{([^}]+)\}/g, (_, name) => vars[name]?.default ?? name);
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return url.replace(/\/$/, "");
    }
    // Relative server path — graft onto the configured target
    return `${fallback}${url.startsWith("/") ? "" : "/"}${url}`.replace(/\/$/, "");
  }

  const host = spec["host"] as string | undefined;
  if (host) {
    const schemes = spec["schemes"] as string[] | undefined;
    const scheme = schemes?.includes("https") ? "https" : (schemes?.[0] ?? "http");
    const basePath = (spec["basePath"] as string | undefined) ?? "";
    return `${scheme}://${host}${basePath}`.replace(/\/$/, "");
  }

  return fallback;
}

/**
 * Merge operation parameters with path-level parameters (the spec allows
 * declaring shared `parameters` on the path item that every operation
 * inherits). Operation-level entries with the same name+location override.
 */
function mergeParameters(pathItem: Json, op: Json): OpenApiParameter[] {
  const pathParams  = (pathItem["parameters"] as OpenApiParameter[] | undefined) ?? [];
  const opParams    = (op["parameters"]       as OpenApiParameter[] | undefined) ?? [];
  const merged = new Map<string, OpenApiParameter>();
  for (const p of pathParams) merged.set(`${p.in}:${p.name}`, p);
  for (const p of opParams)   merged.set(`${p.in}:${p.name}`, p);
  return Array.from(merged.values());
}

/**
 * Expand one (path, method) operation into a concrete URL string with
 * `{path}` placeholders substituted and required query params appended.
 */
function buildOperationUrl(baseUrl: string, path: string, params: OpenApiParameter[]): string {
  // Substitute path parameters
  let resolved = path;
  for (const p of params.filter((x) => x.in === "path")) {
    resolved = resolved.replace(new RegExp(`\\{${p.name}\\}`, "g"), encodeURIComponent(sampleValue(p)));
  }
  // Anything still wrapped in {} (param wasn't declared) → fallback "1"
  resolved = resolved.replace(/\{[^}]+\}/g, "1");

  // Append required query params; skip optional to keep the URL set small
  const requiredQ = params.filter((x) => x.in === "query" && x.required);
  const qs = requiredQ
    .map((p) => `${encodeURIComponent(p.name)}=${encodeURIComponent(sampleValue(p))}`)
    .join("&");

  return qs ? `${baseUrl}${resolved}?${qs}` : `${baseUrl}${resolved}`;
}

export interface ExtractResult {
  urls: string[];      // unique URL strings, ready for nuclei -l / ZAP seed
  operations: number;  // total operations seen (path × method) — for telemetry
}

export function extractApiSpecUrls(specJson: unknown, targetDomain: string): ExtractResult {
  if (!specJson || typeof specJson !== "object") {
    return { urls: [], operations: 0 };
  }
  const spec = specJson as Json;
  const paths = (spec["paths"] as Record<string, Json> | undefined) ?? {};
  const baseUrl = resolveBaseUrl(spec, targetDomain);

  const seen = new Set<string>();
  const urls: string[] = [];
  let operations = 0;

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;

    for (const method of HTTP_METHODS) {
      const op = pathItem[method as Method] as Json | undefined;
      if (!op || typeof op !== "object") continue;
      operations++;

      const params = mergeParameters(pathItem, op);
      const url = buildOperationUrl(baseUrl, path, params);
      if (!seen.has(url)) {
        seen.add(url);
        urls.push(url);
      }
    }
  }

  return { urls, operations };
}

/**
 * Lightweight structural validation. Returns null if valid OpenAPI 2 or 3
 * shape; otherwise a short human-readable reason. We deliberately avoid a
 * full JSON-schema validator here — most real-world specs are slightly
 * non-conformant but still useful as URL sources.
 */
export function validateOpenApiShape(spec: unknown): string | null {
  if (!spec || typeof spec !== "object") return "spec must be a JSON object";
  const s = spec as Json;
  const isV3 = typeof s["openapi"] === "string" && (s["openapi"] as string).startsWith("3.");
  const isV2 = s["swagger"] === "2.0";
  if (!isV3 && !isV2) {
    return "expected `openapi: 3.x.x` or `swagger: 2.0` at the root";
  }
  if (!s["paths"] || typeof s["paths"] !== "object") {
    return "missing or invalid `paths` object";
  }
  const pathCount = Object.keys(s["paths"] as object).length;
  if (pathCount === 0) {
    return "spec contains zero paths";
  }
  return null;
}

/**
 * Count operations (path × method) in the spec — used for the endpoint
 * counter shown in the UI.
 */
export function countOperations(spec: unknown): number {
  if (!spec || typeof spec !== "object") return 0;
  const paths = ((spec as Json)["paths"] as Record<string, Json> | undefined) ?? {};
  let n = 0;
  for (const item of Object.values(paths)) {
    if (!item || typeof item !== "object") continue;
    for (const m of HTTP_METHODS) {
      if (item[m as Method] !== undefined) n++;
    }
  }
  return n;
}
