/**
 * DomainUrlsPanel — tree view of URLs captured by ZAP for a domain.
 *
 * Source: GET /api/domains/:id/urls. The backend pulls ZAP's site tree
 * filtered to the domain's host, so the list reflects every URL the
 * operator's browser proxied during recording (or that any prior ZAP-
 * driven scan discovered). Survives `recording.stop()` — useful for
 * post-session triage.
 *
 * UI shape:
 *   • Header — "N URLs captured" + recording-status chip + filter input
 *   • Tree   — host root → /path/segments/ folders → leaf URL rows.
 *              Folders show the count of URLs within. Leaves show the
 *              full URL (with query string) and a copy icon.
 *   • Empty  — friendly hint: "Start a recording to capture URLs"
 *
 * Why a tree (not a flat list):
 *   • A domain with auth + 5 vuln pages × 4 query variants becomes a
 *     20-row flat list — readable but pattern-blind. The tree groups by
 *     /vulnerabilities/sqli vs /vulnerabilities/xss_r at a glance, so the
 *     operator can spot uncovered routes (e.g. /admin/* never visited)
 *     without scrolling 20 rows.
 *   • Matches the operator's mental model — they recorded by clicking
 *     pages, so the path hierarchy is what they remember.
 */
import { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Network, ChevronRight, ChevronDown, Search, Copy, Check, ExternalLink,
  Globe, Folder, FileText, KeyRound,
} from "lucide-react";
import { domainsApi } from "../lib/api";

type UrlNode = {
  /** Display label — last URL segment, or hostname for the root. */
  label:    string;
  /** Full URL when this node is a leaf; null for folders. */
  fullUrl:  string | null;
  /** Depth in the tree (root = 0). Used for indentation. */
  depth:    number;
  /** Children keyed by next path segment for O(1) merge while building. */
  children: Map<string, UrlNode>;
  /** Number of leaf URLs in this subtree (for folder badge counts). */
  leafCount: number;
  /** True when the URL contains query params — flagged for parameter-mining. */
  hasQuery:  boolean;
};

function emptyNode(label: string, depth: number): UrlNode {
  return {
    label, depth, fullUrl: null, leafCount: 0, hasQuery: false,
    children: new Map<string, UrlNode>(),
  };
}

/**
 * Build a path-segment tree from a flat URL list. We split on `/` so a
 * URL like `http://dvwa/vulnerabilities/sqli/?id=1` becomes:
 *   root → "vulnerabilities" (folder) → "sqli" (folder) → "?id=1" (leaf)
 *
 * The host (e.g. `http://dvwa`) becomes the root node's label so the
 * tree is self-contained — no host-bar above the tree, single visual
 * column, less wasted horizontal space.
 */
function buildTree(urls: string[]): UrlNode | null {
  if (urls.length === 0) return null;

  // Group by origin so we can build one tree per host (rare in practice
  // since the API filters to a single domain, but defensive).
  const byOrigin = new Map<string, string[]>();
  for (const u of urls) {
    try {
      const parsed = new URL(u);
      const origin = parsed.origin;
      if (!byOrigin.has(origin)) byOrigin.set(origin, []);
      byOrigin.get(origin)!.push(u);
    } catch {
      // Malformed URL — skip rather than crash the tree.
    }
  }

  // Single-origin case (the common one) — just build it.
  const origins = [...byOrigin.entries()];
  if (origins.length === 0) return null;
  // Multiple origins (unexpected) — pick the one with the most URLs as
  // the visible tree. Operators inspecting a multi-origin recording can
  // still see counts via the header; full multi-tree UI isn't worth the
  // complexity for an edge case.
  origins.sort(([, a], [, b]) => b.length - a.length);
  const [originRaw, originUrls] = origins[0]!;

  const root = emptyNode(originRaw, 0);

  for (const fullUrl of originUrls) {
    let parsed: URL;
    try { parsed = new URL(fullUrl); } catch { continue; }
    // Path segments: filter empty (`/foo/` splits to `["", "foo", ""]`).
    const segments = parsed.pathname.split("/").filter(Boolean);
    const queryStr = parsed.search;            // includes leading "?"

    let cur = root;
    cur.leafCount++;

    if (segments.length === 0) {
      // Just the host (e.g. http://dvwa/  or  http://dvwa/?id=1)
      const leafLabel = queryStr || "/";
      let leaf = cur.children.get(leafLabel);
      if (!leaf) {
        leaf = emptyNode(leafLabel, cur.depth + 1);
        cur.children.set(leafLabel, leaf);
      }
      leaf.fullUrl  = fullUrl;
      leaf.leafCount = 1;
      leaf.hasQuery = queryStr.length > 0;
      continue;
    }

    for (let i = 0; i < segments.length; i++) {
      const seg     = segments[i]!;
      const isLast  = i === segments.length - 1;
      // The leaf label for the last segment includes the query string —
      // that's the most useful unit for the operator (a URL with a query
      // is a different attack target than one without).
      const label   = isLast ? `${seg}${queryStr}` : seg;
      let next = cur.children.get(label);
      if (!next) {
        next = emptyNode(label, cur.depth + 1);
        cur.children.set(label, next);
      }
      next.leafCount++;
      if (isLast) {
        next.fullUrl  = fullUrl;
        next.hasQuery = queryStr.length > 0;
      }
      cur = next;
    }
  }

  return root;
}

/**
 * Recursive tree row. Folders click to expand/collapse; leaves click to
 * copy the full URL. We track expanded state at the panel level so a
 * "Collapse all / Expand all" header button stays cheap.
 */
function TreeRow({
  node, expanded, onToggle, search, copyUrl, copiedUrl,
}: {
  node:      UrlNode;
  expanded:  Set<string>;
  onToggle:  (key: string) => void;
  search:    string;
  copyUrl:   (url: string) => void;
  copiedUrl: string | null;
}) {
  // Use the node's path-from-root as a unique key for the expanded Set.
  // This is rebuilt on each render which is fine since the tree is
  // capped at ~5000 leaves and the recursive walk is single-pass.
  const isLeaf = node.children.size === 0;
  const isOpen = expanded.has(nodeKey(node));

  // Visibility filter — when a search term is set, only show subtrees
  // that contain a matching leaf. We pre-compute matchedSet at the panel
  // level and pass via context so each row decides cheaply.
  const matches = matchesFilter(node, search);
  if (!matches) return null;

  if (isLeaf) {
    const url = node.fullUrl ?? node.label;
    const justCopied = copiedUrl === url;
    return (
      <div
        className="group flex items-center gap-2 rounded px-2 py-1 hover:bg-gray-800/60"
        style={{ paddingLeft: `${node.depth * 16 + 8}px` }}
      >
        <FileText className={`h-3.5 w-3.5 flex-shrink-0 ${node.hasQuery ? "text-amber-400" : "text-gray-500"}`} />
        <span className="font-mono text-xs text-gray-300 break-all flex-1">{node.label}</span>
        {node.hasQuery && (
          <span
            className="flex-shrink-0 rounded bg-amber-950/40 px-1.5 py-0.5 text-[10px] font-medium text-amber-300 border border-amber-900/40"
            title="URL has query parameters — eligible for parameter-mining attacks (XSS, SQLi, IDOR)"
          >
            <KeyRound className="inline h-2.5 w-2.5 mr-1" />param
          </span>
        )}
        <button
          onClick={() => copyUrl(url)}
          className="flex-shrink-0 p-1 text-gray-600 hover:text-indigo-300 opacity-0 group-hover:opacity-100"
          title="Copy URL"
        >
          {justCopied
            ? <Check className="h-3 w-3 text-emerald-400" />
            : <Copy  className="h-3 w-3" />
          }
        </button>
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex-shrink-0 p-1 text-gray-600 hover:text-indigo-300 opacity-0 group-hover:opacity-100"
          title="Open in new tab"
        >
          <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    );
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => onToggle(nodeKey(node))}
        className="flex w-full items-center gap-1 rounded px-2 py-1 text-left hover:bg-gray-800/60"
        style={{ paddingLeft: `${node.depth * 16 + 4}px` }}
      >
        {isOpen
          ? <ChevronDown  className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
          : <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
        }
        {node.depth === 0
          ? <Globe  className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
          : <Folder className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
        }
        <span className={`font-mono text-xs ${node.depth === 0 ? "text-indigo-200" : "text-gray-300"}`}>
          {node.label}
        </span>
        <span className="ml-auto pr-2 text-[10px] text-gray-500">
          {node.leafCount} URL{node.leafCount === 1 ? "" : "s"}
        </span>
      </button>
      {isOpen && (
        <div>
          {[...node.children.values()].map((c) => (
            <TreeRow
              key={nodeKey(c)}
              node={c}
              expanded={expanded}
              onToggle={onToggle}
              search={search}
              copyUrl={copyUrl}
              copiedUrl={copiedUrl}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Stable key for a node = its label-path from root. Tree shape doesn't
// change at runtime so this is fine without memoising.
function nodeKey(node: UrlNode): string {
  return `${node.depth}:${node.label}`;
}

/**
 * Returns true if the subtree rooted at `node` contains at least one
 * leaf whose label or fullUrl includes the (lowercased) search term.
 * Empty search → everything matches. Inlined recursion to avoid a
 * separate match-set pre-pass.
 */
function matchesFilter(node: UrlNode, search: string): boolean {
  if (!search) return true;
  const term = search.toLowerCase();
  if (node.label.toLowerCase().includes(term)) return true;
  if (node.fullUrl && node.fullUrl.toLowerCase().includes(term)) return true;
  for (const c of node.children.values()) {
    if (matchesFilter(c, term)) return true;
  }
  return false;
}

// Collect every node key for "Expand all" so chevrons flip in one tap.
function allFolderKeys(node: UrlNode, out: Set<string> = new Set()): Set<string> {
  if (node.children.size > 0) out.add(nodeKey(node));
  for (const c of node.children.values()) allFolderKeys(c, out);
  return out;
}

export default function DomainUrlsPanel({
  domainId,
  embedded = false,
}: {
  domainId: string;
  /**
   * When true, render in compact "left rail" mode:
   *  - drops the bordered card chrome (parent provides it)
   *  - hides the big "Captured URLs · N" header (label lives in the rail header)
   *  - keeps filter input but moves the expand/collapse + refresh into a tight row
   *  - height grows to fill the parent so the tree scrolls vertically inside
   * Used by DomainDetailPage's site-map rail.
   */
  embedded?: boolean;
}) {
  const [search, setSearch]       = useState("");
  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["domain-urls", domainId],
    queryFn:  () => domainsApi.listUrls(domainId),
    // Refetch when the panel is shown — operator may have just added URLs
    // by clicking through the live browser session. Keep it modest (5s)
    // so the request budget stays low when the panel sits open.
    refetchInterval: 5_000,
    refetchOnMount:  true,
  });

  const tree = useMemo(() => (data?.urls ? buildTree(data.urls) : null), [data?.urls]);

  // Default to expanding the host root only — keeps the initial render
  // compact for big trees (DVWA recording = 77 URLs across 12 folders).
  // Operator can "Expand all" if they want everything flat.
  const defaultExpanded = useMemo(() => {
    if (!tree) return new Set<string>();
    return new Set([nodeKey(tree)]);
  }, [tree]);

  // Re-seed `expanded` whenever the tree shape changes (e.g. new URLs
  // captured during a live recording). Operator-collapsed nodes stay
  // closed because we union with the existing set.
  const effectiveExpanded = useMemo(() => {
    return new Set<string>([...defaultExpanded, ...expanded]);
  }, [defaultExpanded, expanded]);

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key) || defaultExpanded.has(key)) {
        // Either the node is currently open via the user's choice OR via
        // the default-open seed. In both cases close → just remove from
        // user-set; the default still seeds open until they collapse.
        // We track an explicit collapsed-set to handle this cleanly.
        if (defaultExpanded.has(key)) {
          // Currently open via default; user wants to close it. Move
          // from default → tracked-collapsed by removing the default
          // seed and not re-adding to user-open. Simpler: just never
          // include this key when computing effectiveExpanded.
          // We achieve that by tracking it as "user-closed":
          collapsedRef.current.add(key);
        }
        next.delete(key);
      } else {
        next.add(key);
        collapsedRef.current.delete(key);
      }
      return next;
    });
  }

  // We need a small mutable tracker for "user explicitly closed this
  // default-open node" so the default-expanded seed doesn't fight back.
  const collapsedRef = useRefSet();
  const visibleExpanded = useMemo(() => {
    const out = new Set<string>(effectiveExpanded);
    for (const k of collapsedRef.current) out.delete(k);
    return out;
  }, [effectiveExpanded]);

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url).then(() => {
      setCopiedUrl(url);
      setTimeout(() => setCopiedUrl(null), 1500);
    });
  }

  function expandAll() {
    if (!tree) return;
    setExpanded(allFolderKeys(tree));
    collapsedRef.current.clear();
  }
  function collapseAll() {
    setExpanded(new Set());
    if (tree) {
      // Mark the root as user-collapsed so the default seed doesn't
      // re-open it.
      const root = nodeKey(tree);
      collapsedRef.current.add(root);
    }
  }

  // ── render ──────────────────────────────────────────────────────────

  if (isLoading) {
    return <div className="py-8 text-center text-xs text-gray-500">Loading URLs…</div>;
  }

  const session = data?.session;
  const totalCount = data?.count ?? 0;

  // Container chrome differs between standalone (bordered card) and
  // embedded (parent rail provides chrome, we just render content).
  const Wrapper = embedded
    ? (props: { children: React.ReactNode }) => <div className="space-y-2">{props.children}</div>
    : (props: { children: React.ReactNode }) => (
        <div className="rounded-lg border border-gray-800 bg-gray-950/60">{props.children}</div>
      );

  return (
    <Wrapper>
      {/* Header — full bar standalone, compact in rail mode */}
      {embedded ? (
        <div className="space-y-2 px-1 pb-2">
          {/* Compact stats line */}
          <div className="flex items-center justify-between text-[11px] text-gray-500">
            <span className="flex items-center gap-1.5">
              <Network className="h-3 w-3 text-indigo-400" />
              <span className="font-medium text-gray-300">{totalCount} URLs</span>
              {isFetching && totalCount > 0 && (
                <span className="text-gray-600">·</span>
              )}
              {isFetching && totalCount > 0 && (
                <span className="text-gray-600">refreshing</span>
              )}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={expandAll}
                title="Expand all"
                className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
              >
                <span className="text-[10px]">+</span>
              </button>
              <button
                onClick={collapseAll}
                title="Collapse all"
                className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
              >
                <span className="text-[10px]">−</span>
              </button>
              <button
                onClick={() => refetch()}
                title="Refresh"
                className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
              >
                ⟳
              </button>
            </div>
          </div>
          {session && (
            <span className="flex items-center gap-1.5 text-[10px] text-gray-500">
              <span className={`inline-block h-1.5 w-1.5 rounded-full ${
                session.status === "ACTIVE"
                  ? "bg-emerald-400 animate-pulse"
                  : session.status === "SCANNING"
                  ? "bg-sky-400 animate-pulse"
                  : "bg-gray-600"
              }`} />
              {session.status === "ACTIVE"   ? "Recording"
               : session.status === "SCANNING" ? "Scanning"
               : `Last: ${session.urlCount} URL${session.urlCount === 1 ? "" : "s"}`}
            </span>
          )}
          {/* Filter — full width in compact mode */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter URLs"
              className="w-full rounded border border-gray-800 bg-gray-900 py-1 pl-7 pr-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-indigo-400" />
            <span className="text-sm font-semibold text-gray-200">Captured URLs</span>
            <span className="rounded-full bg-gray-800 px-2 py-0.5 text-[10px] font-medium text-gray-400">
              {totalCount}
            </span>
            {isFetching && totalCount > 0 && (
              <span className="text-[10px] text-gray-600">refreshing…</span>
            )}
          </div>

          {session && (
            <span className="flex items-center gap-1.5 text-[10px] text-gray-500">
              <span className={`inline-block h-1.5 w-1.5 rounded-full ${
                session.status === "ACTIVE"
                  ? "bg-emerald-400 animate-pulse"
                  : session.status === "SCANNING"
                  ? "bg-sky-400 animate-pulse"
                  : "bg-gray-600"
              }`} />
              {session.status === "ACTIVE"   ? "Recording in progress"
               : session.status === "SCANNING" ? "Scan running"
               : `Last recording: ${session.urlCount} URL${session.urlCount === 1 ? "" : "s"} captured`}
            </span>
          )}

          <div className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter URLs"
                className="w-44 rounded border border-gray-800 bg-gray-900 py-1 pl-7 pr-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>
            <button
              onClick={expandAll}
              className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-400 hover:border-indigo-700 hover:text-indigo-300"
            >
              Expand all
            </button>
            <button
              onClick={collapseAll}
              className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-400 hover:border-indigo-700 hover:text-indigo-300"
            >
              Collapse all
            </button>
            <button
              onClick={() => refetch()}
              className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-400 hover:border-indigo-700 hover:text-indigo-300"
            >
              Refresh
            </button>
          </div>
        </div>
      )}

      {/* Tree */}
      <div className={embedded ? "max-h-[60vh] overflow-y-auto" : "max-h-96 overflow-y-auto px-2 py-2"}>
        {tree ? (
          <TreeRow
            node={tree}
            expanded={visibleExpanded}
            onToggle={toggle}
            search={search}
            copyUrl={copyUrl}
            copiedUrl={copiedUrl}
          />
        ) : (
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <Globe className="h-6 w-6 text-gray-700" />
            <p className="text-xs text-gray-500">
              {session
                ? "No URLs in ZAP's site tree right now."
                : "No recording started for this domain yet."}
            </p>
            <p className="max-w-md text-[11px] text-gray-600">
              Open the <span className="text-gray-500">Recording</span> chip and
              click <span className="text-gray-400">Start</span> — point your
              browser at the proxy and the URLs you visit appear here within
              5 seconds.
            </p>
          </div>
        )}
      </div>
    </Wrapper>
  );
}

// Tiny "tracked-collapsed" mutable set used to differentiate
// "user-default-open + still open" from "user-default-open + then
// explicitly closed". The collapsedRef lets the toggle handler track
// the latter without rerunning the default-expanded seed every render.
function useRefSet() {
  const ref = useRef<Set<string>>(new Set());
  return ref;
}
