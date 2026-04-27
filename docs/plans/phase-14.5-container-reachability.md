# Phase 14.5 — Container reachability

**Status:** scoped, not started
**Predecessor:** Phase 14 (SCA reachability MVP — JS/TS + Python repo source) — ✅ shipped
**Surfaced by:** customer feedback after adding `vulnerables/web-dvwa` and seeing 120 findings all `UNKNOWN`. Truth-in-advertising fix (sharper tooltip explaining the gap) shipped same session; this phase fills the gap properly.

---

## What's broken right now

Phase 14's import-grep classifier walks a cloned repo's source tree and matches package names against `import` / `require` statements. That mechanic doesn't translate to container scans:

- **No source code**: container images ship as compiled binaries + bundled OS packages. There's nothing to grep.
- **OS packages dominate**: a typical container has 100-300 OS packages (libssl, glibc, openssl, php-modules, apache modules) — these are linked at OS-build time, not "imported" by anyone.
- **Bundled language packages live elsewhere**: `/app/node_modules`, `/usr/lib/python3.11/site-packages`, `/var/www/html/vendor` — paths vary per image. Even when the language packages are present, the customer's source code that uses them may also be in the image OR may be injected at runtime via a volume mount.

Result: every container finding gets `reachability = UNKNOWN`. The badge UX now (post-Phase-14.5-truth fix) reads as a known-gap rather than a scanner failure, but the actual classification is missing.

## Three approaches, ranked by cost/value

### A — Static entrypoint dependency closure *(recommended first cut, ~1 week)*

**Idea**: read the image's `CMD` / `ENTRYPOINT` from the manifest. Trace which binaries it invokes. For each OS package finding, check whether the package's installed files are in the dependency closure of those binaries (via `ldd` or the package manager's file-ownership database).

**Workflow**:
1. `trivy image --format json` already emits `Metadata.ImageConfig.config.Cmd` + `Entrypoint`
2. Pull + extract the image (Trivy already does this internally; we'd need to keep the layers around)
3. For each entrypoint binary, run `ldd` on it inside a sandboxed copy of the image's filesystem
4. Build a set of `loaded_paths`
5. For each finding, look up which files the package owns (`dpkg -L <pkg>` / `rpm -ql <pkg>`)
6. If any of the package's files appear in `loaded_paths` → REACHABLE; else NOT_REACHABLE
7. Plugins / dynamically-loaded modules → UNKNOWN (we can't see them via `ldd`)

**Catches**: "container runs `nginx`, so the `postgres-client` CVE is NOT_REACHABLE" — the dvwa case shows ~30-40% of OS package findings are deferrable this way.

**Misses**:
- Runtime-loaded plugins (Apache mods loaded by config, Python C extensions)
- Findings in interpreted runtimes (PHP / Python / Node) — knowing the binary is loaded doesn't tell you whether the vulnerable PHP function is called
- Multi-process containers (supervisord, etc.) need their full process tree analysed, not just the entrypoint

**Effort**: medium (~1 week). The hard part is plumbing the layer extraction + sandboxed `ldd` invocation; the matching logic is straightforward.

### B — Filesystem extraction + grep `/app` *(complementary, ~1-2 weeks)*

**Idea**: extract the image's filesystem to a temp dir. For language packages bundled at conventional paths (`/app`, `/srv`, `/var/www`, `/usr/src/app`), run the existing Phase 14 import-grep classifier against those paths. Falls back to UNKNOWN for OS packages.

**Workflow**:
1. `trivy image --download-db-only` then extract layers to `/tmp/scan_workspace/<id>/extracted`
2. Heuristic-detect the source directory (look for `package.json`, `requirements.txt`, `composer.json`, `Gemfile` outside common system dirs)
3. Run `_build_import_map(extracted_app_dir)` — same code that powers Phase 14 repo SCA
4. Match findings whose `PkgName` appears in the import map → REACHABLE

**Catches**: language-package findings inside containers (npm/pip/composer in `/app`). For full-stack-in-a-box images (Rails monolith, Node app) this is most of the findings.

**Misses**: same OS-package category as the static approach. Best paired WITH Approach A.

**Effort**: medium (~1-2 weeks). Trivy already does layer extraction; we'd need to keep the result accessible to our own code.

### C — Runtime instrumentation *(future, weeks-months)*

**Idea**: actually run the container in a sandbox, observe which shared libraries get loaded via `ldd` against running PIDs, plus `lsof` for opened files. Most accurate — captures plugins, dynamic loads, multi-process trees.

**Workflow**:
1. Pull image, run with restricted capabilities (no network, read-only root, ephemeral)
2. Wait for steady state (30s? configurable per-image)
3. Snapshot loaded libraries from `/proc/*/maps` for every process in the container
4. Match against package file ownership

**Catches**: everything Approaches A + B catch, plus runtime-loaded modules.

**Misses**: code paths only triggered by specific HTTP requests (would need fuzz-traffic generation). Containers that need external services to start. Rare-but-real "this CVE is in cron job that fires once a week".

**Effort**: high (weeks-months). Requires running untrusted images safely — security model + orchestration cost is the bulk of the work, not the analysis itself.

**Endor's approach**: B+C combined. Their secret sauce is the runtime-tracing layer that captures actual loaded code paths.

## Recommendation

**Phase 14.5** = Approach A only. Ship the entrypoint-closure classifier; gives the dvwa example concrete value (a chunk of OS-package CVEs flip to NOT_REACHABLE) and matches the headline noise-reduction claim for containers.

**Phase 14.6** = Approach B (filesystem extraction). Composes cleanly on top of A: A handles OS packages, B handles bundled language packages. Together they cover most real customer images.

**Phase 14.7 / Phase 18.x** = Approach C (runtime). Defer until Phase 18 (CSPM) is in flight — that phase is already going to need a sandboxed-execution layer for cloud-config validation, so the infra investment compounds.

## Open questions to settle before starting

1. **Do we extract the image client-side (in the scanner container) or use a sidecar?**
   The scanner container already has Trivy + access to Docker socket via `/var/run/docker.sock` (in dev). Extraction in-process is simpler; sidecar is safer. Probably in-process for v1, sidecar later if it bites.

2. **How do we handle multi-arch images?**
   `linux/amd64` is the obvious default. Multi-arch with platform-specific deps (uncommon but real) may need per-arch classification. Defer to Phase 14.6.

3. **What's the cost ceiling per scan?**
   Static analysis (A) is ~10-30s per image. Filesystem extraction (B) adds 1-2 min for large images. Runtime (C) is multi-minute. Need a per-target budget or the scan queue clogs up.

4. **Where does the "image entrypoint" come from when Kubernetes / docker-compose overrides it?**
   The image's default CMD/ENTRYPOINT is what the static analyzer sees. The actual deployed entrypoint may differ. Phase 14.5 ships with image-default semantics and a documented limitation; Phase 18 (CSPM) can refine this once we have visibility into actual cluster manifests.

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A1 — Layer extraction + entrypoint closure plumbing | ~400 | 3 days |
| A2 — `ldd` analysis + file-ownership matching | ~250 | 2 days |
| A3 — Wire into container scanner + emit `reachability` evidence | ~100 | 1 day |
| A4 — Sharpen badge tooltip again (containers that ARE classified shouldn't say "not yet supported") | ~30 | 1 hour |
| **Total Phase 14.5 (A only)** | **~780** | **~1 week** |

Phase 14.6 (B) and beyond add another 1-2 weeks each.

## Strategic position

Phase 14 MVP gave BreachLens the Endor headline number on JS/Python repo SCA. Phase 14.5 brings the same story to **container** SCA — which is the half customers care about more for production deployments. CSPM-adjacent buyers will ask for this directly; having it in roadmap (and shipping the truth-in-advertising tooltip today) is the right preparation.
