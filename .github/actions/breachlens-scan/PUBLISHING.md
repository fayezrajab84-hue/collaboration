# Publishing the BreachLens Scan Action to GitHub Marketplace

End-to-end checklist for listing this Action on GitHub Marketplace. Most steps require the GitHub web UI — Marketplace doesn't have a CLI flow.

---

## Pre-flight check

Before you start, verify the bundle is publish-ready:

```bash
ls .github/actions/breachlens-scan/
# Expected:
#   action.yml          (composite action definition)
#   README.md           (Marketplace listing content)
#   LICENSE             (MIT)
#   example-workflow.yml
```

All four must exist and the README's "Quickstart" workflow must be copy-pasteable into a real consumer repo.

---

## Path 1 — Publish from this monorepo (fastest)

GitHub allows publishing an Action from any subdirectory of a public repo. Users reference it as `<owner>/<repo>/<path>@<ref>`.

### Steps

1. **Make the repo public** (if not already)
   - Settings → General → Danger Zone → "Change repository visibility"
   - GitHub Marketplace requires the source repo to be public.

2. **Merge your Action work to `main`**
   - This Action is currently on the `claude/admiring-hertz` branch.
   - Open a PR `claude/admiring-hertz → main`, get it merged.
   - Marketplace's "release" picker only sees tags pointing at the default branch.

3. **Tag a release**
   ```bash
   git checkout main && git pull
   git tag -a v1.0.0 -m "Initial Marketplace release"
   git push origin v1.0.0
   ```
   For convenience, also create a moving `v1` tag that follows the latest `v1.x.y`:
   ```bash
   git tag -fa v1 -m "Latest v1 release"
   git push origin v1 --force
   ```

4. **Draft a release in GitHub UI**
   - Go to **Releases** → **Draft a new release** → pick the `v1.0.0` tag.
   - Title: `v1.0.0 — Initial release`
   - Description: paste the README's Quickstart + "What's included" highlights.
   - Check the **"Publish this Action to the GitHub Marketplace"** box (only appears when the repo's `action.yml` is detected — it'll be detected automatically).
   - Pick **Primary Category** = "Security" and **Secondary Category** = "Code quality".

5. **Marketplace review**
   - GitHub auto-validates the action.yml + README + branding.
   - Common rejections:
     - `branding.icon` not in the [allowed list](https://docs.github.com/en/actions/sharing-automations/creating-actions/metadata-syntax-for-github-actions#brandingicon) — we use `shield` which is allowed
     - Missing LICENSE file — we have MIT
     - README missing screenshots / unclear value prop — our README has both
   - Approval is usually within 1-2 days.

6. **Verify the listing**
   - Once approved, the Action is at `https://github.com/marketplace/actions/breachlens-scan`.
   - External repos can use `uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1`.

---

## Path 2 — Publish from a dedicated repo (cleaner branding)

If you want `fayezrajab84-hue/breachlens-action@v1` (shorter consumer path), publish from a single-purpose repo. More work but cleaner.

### Steps

1. **Create a new public repo**
   ```bash
   gh repo create fayezrajab84-hue/breachlens-action --public \
     --description "GitHub Action for BreachLens security scans"
   ```

2. **Initialize with the Action's bundle at the root**
   ```bash
   cd /tmp && git clone https://github.com/fayezrajab84-hue/breachlens-action.git
   cd breachlens-action
   cp /path/to/main/.github/actions/breachlens-scan/{action.yml,README.md,LICENSE,example-workflow.yml} .

   # The README's `uses:` references will need updating from
   #   fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
   # to
   #   fayezrajab84-hue/breachlens-action@v1
   sed -i.bak 's|fayezrajab84-hue/collaboration/.github/actions/breachlens-scan|fayezrajab84-hue/breachlens-action|g' README.md
   rm README.md.bak

   git add . && git commit -m "feat: initial release"
   git push
   ```

3. **Tag + release** (same as Path 1 step 3-4, but in the new repo)
   ```bash
   git tag -a v1.0.0 -m "Initial Marketplace release"
   git tag -fa v1 -m "Latest v1 release"
   git push origin v1.0.0 v1 --force
   ```

4. **Marketplace review** (same as Path 1 step 5-6)

5. **Maintenance loop**
   - When the Action changes in the main monorepo, sync changes to the standalone repo and bump the version:
     ```bash
     cd /tmp/breachlens-action
     # Pull updated action.yml
     curl -fsSL https://raw.githubusercontent.com/fayezrajab84-hue/collaboration/main/.github/actions/breachlens-scan/action.yml -o action.yml
     git add action.yml && git commit -m "feat: sync v1.1.0"
     git tag v1.1.0 && git tag -fa v1
     git push origin main v1.1.0 v1 --force
     ```
   - Or set up a [scheduled workflow in this monorepo](.github/workflows/) that auto-syncs the standalone repo on tagged releases.

---

## Versioning policy

| Bump | When |
|---|---|
| Patch (v1.0.x) | Bug fixes; no input/output changes |
| Minor (v1.x.0) | New optional inputs; new outputs; backward-compatible |
| Major (vx.0.0) | Removed inputs; renamed inputs; changed default behaviour |

Keep the moving `v1` tag pointing at the latest `v1.x.y` so users pinned to `@v1` get patches automatically.

---

## What to ship in v1.0.0

The current bundle includes everything needed:

| Feature | Status |
|---|---|
| Trigger scan from GitHub Actions | ✅ |
| Poll for completion with configurable timeout | ✅ |
| Severity gate (CRITICAL / HIGH / MEDIUM / LOW / INFO / none) | ✅ |
| SARIF 2.1.0 download | ✅ |
| Code Scanning upload | ✅ |
| Step summary table | ✅ |
| Outputs for downstream steps (counts, scan-id, status) | ✅ |
| API token auth (preferred) | ✅ |
| Session cookie auth (deprecated, kept for backwards compat) | ✅ |
| Three target types (repo / container / domain) | ✅ |

What to deliberately defer to v1.1+:

- PR comment posting (the Code Scanning upload covers PR-level visibility today)
- Per-finding dismissal flow (operator-driven via the BreachLens UI)
- Custom-rule severity overrides
- Multi-target scans in a single step (run one Action per target instead)

---

## Marketplace categories

Pick **two** at listing time:

- **Primary: Security** — required for security-tooling discoverability
- **Secondary: Code quality** OR **Continuous integration** — surfaces in DevSecOps category browses

---

## Branding

The `branding:` block in `action.yml` controls the Marketplace tile:

```yaml
branding:
  icon:  shield
  color: blue
```

`shield` is one of GitHub's [allowed icon names](https://docs.github.com/en/actions/sharing-automations/creating-actions/metadata-syntax-for-github-actions#brandingicon). `blue` matches the BreachLens brand-indigo.

For the listing page itself (header image, screenshots), add to the README — Marketplace renders the README directly. Suggested screenshots to add before listing:

1. Step-summary table from a real run (severity counts in green/red badges)
2. GitHub Code Scanning Security tab showing BreachLens findings
3. PR diff showing inline finding annotations

---

## Post-listing

After the Action is live:

1. Update the [main repo README](../../../README.md) with a "CI integration" section pointing at the Marketplace listing
2. Add a `.github/workflows/security.yml` to the BreachLens repo itself, dogfooding the Action against this codebase
3. Open issues in the consumer repos (NodeGoat, juice-shop, etc.) demonstrating real findings flowing through the pipeline
4. Track adoption — `lastUsedAt` on every minted token tells you which CI is actually using it

---

## What I cannot automate

The actual Marketplace listing happens through the GitHub web UI — there's no API for "publish this release to Marketplace". The release-creation step (step 4 in Path 1) is where you check the "Publish this Action to the GitHub Marketplace" box.

Everything up to that point — bundle preparation, tag creation, repo configuration — is scriptable. Everything from that point forward — listing approval, screenshots, descriptions on the Marketplace page itself — is operator action through GitHub UI.
