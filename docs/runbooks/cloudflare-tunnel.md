# Cloudflare Tunnel runbook

> Operator runbook for exposing your local BreachLens deployment on a
> public hostname so GitHub Actions runners (and any external caller)
> can reach it. Uses Cloudflare Tunnel — no firewall changes, no port
> forwarding, no inbound exposure.

This is **Phase A6** in the CI integration arc. With this in place, the
breachlens-scan GitHub Action can target your deployment from any
public GitHub repo, completing the round-trip Stage 2 test.

---

## Why Cloudflare Tunnel and not ngrok / port forwarding

| Option | Pros | Cons |
|---|---|---|
| **Cloudflare Tunnel** *(this runbook)* | Free, persistent URL, no firewall changes, no inbound port, terminates TLS at edge | Requires a Cloudflare-managed domain |
| ngrok | Zero setup | URL changes per session unless paid; rate limits |
| Port forwarding | Zero deps | Exposes inbound port; needs static IP / dynamic DNS; ISP may block; security risk |

For a tool that's meant to live in production CI pipelines, the tunnel
approach wins because the hostname is stable and no firewall config
ever leaves the operator's hands.

---

## Prerequisites

1. **A Cloudflare account** (free tier is fine).
2. **A domain managed by Cloudflare.** This runbook assumes
   `fortisentinel.org` — substitute your own. To put a domain under
   Cloudflare:
   - Sign in → Add a Site → enter your domain → Cloudflare scans
     existing DNS records → switch nameservers at your registrar to
     the two NS hostnames Cloudflare gives you.
   - Or buy directly from Cloudflare Registrar (at-cost, no markup).
3. **Docker Compose deployment running** — `docker compose ps` should
   show `web` as `healthy` before you start the tunnel.

---

## One-time setup (~5 min in the Cloudflare dashboard)

### 1. Create the tunnel

1. Open https://one.dash.cloudflare.com (Zero Trust dashboard — distinct
   from the regular dashboard).
2. **Networks → Tunnels → Create a tunnel**
3. **Connector type**: choose **Cloudflared**.
4. **Tunnel name**: `breachlens-dev` (operator-facing label).
5. Cloudflare displays platform-specific install commands. **Look at
   the Docker tab.** The command will be:

   ```
   docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token eyJh<long-base64-string>
   ```

6. **Copy the entire token** (the `eyJh…` portion). That's all we need
   from the install command — the BreachLens compose file already
   wraps the `tunnel run` part.

### 2. Configure the public hostname

Continue the Cloudflare wizard onto the **Public Hostnames** tab:

| Field | Value |
|---|---|
| Subdomain | `breachlens` |
| Domain | `fortisentinel.org` |
| Path | _(leave empty)_ |
| Service Type | **HTTP** |
| URL | `web:80` |

Click **Save tunnel**.

### 3. Verify DNS auto-creation

Cloudflare adds a CNAME record automatically — no manual DNS step.
Verify by opening **DNS → Records** in the regular Cloudflare dashboard
for `fortisentinel.org`. You should see a row:

```
Type: CNAME   Name: breachlens   Content: <tunnel-uuid>.cfargotunnel.com   Proxy: ☁️ Proxied
```

Don't toggle that off — Proxy mode is what gets you the public IP +
edge TLS for free.

---

## Wire it into BreachLens

### 1. Set the token in `.env`

```bash
# Edit .env, paste the token from step 1.5 above:
CLOUDFLARE_TUNNEL_TOKEN=eyJh<long-base64-string>
```

### 2. Bring up the tunnel

```bash
docker compose --profile tunnel up -d cloudflared
```

### 3. Watch it connect (~30s)

```bash
docker compose logs -f cloudflared
```

Look for:

```
INF Connection registered connIndex=0 ip=... location=... protocol=quic
INF Connection registered connIndex=1 ...
INF Updated to new configuration config="..."
```

Two `Connection registered` lines = healthy redundant edge connections.
If you see `failed to fetch token` the env var didn't pass through;
verify with `docker compose exec cloudflared env | grep TUNNEL_TOKEN`.

### 4. Validate from outside

```bash
# Hit the tunnel from anywhere (your phone, another machine, GitHub-hosted runner)
curl -s https://breachlens.fortisentinel.org/health
```

Expected: `{"status":"ok","db":"ok","redis":"ok"}` or similar — the
same response `localhost/health` gives. If you get Cloudflare's "no
healthy origin" error, the `web` service isn't healthy or the public
hostname routes to the wrong service URL.

---

## Use the public URL with the GitHub Action

### In your test repo's GitHub variables/secrets

| Type | Name | Value |
|---|---|---|
| Repository **variable** | `BREACHLENS_API_URL` | `https://breachlens.fortisentinel.org` |
| Repository **secret** | `BREACHLENS_API_TOKEN` | `blt_…` (mint via Settings → API Tokens) |

### Workflow file in the test repo

```yaml
name: Security scan
on: [pull_request, push]
permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@claude/admiring-hertz
        with:
          api-url:        ${{ vars.BREACHLENS_API_URL }}
          api-token:      ${{ secrets.BREACHLENS_API_TOKEN }}
          repo-id:        cmoh3qxnr00ki43p4nqix4zl4   # juice-shop, has known findings
          severity-gate:  HIGH
```

(Pin to `@v1` once you've tagged a release on `main`.)

---

## What the tunnel exposes (and what it does NOT)

The tunnel routes `breachlens.fortisentinel.org` → `web:80`
(the nginx container). Through that single hostname:

| Path | Reaches | Use |
|---|---|---|
| `https://breachlens.fortisentinel.org/` | Vite SPA | Browse the BreachLens UI from anywhere |
| `https://breachlens.fortisentinel.org/api/scans/...` | API service | GitHub Actions, the breachlens CLI, scripts |
| `https://breachlens.fortisentinel.org/auth/...` | OAuth flows | (works only after env vars below are updated) |

What stays internal (NOT reachable through the tunnel):
- Postgres (port 5432) — database
- Redis (port 6379) — queue
- Scanner services (port 8000) — only the API talks to them
- ZAP (port 8090) — only the scanner talks to it
- Wazuh manager — outbound calls only

---

## Optional: enable login through the public URL

For tonight's CI testing, **Bearer token auth works through the tunnel
without any other changes** — that's the only path GitHub Actions uses.

If you want to log in to the BreachLens UI via the public URL too,
update three env vars:

```bash
# .env
FRONTEND_URL=https://breachlens.fortisentinel.org
GITHUB_CALLBACK_URL=https://breachlens.fortisentinel.org/auth/github/callback
API_PUBLIC_URL=https://breachlens.fortisentinel.org
```

Then in your GitHub OAuth App settings (https://github.com/settings/developers):
- **Authorization callback URL**: add `https://breachlens.fortisentinel.org/auth/github/callback`
  (you can have multiple, comma-separated isn't required — GitHub stores them as a list)

Restart the API to pick up the new env vars:

```bash
docker compose restart api
```

You can keep `localhost` as a callback URL too — both will work.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cloudflared` container restarts in a loop | Token unset / invalid. Verify with `docker compose config cloudflared \| grep TUNNEL_TOKEN`. |
| Tunnel connects but `breachlens.fortisentinel.org` returns 502 | The `web` service isn't healthy. `docker compose ps` to verify; restart with `docker compose restart web`. |
| Tunnel returns 530 / "no healthy origin" | The Public Hostname's URL is misconfigured. In the Cloudflare dashboard, edit the hostname and confirm Service URL is exactly `web:80` (not `localhost:80` or `127.0.0.1:80`). |
| `/api/scans` returns 401 even with valid Bearer token | The token may have expired. Mint a new one in Settings → API Tokens. |
| GitHub Actions runner can't reach the URL | Cloudflare Tunnel has 99.99% uptime — likely your local Docker stopped. Verify on your host: `curl https://breachlens.fortisentinel.org/health` works. |
| GitHub OAuth login redirects to `localhost` | Update `FRONTEND_URL` + `GITHUB_CALLBACK_URL` per the section above + add the callback URL to your GitHub OAuth App. |

### Inspect tunnel state from inside the cloudflared container

```bash
# Detailed metrics + connection state
docker compose exec cloudflared wget -qO- http://localhost:8080/metrics

# Liveness check
docker compose exec cloudflared wget -qO- http://localhost:8080/ready
```

---

## Tear-down

To stop exposing publicly without losing the tunnel config:

```bash
docker compose stop cloudflared
```

To remove the tunnel completely:

1. Stop the container: `docker compose --profile tunnel down`
2. In the Cloudflare Zero Trust dashboard → Networks → Tunnels →
   click the tunnel → Delete.
3. The DNS record auto-deletes when the tunnel is deleted.

---

## Security notes

- The tunnel exposes whatever the `web` service is exposing. BreachLens
  requires authentication on every `/api/*` route except `/api/health`,
  so the tunnel doesn't bypass auth — Bearer tokens + sessions enforce
  the same controls as `localhost`.
- The connector token is a **bearer credential** — anyone holding it
  can register their own cloudflared with your tunnel. Treat like a
  password: never commit, rotate if leaked. Cloudflare lets you delete
  + recreate the tunnel to invalidate.
- API tokens minted before the tunnel was set up still work over the
  tunnel — they're not bound to the original hostname.
- For production, lock down the public hostname further:
  - Cloudflare Access policies (require Google / GitHub SSO before
    even reaching the BreachLens UI)
  - WAF rules (rate limiting, geo blocking, bot filtering — all free
    on the Cloudflare dashboard)
  - Mutual TLS for `/api/*` if you want to require client certs

---

## What this enables for the CI integration arc

| Phase | Status before | After |
|---|---|---|
| A1 — SARIF export | ✅ shipped, localhost-only | ✅ reachable from any GitHub runner |
| A2 — Composite Action | ✅ shipped | ✅ runs end-to-end against your deployment |
| A4 — API tokens | ✅ shipped | ✅ Bearer auth flows over the public URL |
| A5 — Marketplace bundle | ✅ shipped | ✅ ready to publish + dogfood from this monorepo |
| A6 — **public reachability (this runbook)** | — | ✅ **shipped** |
| A7 (next) — first real PR test from a public consumer repo | — | unblocked once A6 is up |
