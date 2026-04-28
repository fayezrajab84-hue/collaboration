/**
 * One-off helper: trigger a PENTEST_FULL on the juice-shop domain.
 * Mirrors triggerTestScan.ts but targets juice-shop instead of dvwa.
 * Used by Phase 27.6 b3 validation — Juice Shop has JWT-based auth so
 * jwt_attacker should produce real findings here that DVWA can't surface.
 */
import { triggerScan } from "../services/scanService.js";
import prisma from "../db.js";

async function run() {
  const domainId = "cmoh4mqg90001amrdvf6q9r7w"; // juice-shop:3000
  const domain = await prisma.domain.findUnique({
    where: { id: domainId },
    include: { authConfig: true },
  });
  if (!domain) throw new Error("juice-shop domain not found");

  // NOTE: ZAP recording contexts don't survive ZAP container restarts —
  // the DB row stays but ZAP loses the URL list. For Juice Shop validation
  // we deliberately SKIP the recording and let Phase 0.5's Playwright
  // crawler walk the app fresh (~30 URLs from a basic SPA crawl is enough
  // to exercise jwt_attacker / ssrf_attacker / commix on real endpoints).
  // To use a recording later: pass recordingContextName / Id explicitly
  // after re-recording the session in the UI.
  console.log("[trigger-juice-shop] using Playwright crawler (no recording context)");

  const result = await triggerScan({
    orgId:         domain.orgId,
    targetType:    "DOMAIN",
    targetId:      domain.id,
    scanTypes:     ["PENTEST_FULL"],
    domain:        domain.domain,
    selectedSubdomains: [],
    pentestDepth:  domain.pentestDepth,
    domainAuthConfigId: domain.authConfig?.id,
  });
  console.log(JSON.stringify(result, null, 2));
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
