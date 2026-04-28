/**
 * One-off helper: trigger a PENTEST_FULL on the dvwa domain.
 *
 * This variant pulls the most recent recording session for the domain and
 * passes its ZAP context to the new scan. That makes Phase 0.5 use the
 * recorded URL set (parameterised, auth'd) instead of unauthenticated
 * Playwright crawl — which is what xsstrike/dalfox need to reach the
 * vulnerable endpoints in dvwa. Safe to re-run.
 */
import { triggerScan } from "../services/scanService.js";
import prisma from "../db.js";

async function run() {
  const domainId = "cmo5j84520001q8lmvjvkm3uw";
  const domain = await prisma.domain.findUnique({
    where: { id: domainId },
    include: { authConfig: true },
  });
  if (!domain) throw new Error("domain not found");

  const selected = await prisma.subdomainDiscovery.findMany({
    where: { domainId, includedInScan: true },
    select: { subdomain: true },
  });
  const rootLower = domain.domain.toLowerCase().trim();
  const selectedSubdomains = selected
    .map((s) => s.subdomain)
    .filter((s) => s.toLowerCase().trim() !== rootLower);

  // Pull the most recent recording so we feed the recorded URL set into
  // Phase 0.5. STOPPED status is fine — we only need the ZAP context info,
  // and the orchestrator will skip Playwright if recording_context_name is
  // present.
  const recording = await prisma.recordingSession.findFirst({
    where: { domainId },
    orderBy: { startedAt: "desc" },
    select: {
      id: true,
      zapContextId: true,
      zapContextName: true,
      urlCount: true,
      status: true,
    },
  });
  console.log("[trigger] using recording:", recording);

  const result = await triggerScan({
    orgId:         domain.orgId,
    targetType:    "DOMAIN",
    targetId:      domain.id,
    scanTypes:     ["PENTEST_FULL"],
    domain:        domain.domain,
    selectedSubdomains,
    pentestDepth:  domain.pentestDepth,
    domainAuthConfigId: domain.authConfig?.id,
    recordingContextId:   recording?.zapContextId ?? undefined,
    recordingContextName: recording?.zapContextName ?? undefined,
    recordingTargetUrl:   `http://${domain.domain}`,
    recordingSessionId:   recording?.id ?? undefined,
  });
  console.log(JSON.stringify(result, null, 2));
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
