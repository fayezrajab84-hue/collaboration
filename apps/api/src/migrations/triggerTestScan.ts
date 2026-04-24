/**
 * One-off helper: trigger a PENTEST_FULL on the dvwa domain so we can
 * verify the Affected-URL + HTTP-Exchange evidence fix without going
 * through the web UI. Safe to re-run.
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

  const result = await triggerScan({
    orgId:         domain.orgId,
    targetType:    "DOMAIN",
    targetId:      domain.id,
    scanTypes:     ["PENTEST_FULL"],
    domain:        domain.domain,
    selectedSubdomains,
    pentestDepth:  domain.pentestDepth,
    domainAuthConfigId: domain.authConfig?.id,
  });
  console.log(JSON.stringify(result, null, 2));
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
