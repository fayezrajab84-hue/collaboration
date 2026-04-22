/**
 * One-shot: trigger a DAST scan on DVWA to validate the new Dalfox install.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/triggerDvwaDast.ts"
 */
import prisma from "../db.js";
import { triggerScan } from "../services/scanService.js";

async function run() {
  const domain = await prisma.domain.findFirst({
    where: { domain: "dvwa" },
    include: { authConfig: true },
  });
  if (!domain) throw new Error("DVWA domain not found");

  console.log(
    `[trigger-dvwa] domain=${domain.id} org=${domain.orgId} authConfig=${domain.authConfig?.id ?? "none"}`,
  );

  const result = await triggerScan({
    orgId: domain.orgId,
    targetType: "DOMAIN",
    targetId: domain.id,
    scanTypes: ["DAST"],
    domain: domain.domain,
    domainAuthConfigId: domain.authConfig?.id,
  });

  console.log(`[trigger-dvwa] scanJobId=${result.scanJobId} status=${result.status}`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
