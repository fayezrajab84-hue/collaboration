/**
 * One-time migration: update merged SCA/CONTAINER findings to use
 * human-friendly titles (e.g. "Apache Tomcat" instead of
 * "org.apache.tomcat.embed:tomcat-embed-core") and remove the
 * redundant CVE list from the description (now shown in the Subissues panel).
 *
 * Safe to re-run — idempotent.
 *
 * Run: docker exec admiring-hertz-api-1 node --import tsx/esm \
 *        /app/apps/api/src/migrations/cleanScaTitles.ts
 */

import prisma from "../db.js";
import { logger } from "../logger.js";

interface StructuredCve {
  cveId:      string | null;
  severity:   string;
  fixVersion: string | null;
  title:      string | null;
}

function humanName(pkg: string, firstCveTitle?: string | null): string {
  if (firstCveTitle) {
    const colonIdx = firstCveTitle.indexOf(":");
    if (colonIdx > 0 && colonIdx < 50) return firstCveTitle.slice(0, colonIdx).trim();
  }
  if (pkg.includes(":")) return pkg.split(":").pop()!;
  return pkg;
}

async function run() {
  logger.info("[cleanScaTitles] starting SCA title/description cleanup");

  const findings = await prisma.finding.findMany({
    where: { scanType: { in: ["SCA", "CONTAINER"] } },
  });

  logger.info(`[cleanScaTitles] ${findings.length} SCA/CONTAINER findings to inspect`);

  let updated = 0;
  let skipped = 0;

  for (const f of findings) {
    const raw  = f.rawOutput as Record<string, unknown> | null;
    const pkg  = f.packageName ?? "";
    const ver  = f.packageVersion ?? "";

    // Single-CVE findings — just clean up title/description if they use raw pkg name
    if (!raw?.["merged"]) {
      const cveTitle = (raw?.["Title"] as string | undefined) ?? null;
      const name = humanName(pkg, cveTitle);

      // Only update if the raw Maven coords are exposed in the title
      if (pkg.includes(":") && f.title.includes(pkg)) {
        const newTitle = f.title.replace(pkg, name);
        // Remove CVE list from description if present
        const newDesc = f.description.replace(/\n\nCVEs:\n[\s\S]*/m, "");
        await prisma.finding.update({
          where: { id: f.id },
          data: { title: newTitle, description: newDesc },
        });
        updated++;
      } else {
        skipped++;
      }
      continue;
    }

    // Merged finding
    const cves = (raw["cves"] as StructuredCve[] | undefined) ?? [];
    const fixVer = raw["fixVersion"] as string | null | undefined;
    const count  = (raw["count"] as number | undefined) ?? cves.length;
    const firstTitle = cves[0]?.title ?? null;
    const name = humanName(pkg, firstTitle);

    // Derive top severity from existing title (last word in parens)
    const sevMatch = f.title.match(/\((\w+)\)$/);
    const topSev   = sevMatch?.[1] ?? "HIGH";

    const newTitle = `${name} ${ver} — ${count} vulnerabilities (${topSev})`;
    const newDesc  =
      `${count} vulnerabilities found in ${name} ${ver}.` +
      (fixVer ? ` Upgrade to ${fixVer} to fix all.` : "");

    if (f.title === newTitle && f.description === newDesc) {
      skipped++;
      continue;
    }

    await prisma.finding.update({
      where: { id: f.id },
      data: { title: newTitle, description: newDesc },
    });
    updated++;
  }

  logger.info(`[cleanScaTitles] done — ${updated} findings updated, ${skipped} skipped`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
