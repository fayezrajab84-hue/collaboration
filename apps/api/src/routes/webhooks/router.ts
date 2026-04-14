import { Router } from "express";
import { createHmac, timingSafeEqual } from "crypto";
import prisma from "../../db.js";
import { decrypt } from "../../services/encryptionService.js";
import { triggerScan } from "../../services/scanService.js";
import { logger } from "../../logger.js";

const router = Router();

// Raw body needed for HMAC verification
router.use("/github", (req, _res, next) => {
  let body = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    (req as unknown as { rawBody: string }).rawBody = body;
    try {
      req.body = JSON.parse(body);
    } catch {
      req.body = {};
    }
    next();
  });
});

router.post("/github", async (req, res) => {
  const event = req.headers["x-github-event"] as string;
  const signature = req.headers["x-hub-signature-256"] as string;
  const rawBody = (req as unknown as { rawBody: string }).rawBody;

  // Find matching repository by GitHub ID
  const repoId: number | undefined = req.body?.repository?.id;
  if (!repoId) { res.status(200).json({ ok: true }); return; }

  const repo = await prisma.repository.findUnique({
    where: { githubId: repoId },
    select: { id: true, orgId: true, defaultBranch: true, webhookSecret: true, url: true },
  });

  if (!repo) { res.status(200).json({ ok: true }); return; }

  // Validate HMAC signature
  if (repo.webhookSecret && signature) {
    try {
      const secret = decrypt(repo.webhookSecret);
      const expected = `sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`;
      const sigBuf = Buffer.from(signature);
      const expBuf = Buffer.from(expected);
      if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
        logger.warn("GitHub webhook signature mismatch", { repoId });
        res.status(401).json({ error: "Invalid signature" });
        return;
      }
    } catch {
      res.status(401).json({ error: "Signature verification failed" });
      return;
    }
  }

  // Handle push events — trigger scan on the pushed branch
  if (event === "push") {
    const ref: string = req.body?.ref ?? "";
    const branch = ref.replace("refs/heads/", "");

    // Only scan the default branch on push (configurable post-MVP)
    if (branch === repo.defaultBranch || branch === "main" || branch === "master") {
      try {
        await triggerScan({
          orgId: repo.orgId,
          targetType: "REPOSITORY",
          targetId: repo.id,
          scanTypes: ["SAST", "SCA", "SECRET", "IAC"],
          repoUrl: repo.url,
          branch,
        });
        logger.info("Webhook triggered scan", { repoId: repo.id, branch });
      } catch (err) {
        logger.error("Failed to trigger webhook scan", { error: (err as Error).message });
      }
    }
  }

  res.status(200).json({ ok: true });
});

export default router;
