/**
 * Instance-wide SBOM signing key endpoint.
 *
 * The public key is needed to verify SBOM signatures emitted as
 * `X-Sbom-Signature` headers from the per-repo download endpoints.
 *
 * Auth-gated for two reasons:
 *   1. Surfaces the key creation timestamp + key ID — useful for an
 *      operator audit trail but not something we want unauthenticated
 *      visitors enumerating
 *   2. SOC 2 / ISO 27001 evidence trail — every key fetch is captured
 *      in the request log alongside the user
 *
 * Public-key material itself is, well, public — there's no secrecy harm
 * in a logged-in member fetching it. ADMIN+ NOT required.
 */
import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import { getPublicKeyView } from "../../services/sbomSigningService.js";

const router = Router();

router.get("/public-key", requireAuth, async (_req, res, next) => {
  try {
    const key = await getPublicKeyView();
    if (!key) {
      // No key has been generated yet — this is the cold-start case before
      // any SBOM has been signed. Surface a 404 so curl-driven scripts can
      // wait/retry rather than silently consume an empty key.
      res.status(404).json({
        error:   "no_signing_key",
        message: "No SBOM signing key generated yet. Trigger an SCA scan to provision one.",
      });
      return;
    }
    res.json(key);
  } catch (err) { next(err); }
});

export default router;
