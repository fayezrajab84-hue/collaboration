import { Router } from "express";
import passport from "passport";
import { randomBytes } from "node:crypto";
import { requireAuth } from "../middleware/requireAuth.js";
import prisma from "../db.js";
import { config } from "../config.js";
import { encrypt, decrypt } from "../services/encryptionService.js";
import * as audit from "../services/auditService.js";
import { logger } from "../logger.js";
import {
  buildAuthorizationUrl,
  exchangeCodeForUserProfile,
  resolveRole,
  OidcError,
  type OidcOrgConfig,
} from "../auth/oidcService.js";
import type { Role } from "@prisma/client";

// Augment express-session to carry the SSO CSRF state across the redirect.
// Same session as the eventual logged-in session — the callback `req.login`
// promotes it without a session reset.
declare module "express-session" {
  interface SessionData {
    ssoState?: {
      state:    string;
      nonce:    string;
      orgId:    string;
      configId: string;
    };
  }
}

const router = Router();

// Initiate GitHub OAuth flow
router.get("/github", passport.authenticate("github", { scope: ["user:email", "repo"] }));

// OAuth callback
router.get(
  "/github/callback",
  passport.authenticate("github", {
    failureRedirect: `${config.FRONTEND_URL}/login?error=oauth_failed`,
  }),
  (_req, res) => {
    res.redirect(`${config.FRONTEND_URL}/dashboard`);
  }
);

// ── SSO (OIDC) — Phase 22 PR 3 Slice B ───────────────────────────────────────
// Companion to the SSO config tab in Settings (Slice A).
// Flow:
//   GET /auth/sso/initiate?email=alice@acme.com
//     → resolve org by email domain → build IdP authorization URL → 302
//   IdP authenticates user → redirects back to our callback with `?code=…&state=…`
//   GET /auth/sso/callback?code=…&state=…
//     → verify state → exchange code → fetch userinfo
//     → JIT-provision User + OrganizationMember (or update existing role)
//     → req.login(user) → redirect to /dashboard
//
// CSRF protection: state + nonce stored in express-session at initiate time,
// validated at callback time. State mismatch → no token exchange.

const SSO_CALLBACK_PATH = "/auth/sso/callback";

function ssoErrorRedirect(reason: string): string {
  return `${config.FRONTEND_URL}/login?error=${encodeURIComponent(reason)}`;
}

async function buildOrgConfig(ssoRow: {
  id: string; orgId: string; issuerUrl: string; clientId: string;
  encryptedSecrets: unknown; defaultRole: Role; groupRoleMapping: unknown;
}): Promise<OidcOrgConfig> {
  const secretsJson = ssoRow.encryptedSecrets as { clientSecret?: string } | null;
  if (!secretsJson?.clientSecret) {
    throw new Error(`SsoConfig ${ssoRow.id} has no encrypted clientSecret`);
  }
  return {
    orgId:            ssoRow.orgId,
    issuerUrl:        ssoRow.issuerUrl,
    clientId:         ssoRow.clientId,
    clientSecret:     decrypt(secretsJson.clientSecret),
    defaultRole:      ssoRow.defaultRole,
    groupRoleMapping: (ssoRow.groupRoleMapping as Record<string, Role>) ?? {},
  };
}

router.get("/sso/initiate", async (req, res) => {
  try {
    const email = String(req.query["email"] ?? "").trim().toLowerCase();
    if (!email.includes("@")) {
      res.redirect(ssoErrorRedirect("invalid_email"));
      return;
    }
    const domain = email.split("@")[1] ?? "";

    // Resolve org by email domain — `has` operator on the String[] column.
    const sso = await prisma.ssoConfig.findFirst({
      where: { allowedEmailDomains: { has: domain }, isActive: true },
    });
    if (!sso) {
      res.redirect(ssoErrorRedirect("no_sso_for_domain"));
      return;
    }

    const orgConfig = await buildOrgConfig(sso);
    const state     = randomBytes(16).toString("hex");
    const nonce     = randomBytes(16).toString("hex");

    req.session.ssoState = { state, nonce, orgId: sso.orgId, configId: sso.id };

    const redirectUri = `${config.API_PUBLIC_URL}${SSO_CALLBACK_PATH}`;
    const authUrl     = await buildAuthorizationUrl(orgConfig, state, nonce, redirectUri);

    logger.info("[sso] initiating login", { email, orgId: sso.orgId, issuer: sso.issuerUrl });
    res.redirect(authUrl);
  } catch (err) {
    const kind = err instanceof OidcError ? err.kind : "INITIATE_FAILED";
    logger.error("[sso] initiate failed", { error: (err as Error).message, kind });
    res.redirect(ssoErrorRedirect(kind.toLowerCase()));
  }
});

router.get("/sso/callback", async (req, res, next) => {
  try {
    const code  = req.query["code"];
    const state = req.query["state"];
    if (typeof code !== "string" || typeof state !== "string") {
      res.redirect(ssoErrorRedirect("invalid_callback"));
      return;
    }

    const stored = req.session.ssoState;
    if (!stored || stored.state !== state) {
      res.redirect(ssoErrorRedirect("state_mismatch"));
      return;
    }

    const sso = await prisma.ssoConfig.findUnique({ where: { id: stored.configId } });
    if (!sso || !sso.isActive) {
      res.redirect(ssoErrorRedirect("sso_disabled"));
      return;
    }

    const orgConfig   = await buildOrgConfig(sso);
    const redirectUri = `${config.API_PUBLIC_URL}${SSO_CALLBACK_PATH}`;
    const profile     = await exchangeCodeForUserProfile(orgConfig, code, redirectUri);

    if (!profile.email) {
      res.redirect(ssoErrorRedirect("no_email_in_profile"));
      return;
    }

    // ── JIT user provisioning ────────────────────────────────────────────────
    // Find by stable IdP `sub` first (handles email-change case), then by
    // email (so a GitHub-OAuth user gets linked rather than duplicated).
    const stableId = `oidc:${stored.orgId}:${profile.sub}`;
    let user = await prisma.user.findUnique({ where: { githubId: stableId } });

    if (!user) {
      const byEmail = await prisma.user.findFirst({ where: { email: profile.email } });
      if (byEmail) {
        user = byEmail;
        // Don't overwrite githubId — preserve the GitHub link if it exists.
      } else {
        user = await prisma.user.create({
          data: {
            githubId:    stableId,
            username:    profile.name ?? profile.email.split("@")[0] ?? profile.sub,
            email:       profile.email,
            avatarUrl:   profile.picture ?? null,
            // No real access token for SSO users — placeholder ciphertext so
            // the NOT NULL constraint is satisfied. SSO users can't clone
            // private repos via this account; that's a deliberate limitation
            // until we add per-user GitHub-token linking on top of SSO.
            accessToken: encrypt("oidc-no-token"),
          },
        });
        logger.info("[sso] new user JIT-provisioned", { userId: user.id, email: profile.email });
      }
    }

    // ── Org membership + role assignment ─────────────────────────────────────
    // Re-resolve role on every login so group-mapping changes propagate.
    const role = resolveRole(orgConfig, profile.groups);
    await prisma.organizationMember.upsert({
      where:  { userId_orgId: { userId: user.id, orgId: stored.orgId } },
      create: { userId: user.id, orgId: stored.orgId, role },
      update: { role },
    });

    await audit.log({
      orgId:        stored.orgId,
      userId:       user.id,
      action:       "sso.login",
      resourceType: "User",
      resourceId:   user.id,
      metadata: {
        email:  profile.email,
        sub:    profile.sub,
        role,
        groups: profile.groups ?? [],
      },
    });

    // Establish session via passport's req.login — same mechanism the GitHub
    // OAuth callback uses. Wipes the ssoState afterward so a stale state can't
    // be replayed.
    req.login(user, (err) => {
      if (err) { next(err); return; }
      delete req.session.ssoState;
      res.redirect(`${config.FRONTEND_URL}/dashboard`);
    });
  } catch (err) {
    const kind = err instanceof OidcError ? err.kind : "CALLBACK_FAILED";
    logger.error("[sso] callback failed", { error: (err as Error).message, kind });
    res.redirect(ssoErrorRedirect(kind.toLowerCase()));
  }
});

// Logout
router.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      next(err);
      return;
    }
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true });
    });
  });
});

// Current user
router.get("/me", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgs = await prisma.organizationMember.findMany({
      where: { userId: user.id },
      include: { org: true },
    });

    const fullUser = await prisma.user.findUnique({ where: { id: user.id } });
    if (!fullUser) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    res.json({
      id: fullUser.id,
      username: fullUser.username,
      email: fullUser.email,
      avatarUrl: fullUser.avatarUrl,
      orgs: orgs.map((m) => ({
        id: m.org.id,
        name: m.org.name,
        slug: m.org.slug,
        role: m.role,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;
