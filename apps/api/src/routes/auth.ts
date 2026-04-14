import { Router } from "express";
import passport from "passport";
import { requireAuth } from "../middleware/requireAuth.js";
import prisma from "../db.js";
import { config } from "../config.js";

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
