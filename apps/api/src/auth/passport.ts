import passport from "passport";
import { Strategy as GitHubStrategy } from "passport-github2";
import type { Profile } from "passport-github2";
import prisma from "../db.js";
import { config } from "../config.js";
import { encrypt } from "../services/encryptionService.js";
import { logger } from "../logger.js";

passport.use(
  new GitHubStrategy(
    {
      clientID: config.GITHUB_CLIENT_ID,
      clientSecret: config.GITHUB_CLIENT_SECRET,
      callbackURL: config.GITHUB_CALLBACK_URL,
      scope: ["user:email", "repo"],
    },
    async (
      accessToken: string,
      _refreshToken: string,
      profile: Profile,
      done: (err: Error | null, user?: Express.User) => void
    ) => {
      try {
        const encryptedToken = encrypt(accessToken);
        const email =
          profile.emails?.[0]?.value ?? null;
        const avatarUrl =
          profile.photos?.[0]?.value ?? null;

        // Find-or-create user
        let user = await prisma.user.findUnique({
          where: { githubId: profile.id },
        });

        if (!user) {
          // Create user
          user = await prisma.user.create({
            data: {
              githubId: profile.id,
              username: profile.username ?? profile.displayName ?? profile.id,
              email,
              avatarUrl,
              accessToken: encryptedToken,
            },
          });

          // Auto-create personal organization
          const slug = (profile.username ?? profile.id).toLowerCase().replace(/[^a-z0-9-]/g, "-");
          const org = await prisma.organization.create({
            data: {
              name: profile.username ?? profile.displayName ?? profile.id,
              slug,
              type: "PERSONAL",
            },
          });

          await prisma.organizationMember.create({
            data: {
              userId: user.id,
              orgId: org.id,
              role: "OWNER",
            },
          });

          logger.info("New user registered", { userId: user.id, username: user.username });
        } else {
          // Update token on each login
          user = await prisma.user.update({
            where: { id: user.id },
            data: { accessToken: encryptedToken, email, avatarUrl },
          });
        }

        // ── Accept any pending invitations matching this GitHub username ───
        // Runs on EVERY login (not just first), so an admin can invite an
        // existing user to a different org and the invitation lands on
        // their next sign-in. Username match is case-insensitive — invites
        // are stored lowercase.
        const usernameLower = (profile.username ?? "").toLowerCase();
        if (usernameLower) {
          const pending = await prisma.invitation.findMany({
            where: {
              githubUsername: usernameLower,
              acceptedAt:     null,
              expiresAt:      { gt: new Date() },
            },
          });

          for (const inv of pending) {
            // Skip if user is already a member of that org (defensive — the
            // invite-create path checks this, but races are possible).
            const alreadyMember = await prisma.organizationMember.findUnique({
              where: { userId_orgId: { userId: user.id, orgId: inv.orgId } },
            });
            if (alreadyMember) {
              await prisma.invitation.update({
                where: { id: inv.id },
                data:  { acceptedAt: new Date(), acceptedUserId: user.id },
              });
              continue;
            }

            await prisma.$transaction([
              prisma.organizationMember.create({
                data: { userId: user.id, orgId: inv.orgId, role: inv.role },
              }),
              prisma.invitation.update({
                where: { id: inv.id },
                data:  { acceptedAt: new Date(), acceptedUserId: user.id },
              }),
            ]);

            logger.info("Invitation accepted", {
              userId: user.id, orgId: inv.orgId, invitationId: inv.id, role: inv.role,
            });
          }
        }

        done(null, user);
      } catch (err) {
        logger.error("GitHub OAuth error", { error: (err as Error).message });
        done(err as Error);
      }
    }
  )
);

passport.serializeUser((user: Express.User, done) => {
  const u = user as { id: string };
  done(null, u.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user ?? false);
  } catch (err) {
    done(err);
  }
});
