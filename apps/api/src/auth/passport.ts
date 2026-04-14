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
