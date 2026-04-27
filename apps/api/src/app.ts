import express from "express";
import helmet from "helmet";
import cors from "cors";
import session from "express-session";
import RedisStore from "connect-redis";
import passport from "passport";
import rateLimit from "express-rate-limit";

import { config } from "./config.js";
import { redis } from "./redis.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestId } from "./middleware/requestId.js";
import healthRouter from "./routes/health.js";
import authRouter from "./routes/auth.js";
import reposRouter from "./routes/repos/router.js";
import containersRouter from "./routes/containers/router.js";
import domainsRouter from "./routes/domains/router.js";
import findingsRouter from "./routes/findings/router.js";
import ticketsRouter from "./routes/tickets/router.js";
import scansRouter from "./routes/scans/router.js";
import integrationsRouter from "./routes/integrations/router.js";
import webhooksRouter from "./routes/webhooks/router.js";
import chatRouter from "./routes/chat/router.js";
import reportsRouter from "./routes/reports/router.js";
import suppressionsRouter from "./routes/suppressions/router.js";
import aiProvidersRouter from "./routes/aiProviders/router.js";
import adminRouter from "./routes/admin/router.js";
import policiesRouter from "./routes/policies/router.js";
import auditRouter from "./routes/audit/router.js";
import membersRouter from "./routes/members/router.js";
import ssoRouter from "./routes/sso/router.js";
import sbomRouter from "./routes/sbom/router.js";
import complianceRouter from "./routes/compliance/router.js";

import "./auth/passport.js"; // side-effect: registers passport strategies

const app = express();

// ── Security middleware ───────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(helmet());
app.use(
  cors({
    origin: config.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ── Rate limiting ─────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: { error: "Too many auth requests, please try again later" },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 300,
  message: { error: "Too many requests, please slow down" },
});

// ── Body parsing ──────────────────────────────────────────────────────────
// 5mb cap because large vendor OpenAPI specs (AWS, Stripe) routinely exceed
// 1mb and we accept them via /api/domains/:id/apispec/import.
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
// Accept raw YAML / plain text bodies for OpenAPI spec import
// (POST /api/domains/:id/apispec/import). Limit bumped to 5mb because
// large vendor specs (e.g. AWS, Stripe) routinely exceed 1mb.
app.use(
  express.text({
    type: ["application/yaml", "application/x-yaml", "text/yaml", "text/plain"],
    limit: "5mb",
  }),
);

// ── Session (Redis-backed via ioredis) ────────────────────────────────────
// connect-redis v7 accepts ioredis clients; cast to satisfy its type signature
const store = new RedisStore({ client: redis as never });

app.use(
  session({
    store,
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// ── Passport ──────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ── Request ID ────────────────────────────────────────────────────────────
app.use(requestId);

// ── Routes ────────────────────────────────────────────────────────────────
app.use(healthRouter);
// Strict auth limiter only on the IdP-handshake routes — those make
// outbound calls to GitHub / Microsoft / Okta and are the actual abuse
// vector. /auth/me, /auth/logout, /auth/org/switch run on every page
// load and session change, so they get the looser apiLimiter (300/min)
// to avoid a "Too many auth requests" wall after 10 navigations.
app.use("/auth/github",       authLimiter);
app.use("/auth/sso/initiate", authLimiter);
app.use("/auth/sso/callback", authLimiter);
app.use("/auth", apiLimiter, authRouter);
app.use("/api/repos", apiLimiter, reposRouter);
app.use("/api/containers", apiLimiter, containersRouter);
app.use("/api/domains", apiLimiter, domainsRouter);
app.use("/api/findings", apiLimiter, findingsRouter);
app.use("/api/tickets", apiLimiter, ticketsRouter);
app.use("/api/scans", apiLimiter, scansRouter);
app.use("/api/integrations", apiLimiter, integrationsRouter);
app.use("/api/webhooks", webhooksRouter);
app.use("/api/chat", apiLimiter, chatRouter);
app.use("/api/reports", apiLimiter, reportsRouter);
app.use("/api/suppressions", apiLimiter, suppressionsRouter);
app.use("/api/ai-providers", apiLimiter, aiProvidersRouter);
app.use("/api/admin", apiLimiter, adminRouter);
app.use("/api/policies", apiLimiter, policiesRouter);
app.use("/api/audit", apiLimiter, auditRouter);
app.use("/api/members", apiLimiter, membersRouter);
app.use("/api/sso", apiLimiter, ssoRouter);
app.use("/api/sbom", apiLimiter, sbomRouter);
app.use("/api/compliance", apiLimiter, complianceRouter);

// ── Error handler (must be last) ──────────────────────────────────────────
app.use(errorHandler);

export default app;
