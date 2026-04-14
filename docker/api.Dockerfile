FROM node:20-alpine AS base
RUN npm install -g pnpm@9

# ── Builder stage ───────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

# Copy workspace config + .npmrc (sets node-linker=hoisted BEFORE install)
COPY package.json pnpm-workspace.yaml tsconfig.base.json .npmrc ./
COPY pnpm-lock.yaml* ./

# Copy package manifests for layer caching
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

# Install — do NOT use --frozen-lockfile so pnpm respects .npmrc linker setting
RUN pnpm install --no-frozen-lockfile

# Copy source
COPY packages/types/ ./packages/types/
COPY apps/api/ ./apps/api/

# Generate Prisma client — run from workspace root using hoisted binary
# (avoids pnpm filter path resolution issues with the isolated linker)
RUN node_modules/.bin/prisma generate --schema=apps/api/prisma/schema.prisma

# Build TypeScript
RUN pnpm --filter @devsecops/api build

# ── Migrate stage (runs prisma migrate deploy) ───────────────────────────
FROM builder AS migrate
WORKDIR /app
CMD ["node_modules/.bin/prisma", "migrate", "deploy", "--schema=apps/api/prisma/schema.prisma"]

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
RUN npm install -g pnpm@9

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodeuser -u 1001 -G nodejs

# Copy workspace config
COPY package.json pnpm-workspace.yaml .npmrc ./
COPY pnpm-lock.yaml* ./
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

# Install production dependencies — no frozen-lockfile so .npmrc is respected
RUN pnpm install --no-frozen-lockfile --prod

# Copy built output and generated Prisma client
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY apps/api/prisma ./apps/api/prisma

USER nodeuser

EXPOSE 3000

CMD ["node", "apps/api/dist/server.js"]
