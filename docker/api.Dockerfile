FROM node:20-alpine AS base
RUN npm install -g pnpm@9

# ── Builder stage ───────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

# Copy workspace config
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./

# Copy package manifests for dependency caching
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

# Install all dependencies
RUN pnpm install --frozen-lockfile

# Copy source
COPY packages/types/ ./packages/types/
COPY apps/api/ ./apps/api/

# Generate Prisma client
RUN pnpm --filter @devsecops/api db:generate

# Build TypeScript
RUN pnpm --filter @devsecops/api build

# ── Runtime stage ───────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
RUN npm install -g pnpm@9

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodeuser -u 1001 -G nodejs

# Copy workspace config and package manifests
COPY package.json pnpm-workspace.yaml ./
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

# Install production dependencies only
RUN pnpm install --frozen-lockfile --prod

# Copy built output and Prisma artifacts
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/node_modules/.prisma ./apps/api/node_modules/.prisma
COPY apps/api/prisma ./apps/api/prisma

USER nodeuser

EXPOSE 3000

CMD ["node", "apps/api/dist/server.js"]
