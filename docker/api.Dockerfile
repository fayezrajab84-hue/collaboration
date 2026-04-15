FROM node:20-alpine AS base
# OpenSSL is required by Prisma's query engine on Alpine (musl libc)
# curl is required by Docker healthcheck
RUN apk add --no-cache openssl curl
RUN npm install -g pnpm@9

# ── Builder stage ───────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

# .npmrc sets node-linker=hoisted — must be copied before pnpm install
COPY package.json pnpm-workspace.yaml tsconfig.base.json .npmrc ./
COPY pnpm-lock.yaml* ./
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

# Install without --frozen-lockfile so pnpm respects .npmrc linker setting
RUN pnpm install --no-frozen-lockfile

# Copy source
COPY packages/types/ ./packages/types/
COPY apps/api/ ./apps/api/

# Generate Prisma client — use hoisted binary from workspace root
RUN node_modules/.bin/prisma generate --schema=apps/api/prisma/schema.prisma

# Build shared types package first (creates dist/*.d.ts for project references)
RUN node_modules/.bin/tsc --project packages/types/tsconfig.json

# Compile API (references types via TypeScript project references)
RUN node_modules/.bin/tsc --project apps/api/tsconfig.json

# ── Migrate stage ────────────────────────────────────────────────────────
FROM builder AS migrate
WORKDIR /app
CMD ["node_modules/.bin/prisma", "migrate", "deploy", "--schema=apps/api/prisma/schema.prisma"]
# ^ For production once migration files are committed.
# During initial development with no migration files, override with:
#   command: node_modules/.bin/prisma db push --schema=apps/api/prisma/schema.prisma --skip-generate

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
RUN apk add --no-cache curl
RUN npm install -g pnpm@9

WORKDIR /app

RUN addgroup -g 1001 -S nodejs && adduser -S nodeuser -u 1001 -G nodejs

COPY package.json pnpm-workspace.yaml .npmrc ./
COPY pnpm-lock.yaml* ./
COPY packages/types/package.json ./packages/types/
COPY apps/api/package.json ./apps/api/

RUN pnpm install --no-frozen-lockfile --prod

# Copy compiled output and generated Prisma client
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY apps/api/prisma ./apps/api/prisma

USER nodeuser

EXPOSE 3000

CMD ["node", "apps/api/dist/server.js"]
