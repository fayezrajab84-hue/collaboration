FROM node:20-alpine AS base
RUN npm install -g pnpm@9

# ── Builder stage ───────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL

COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY pnpm-lock.yaml* ./
COPY packages/types/package.json ./packages/types/
COPY apps/web/package.json ./apps/web/

RUN if [ -f pnpm-lock.yaml ]; then pnpm install --frozen-lockfile; else pnpm install; fi

COPY packages/types/ ./packages/types/
COPY apps/web/ ./apps/web/

RUN pnpm --filter @devsecops/web build

# ── Runtime stage (nginx) ───────────────────────────────────────────────
FROM nginx:1.25-alpine AS runtime

COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
