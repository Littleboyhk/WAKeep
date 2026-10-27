# =============================================================================
# Multi-stage Dockerfile for WAKeep
# Optimized for free cloud hosting (Render, Koyeb, Railway) under 70MB RAM
# =============================================================================

# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package*.json tsconfig.json ./
RUN npm ci

# Copy source code and build TypeScript
COPY src/ ./src
RUN npm run build

# Stage 2: Production Runtime
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies only
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy compiled files and static assets
COPY --from=builder /app/dist ./dist
COPY public/ ./public

# Expose standard application port
EXPOSE 3000

# Run lightweight keep-alive healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

# Start server
CMD ["node", "dist/server.js"]
