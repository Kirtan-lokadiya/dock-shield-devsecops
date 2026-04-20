# ─────────────────────────────────────
# Dock Shield Backend - with Trivy Scanner
# ─────────────────────────────────────
FROM node:20-alpine3.21

# Install Trivy scanner
RUN apk update && apk upgrade --no-cache && apk add --no-cache curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create app directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy source
COPY server.js .

# npm is not needed at runtime; removing it reduces attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/bin/npm \
    /usr/local/bin/npx

# Non-root user
RUN addgroup -S scanner && adduser -S scanner -G scanner && \
    mkdir -p /home/scanner/.cache/trivy && \
    chown -R scanner:scanner /home/scanner /app

ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

EXPOSE 4000

USER scanner

HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://localhost:4000/health || exit 1

CMD ["node", "server.js"]
