# ─────────────────────────────────────
# Dock Shield Backend - with Trivy Scanner
# ─────────────────────────────────────
FROM node:18-alpine

# Install Trivy scanner
RUN apk add --no-cache curl docker-cli && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create app directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY server.js .

# Non-root user
RUN addgroup -S scanner && adduser -S scanner -G scanner
# Note: scanner needs docker socket access, handled via group in docker-compose

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://localhost:4000/health || exit 1

CMD ["node", "server.js"]
