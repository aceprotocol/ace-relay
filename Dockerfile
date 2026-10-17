# Requires a vendored SDK: run scripts/vendor-local-deps.sh first (CI does), because
# `file:../sdk-ts` does not resolve inside the build context. Goes away once
# @ace-protocol/sdk is published.
FROM node:24.18-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY vendor ./vendor
RUN npm ci
COPY . .
RUN npm run build

FROM node:24.18-alpine
RUN apk add --no-cache tini
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/vendor ./vendor
COPY --from=builder /app/package.json /app/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
# Plain HTTP only; TLS 1.3 with hybrid PQ groups (OpenSSL 3.5+) is the host nginx's job (README).
EXPOSE 3000 9090
USER node
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
