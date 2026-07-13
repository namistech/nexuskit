# NexusKit — production image
# Single image, two Coolify applications point at it with different start
# commands: the API (`node server.js`, default CMD below) and the worker
# (`node worker.js`, set as a start command override on the second app).
# No multi-stage build needed — there's no compile step for plain JS.

FROM node:20-alpine AS base
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY . .

RUN addgroup -S nexuskit && adduser -S nexuskit -G nexuskit
USER nexuskit

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/healthz', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
