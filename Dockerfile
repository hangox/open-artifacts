FROM node:22-slim

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8787

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npx", "wrangler", "dev", "--ip", "0.0.0.0", "--port", "8787", "--persist-to", "/app/.wrangler/state"]
