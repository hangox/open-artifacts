#!/bin/sh
set -eu

# wrangler dev(本地模式,不连 Cloudflare 云端)只从 .dev.vars 里读取密钥,
# 不会自动透传容器的环境变量给 Worker 的 env 绑定,所以在启动前
# 把 Portainer/compose 注入的环境变量落到这个文件里。
: > /app/.dev.vars
[ -n "${CREATE_TOKEN:-}" ] && echo "CREATE_TOKEN=${CREATE_TOKEN}" >> /app/.dev.vars
[ -n "${ADMIN_TOKEN:-}" ] && echo "ADMIN_TOKEN=${ADMIN_TOKEN}" >> /app/.dev.vars
[ -n "${MAX_STORAGE_BYTES:-}" ] && echo "MAX_STORAGE_BYTES=${MAX_STORAGE_BYTES}" >> /app/.dev.vars

export WRANGLER_SEND_METRICS=false

exec "$@"
