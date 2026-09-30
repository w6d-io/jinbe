#!/usr/bin/env bash
# Before/after benchmark of the shared read cache (src/cache).
#
#   scripts/bench-cache/run.sh [BASE_REF] [IDENTITIES]      (defaults: develop, 500)
#
# Starts its own Kratos (in-memory, :14433/:14434) and Redis (:16379) containers — never the dev
# stack's — seeds IDENTITIES identities, builds BASE_REF and this checkout, and runs three servers
# with DEV_BYPASS_AUTH against the same data: BASE_REF (:13001), this checkout (:13002), this checkout
# with CACHE_ENABLED=false (:13003). Kratos and OPA are reached through counting proxies (:14435,
# :18182) so every row reports upstream calls per request. OPA is the dev stack's (:8181, read-only
# queries with its local dummy token); without it the OPA columns read 0.
#
# Prints two tables (warm; human pace, rounds 6s apart) and the cold OPA guard-burst comparison.
# Leaves nothing running.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BASE_REF="${1:-develop}"
N_IDENT="${2:-500}"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f bench-kratos bench-redis >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/kratos"
cp "$HERE/kratos/kratos.yml" "$HERE/kratos/identity.schema.json" "$WORK/kratos/"
docker rm -f bench-kratos bench-redis >/dev/null 2>&1 || true
docker run -d --name bench-kratos -p 14433:4433 -p 14434:4434 -v "$WORK/kratos:/etc/config/kratos" \
  oryd/kratos:v1.3.0 serve -c /etc/config/kratos/kratos.yml --dev --watch-courier=false >/dev/null
docker run -d --name bench-redis -p 16379:6379 redis:7-alpine >/dev/null
until curl -sf localhost:14434/admin/health/ready >/dev/null; do sleep 1; done
node "$HERE/seed.mjs" "$N_IDENT"

node "$HERE/count-proxy.mjs" 14435 http://localhost:14434 & PIDS+=($!)
node "$HERE/count-proxy.mjs" 18182 http://localhost:8181 & PIDS+=($!)

mkdir -p "$WORK/base"
git -C "$REPO" archive "$BASE_REF" | tar -x -C "$WORK/base"
ln -s "$REPO/node_modules" "$WORK/base/node_modules"
(cd "$WORK/base" && npx tsc >/dev/null 2>&1 || true)
(cd "$REPO" && npx tsc)

export NODE_ENV=development DEV_BYPASS_AUTH=true DEV_USER_EMAIL=dev@localhost.dev ADMIN_EMAIL=dev@localhost.dev
export KRATOS_ADMIN_URL=http://localhost:14435 KRATOS_PUBLIC_URL=http://localhost:14433
export REDIS_URL=redis://localhost:16379
export ENCRYPTION_KEY=bench-encryption-key-32-chars-long! OPA_URL=http://localhost:18182 OPA_TOKEN=local-dev-opa-token-0123456789abcdef
export OPAL_CLIENT_TOKEN=bench-opal-client-token-0123456789abcdef0123
export RATE_LIMIT_MAX=1000000 LOG_LEVEL=warn ENABLE_SWAGGER=false METRICS_PORT=0 AUDIT_SINK=legacy
export AUTH_DOMAIN=auth.localhost.dev APP_DOMAIN=app.localhost.dev API_DOMAIN=api.localhost.dev
export LOGIN_UI_URL=http://localhost:3001 ADMIN_UI_URL=http://localhost:5173
(cd "$WORK/base" && ADMIN_PASSWORD='Bench-Only-Pass-4f9!x' node dist/cli/bootstrap.js >/dev/null 2>&1)

(cd "$WORK/base" && PORT=13001 exec node dist/server.js >"$WORK/base.log" 2>&1) & PIDS+=($!)
(cd "$REPO" && PORT=13002 exec node dist/server.js >"$WORK/cache.log" 2>&1) & PIDS+=($!)
(cd "$REPO" && PORT=13003 CACHE_ENABLED=false exec node dist/server.js >"$WORK/off.log" 2>&1) & PIDS+=($!)
for p in 13001 13002 13003; do until curl -sf "localhost:$p/api/health" >/dev/null; do sleep 1; done; done

N=60 node "$HERE/bench.mjs"
echo
MODE=spaced ROUNDS=8 node "$HERE/bench.mjs"
echo
echo "Cold burst of 49 concurrent guard checks (OPA):"
echo -n "  $BASE_REF: "; CACHE_STORE=memory node "$HERE/opa-burst.mjs" "$WORK/base/dist"
echo -n "  this checkout: "; CACHE_STORE=memory node "$HERE/opa-burst.mjs" "$REPO/dist"
