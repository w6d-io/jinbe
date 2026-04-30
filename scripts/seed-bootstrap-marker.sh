#!/usr/bin/env bash
#
# scripts/seed-bootstrap-marker.sh
#
# Pre-flight migration helper. Run BEFORE deploying the bootstrap-job
# version of the auth chart on a cluster that was already initialized
# under the legacy inline-bootstrap code path.
#
# Writes `rbac:bootstrap:state` into the cluster's Redis with
# `manualMigration: true` so the new bootstrap CLI sees the marker on
# its first run, treats the install as already-bootstrapped, and exits
# 0 without re-seeding anything.
#
# Usage:
#   ./scripts/seed-bootstrap-marker.sh <namespace> [--dry-run] [--force]
#
# Examples:
#   ./scripts/seed-bootstrap-marker.sh auth-w6d --dry-run
#   ./scripts/seed-bootstrap-marker.sh auth-w6d
#
# Flags:
#   --dry-run   Print the payload that would be written; do not write.
#   --force     Overwrite an existing marker. Without this flag, the
#               script aborts if the marker already exists.
#
# Requirements: kubectl, jq

set -euo pipefail

NS="${1:-}"
shift || true

if [[ -z "$NS" ]]; then
  echo "usage: $0 <namespace> [--dry-run] [--force]" >&2
  exit 64
fi

DRY_RUN=false
FORCE=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --force)   FORCE=true ;;
    *)         echo "unknown flag: $arg" >&2; exit 64 ;;
  esac
done

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "required command not found: $1" >&2; exit 127; }
}
require kubectl
require jq

SCHEMA_VERSION=1
RELEASE="${RELEASE:-auth-w6d}"
JINBE_DEPLOY="${JINBE_DEPLOY:-${RELEASE}-jinbe}"
REDIS_LABEL="${REDIS_LABEL:-app.kubernetes.io/component=master,app.kubernetes.io/name=redis}"

# Discover the running jinbe image SHA (image tag is treated as gitSha
# unless an explicit COMMIT_SHA is set on the deployment).
GIT_SHA="$(kubectl -n "$NS" get deploy "$JINBE_DEPLOY" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' \
  | awk -F: '{print $2}')"

if [[ -z "$GIT_SHA" || "$GIT_SHA" == "<no value>" ]]; then
  echo "could not determine jinbe image SHA from deployment $JINBE_DEPLOY in $NS" >&2
  exit 1
fi

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PAYLOAD="$(jq -nc \
  --arg sha          "$GIT_SHA" \
  --arg now          "$NOW" \
  --argjson schema   "$SCHEMA_VERSION" \
  '{
    version:               $sha,
    schemaVersion:         $schema,
    gitSha:                $sha,
    bootstrappedAt:        $now,
    lastUpgradeAt:         $now,
    previousSchemaVersion: null,
    manualMigration:       true,
    migrations: [
      { from: null, to: $schema, appliedAt: $now, gitSha: $sha, manual: true }
    ],
    builtInsHash: { rules: "manual-migration", routeMap: "manual-migration" }
  }')"

REDIS_POD="$(kubectl -n "$NS" get pod -l "$REDIS_LABEL" -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "$REDIS_POD" ]]; then
  echo "could not find Redis master pod in $NS (label: $REDIS_LABEL)" >&2
  exit 1
fi

echo "→ namespace:       $NS"
echo "→ jinbe deploy:    $JINBE_DEPLOY"
echo "→ redis pod:       $REDIS_POD"
echo "→ image gitSha:    $GIT_SHA"
echo "→ schemaVersion:   $SCHEMA_VERSION"
echo "→ payload:         $PAYLOAD"
echo

if [[ "$DRY_RUN" == "true" ]]; then
  echo "(dry run — no write)"
  exit 0
fi

# Check existing marker first.
EXISTING="$(kubectl -n "$NS" exec "$REDIS_POD" -c redis -- \
  redis-cli --no-raw get 'rbac:bootstrap:state' 2>/dev/null || true)"

if [[ -n "$EXISTING" && "$EXISTING" != "(nil)" && "$FORCE" != "true" ]]; then
  echo "marker already exists in Redis. Use --force to overwrite." >&2
  echo "current value: $EXISTING" >&2
  exit 1
fi

kubectl -n "$NS" exec "$REDIS_POD" -c redis -- \
  redis-cli set 'rbac:bootstrap:state' "$PAYLOAD" >/dev/null

echo "✓ marker written"
kubectl -n "$NS" exec "$REDIS_POD" -c redis -- \
  redis-cli get 'rbac:bootstrap:state'
