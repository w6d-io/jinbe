#!/bin/sh
# Local dev only. Stands in for the push jinbe no longer makes (055d80c removed its OPAL fan-out):
# on every change jinbe announces on Redis (rbac:realtime), and every OPAL_REFRESH_SECONDS as a
# safety net, hand opal-server jinbe's full datasource manifest so each client refetches every entry.
set -u

push() {
  manifest=$(mktemp)
  if wget -q -O "$manifest" --header "Authorization: Bearer $OPAL_CLIENT_TOKEN" "$JINBE_URL/api/admin/rbac/opal-datasource" \
    && wget -q -O /dev/null --header 'Content-Type: application/json' --post-file "$manifest" "$OPAL_SERVER_URL/data/config"; then
    echo "$(date -Iseconds) pushed: $1"
  else
    echo "$(date -Iseconds) push failed: $1" >&2
  fi
  rm -f "$manifest"
}

(while :; do sleep "${OPAL_REFRESH_SECONDS:-30}"; push periodic; done) &

while :; do
  redis-cli -h "$REDIS_HOST" --csv SUBSCRIBE rbac:realtime | while IFS= read -r line; do
    case "$line" in '"message"'*) push "$line" ;; esac
  done
  echo "$(date -Iseconds) redis subscription lost, retrying" >&2
  sleep 2
done
