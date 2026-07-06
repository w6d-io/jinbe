#!/usr/bin/env bash
set -euo pipefail

KRATOS_ADMIN="http://auth-kratos-admin.auth/admin/identities"
PAGE_SIZE=500
OUTPUT="users-dump.json"

echo "Fetching all identities from Kratos..."

ALL="[]"
PAGE_TOKEN=""
PAGE=0

while true; do
  PAGE=$((PAGE + 1))
  URL="${KRATOS_ADMIN}?page_size=${PAGE_SIZE}"
  [ -n "$PAGE_TOKEN" ] && URL="${URL}&page_token=${PAGE_TOKEN}"

  RESP=$(curl -sS -D /dev/stderr "$URL" 2>/tmp/kratos-headers)
  HEADERS=$(cat /tmp/kratos-headers)

  COUNT=$(echo "$RESP" | jq 'length')
  echo "  Page ${PAGE}: ${COUNT} identities"

  # Extract id, traits, metadata_admin
  SLIM=$(echo "$RESP" | jq '[.[] | {id, traits, metadata_admin}]')
  ALL=$(echo "$ALL" "$SLIM" | jq -s '.[0] + .[1]')

  # Parse next page_token from Link header
  NEXT=$(echo "$HEADERS" | grep -i '^link:' | grep -o 'page_token=[^&>]*' | tail -1 | cut -d= -f2 || true)

  if [ -z "$NEXT" ] || [ "$COUNT" -lt "$PAGE_SIZE" ]; then
    break
  fi
  PAGE_TOKEN="$NEXT"
done

TOTAL=$(echo "$ALL" | jq 'length')
echo "Total: ${TOTAL} identities"

# Find users with group "user" (singular) that need fixing to "users" (plural)
echo ""
echo "Users with group 'user' (needs fix to 'users'):"
echo "$ALL" | jq '[.[] | select(.metadata_admin.groups != null) | select(.metadata_admin.groups | index("user")) | {id, email: .traits.email, groups: .metadata_admin.groups}]'

FIXABLE=$(echo "$ALL" | jq '[.[] | select(.metadata_admin.groups != null) | select(.metadata_admin.groups | index("user"))] | length')
echo ""
echo "${FIXABLE} users need 'user' → 'users' fix"

echo "$ALL" | jq '.' > "$OUTPUT"
echo "Full dump saved to ${OUTPUT}"
