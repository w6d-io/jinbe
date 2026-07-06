#!/usr/bin/env bash
set -euo pipefail

KRATOS_ADMIN="http://auth-kratos-admin.auth/admin/identities"
INPUT="${1:-users-dump.json}"
DRY_RUN="${DRY_RUN:-1}"

if [ ! -f "$INPUT" ]; then
  echo "Usage: $0 <users-dump.json>"
  echo "  Set DRY_RUN=0 to actually apply changes"
  exit 1
fi

# Build list of identities that have "user" in their groups
FIXES=$(jq -c '[.[] | select(.metadata_admin.groups != null) | select(.metadata_admin.groups | index("user")) | {id, email: .traits.email, groups: .metadata_admin.groups}] | .[]' "$INPUT")

if [ -z "$FIXES" ]; then
  echo "No users with group 'user' found — nothing to fix."
  exit 0
fi

COUNT=$(echo "$FIXES" | wc -l | tr -d ' ')
echo "Found ${COUNT} users with 'user' group to fix"
echo ""

if [ "$DRY_RUN" = "1" ]; then
  echo "=== DRY RUN (set DRY_RUN=0 to apply) ==="
  echo ""
fi

OK=0
FAIL=0

echo "$FIXES" | while IFS= read -r row; do
  ID=$(echo "$row" | jq -r '.id')
  EMAIL=$(echo "$row" | jq -r '.email')
  OLD_GROUPS=$(echo "$row" | jq -c '.groups')

  # Replace "user" with "users" in the groups array
  NEW_GROUPS=$(echo "$OLD_GROUPS" | jq -c '[.[] | if . == "user" then "users" else . end]')

  echo "  ${EMAIL} (${ID})"
  echo "    old: ${OLD_GROUPS}"
  echo "    new: ${NEW_GROUPS}"

  if [ "$DRY_RUN" = "1" ]; then
    echo "    → skipped (dry run)"
    echo ""
    continue
  fi

  # GET full identity to get current state (needed for PUT)
  FULL=$(curl -sS "${KRATOS_ADMIN}/${ID}")
  if [ $? -ne 0 ] || [ -z "$FULL" ]; then
    echo "    ✗ failed to fetch identity"
    FAIL=$((FAIL + 1))
    echo ""
    continue
  fi

  # Build PUT body: update metadata_admin.groups, keep everything else
  BODY=$(echo "$FULL" | jq --argjson groups "$NEW_GROUPS" '
    {
      schema_id: .schema_id,
      traits: .traits,
      metadata_admin: ((.metadata_admin // {}) | .groups = $groups),
      metadata_public: (.metadata_public // {}),
      state: .state
    }
  ')

  HTTP_CODE=$(curl -sS -o /tmp/kratos-put-resp -w '%{http_code}' \
    -X PUT "${KRATOS_ADMIN}/${ID}" \
    -H 'Content-Type: application/json' \
    -d "$BODY")

  if [ "$HTTP_CODE" = "200" ]; then
    echo "    ✓ updated (HTTP ${HTTP_CODE})"
    OK=$((OK + 1))
  else
    RESP=$(cat /tmp/kratos-put-resp)
    echo "    ✗ failed (HTTP ${HTTP_CODE}): ${RESP}"
    FAIL=$((FAIL + 1))
  fi
  echo ""
done

echo "Done. OK=${OK} FAIL=${FAIL}"
