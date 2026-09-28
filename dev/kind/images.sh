#!/usr/bin/env bash
# Builds the three images kind runs from local sources, for the host arch, and skips any whose
# label already records the same source revision. FORCE=1 rebuilds all.
#   site-operator:local       site-operator at $SITE_OPERATOR_REF (git archive: committed state only)
#   oathkeeper-maester:local  ory/oathkeeper-maester $MAESTER_REF + site-operator/hack/maester-sidecar.patch
#   gatekit:kind              the gatekit checkout's HEAD (the compose keeps its own gatekit:local)
source "$(dirname "$0")/lib.sh"

ARCH=$(docker version --format '{{.Server.Arch}}')

built_rev() { docker image inspect "$1" --format '{{index .Config.Labels "dev.kind.rev"}}' 2>/dev/null || true; }

build() { # image rev context [dockerfile]
  local img=$1 rev=$2 ctx=$3 file=${4:-$3/Dockerfile}
  if [ "${FORCE:-0}" != 1 ] && [ "$(built_rev "$img")" = "$rev" ]; then
    log "$img up to date ($rev)"; return
  fi
  log "building $img ($rev)"
  # explicit: podman's docker API (legacy builder) does not fill TARGETARCH, the Dockerfiles default to amd64
  docker build -q -t "$img" --label "dev.kind.rev=$rev" --build-arg TARGETOS=linux --build-arg "TARGETARCH=$ARCH" \
    -f "$file" "$ctx" >/dev/null
}

# site-operator: the pinned commit, not the working tree
rev=$(git -C "$SITE_OPERATOR_DIR" rev-parse --short=7 "$SITE_OPERATOR_REF")
src="$CACHE/site-operator-$rev"
if [ ! -d "$src" ]; then
  mkdir -p "$src"
  git -C "$SITE_OPERATOR_DIR" archive "$rev" | tar -x -C "$src"
fi
build "$IMG_OPERATOR" "$rev" "$src"

# maester: upstream tag + the sidecar patch the chart expects (v0.1.14-w6d.1)
patch="$SITE_OPERATOR_DIR/hack/maester-sidecar.patch"
prev="$MAESTER_REF+$(shasum "$patch" | cut -c1-8)"
msrc="$CACHE/oathkeeper-maester"
if [ "$(built_rev "$IMG_MAESTER")" != "$prev" ] || [ "${FORCE:-0}" = 1 ]; then
  rm -rf "$msrc"
  git clone -q --depth 1 --branch "$MAESTER_REF" https://github.com/ory/oathkeeper-maester "$msrc" 2>/dev/null
  git -C "$msrc" apply "$patch"
fi
build "$IMG_MAESTER" "$prev" "$msrc" "$SITE_OPERATOR_DIR/hack/maester.Dockerfile"

# gatekit: the checkout's HEAD
build "$IMG_GATEKIT" "$(git -C "$GATEKIT_DIR" rev-parse --short=7 HEAD)" "$GATEKIT_DIR"
