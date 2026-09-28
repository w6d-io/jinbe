#!/usr/bin/env bash
# Deletes the kind cluster `auth-local` (everything in it: Sites, Zones, Gateway). The compose stack
# is untouched; jinbe keeps its kubeconfig and answers 503 kubernetes_unavailable until up.sh runs.
# PURGE=1 also removes .state/ and .cache/ (kubeconfigs, rendered chart, cloned maester sources).
source "$(dirname "$0")/lib.sh"
export KIND_EXPERIMENTAL_PROVIDER=podman

if cluster_exists; then
  log "deleting cluster $CLUSTER"
  kind delete cluster --name "$CLUSTER" --kubeconfig "$ADMIN_KC"
else
  log "no cluster $CLUSTER"
fi
# up.sh lowered it for the ingress on :80 (runtime only); put podman's default back
if [ "$HTTP_PORT" -lt 1024 ] && [ "$(podman machine ssh sysctl -n net.ipv4.ip_unprivileged_port_start | tr -d '\r')" != 1024 ]; then
  log "podman machine: net.ipv4.ip_unprivileged_port_start -> 1024"
  podman machine ssh sudo sysctl -q -w net.ipv4.ip_unprivileged_port_start=1024
fi
if [ "${PURGE:-0}" = 1 ]; then
  log "purging .state and .cache"
  rm -rf "$STATE" "$CACHE"
fi
