# Shared by up.sh / down.sh / images.sh. Local dev only: every kubectl call goes through $K,
# which pins the kind cluster's OWN kubeconfig file and context (never ~/.kube/config).
set -euo pipefail

KIND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JINBE_DIR="$(cd "$KIND_DIR/../.." && pwd)"
AUTH_DIR="$(cd "$JINBE_DIR/.." && pwd)"
STATE="$KIND_DIR/.state"
CACHE="$KIND_DIR/.cache"

CLUSTER=auth-local
CONTEXT=kind-$CLUSTER
ADMIN_KC="$STATE/admin.kubeconfig"
# the only file the compose jinbe sees (./dev/kind/jinbe mounted at /kind)
JINBE_KC="$KIND_DIR/jinbe/kubeconfig"
NS=auth
# kube-apiserver published on the host; jinbe (compose) reaches it at host.containers.internal
API_PORT=${KIND_API_PORT:-6443}
# ingress-nginx on the host: http://<site>.sites.localtest.me. Port 80 on purpose: Oathkeeper matches
# rules against the Host header, and ingress-nginx forwards it with any port the browser sent, so a
# site on :8080 would match no rule (up.sh lets rootless podman bind it, see README)
HTTP_PORT=${KIND_HTTP_PORT:-80}
if [ "$HTTP_PORT" -lt 1024 ]; then HTTP_LISTEN=0.0.0.0; else HTTP_LISTEN=127.0.0.1; fi
ZONE_DOMAIN=sites.localtest.me

SITE_OPERATOR_DIR=${SITE_OPERATOR_DIR:-$AUTH_DIR/site-operator}
SITE_OPERATOR_REF=${SITE_OPERATOR_REF:-d33f4b1}
GATEKIT_DIR=${GATEKIT_DIR:-$AUTH_DIR/gatekit}
CHART_DIR=${CHART_DIR:-$AUTH_DIR/charts/charts/auth}
MAESTER_REF=v0.1.14
INGRESS_NGINX_URL=https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.13.3/deploy/static/provider/kind/deploy.yaml

IMG_OPERATOR=site-operator:local
IMG_MAESTER=oathkeeper-maester:local
IMG_GATEKIT=gatekit:kind

K="kubectl --kubeconfig $ADMIN_KC --context $CONTEXT"
# kind's admin is in kubeadm:cluster-admins, not system:masters; the chart's admission policies let
# only system:masters (or Argo) write platform Rules, so chart applies run as a masters member
KM="$K --as=local-dev-admin --as-group=system:masters --as-group=system:authenticated"

log() { printf '\033[1;34m[kind]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[kind]\033[0m %s\n' "$*" >&2; exit 1; }
cluster_exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }

mkdir -p "$STATE" "$CACHE"
