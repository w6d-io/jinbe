#!/usr/bin/env bash
# Creates (or restarts) the local kind cluster `auth-local` with the Sites/Gateway half of the auth
# chart, and wires the compose jinbe to it. Idempotent: re-run after a reboot, a site-operator bump
# (SITE_OPERATOR_REF=<sha>) or a chart change. Local dev only; see README.md.
source "$(dirname "$0")/lib.sh"
export KIND_EXPERIMENTAL_PROVIDER=podman   # the docker provider cannot see rootless podman's cgroup delegation
NODE=$CLUSTER-control-plane

for bin in kind kubectl helm yq envsubst podman docker; do command -v $bin >/dev/null || die "$bin not found"; done

log "images"
"$KIND_DIR/images.sh"

# rootless podman binds no port below net.ipv4.ip_unprivileged_port_start (1024) in the podman
# machine VM. Lowered at runtime only (the VM forgets it on restart; up.sh sets it again).
if [ "$HTTP_PORT" -lt 1024 ]; then
  start=$(podman machine ssh sysctl -n net.ipv4.ip_unprivileged_port_start | tr -d '\r')
  if [ "$start" -gt "$HTTP_PORT" ]; then
    log "podman machine: net.ipv4.ip_unprivileged_port_start $start -> $HTTP_PORT (runtime only)"
    podman machine ssh sudo sysctl -q -w net.ipv4.ip_unprivileged_port_start="$HTTP_PORT"
  fi
fi

if cluster_exists; then
  if [ "$(podman inspect -f '{{.State.Running}}' "$NODE")" != true ]; then
    log "starting $NODE"; podman start "$NODE" >/dev/null
  fi
else
  log "creating cluster $CLUSTER (api :$API_PORT, http :$HTTP_PORT)"
  export API_PORT HTTP_PORT HTTP_LISTEN
  envsubst '${API_PORT} ${HTTP_PORT} ${HTTP_LISTEN}' < "$KIND_DIR/kind-config.yaml" > "$STATE/kind-config.yaml"
  kind create cluster --config "$STATE/kind-config.yaml" --kubeconfig "$ADMIN_KC" --wait 180s
fi
kind export kubeconfig --name "$CLUSTER" --kubeconfig "$ADMIN_KC" >/dev/null 2>&1
for _ in $(seq 60); do $K get --raw /readyz >/dev/null 2>&1 && break; sleep 2; done

log "loading images"
kind load docker-image --name "$CLUSTER" "$IMG_OPERATOR" "$IMG_MAESTER" "$IMG_GATEKIT" 2>&1 | grep -v '^$' || true

log "ingress-nginx"
[ -s "$CACHE/ingress-nginx.yaml" ] || curl -fsSL "$INGRESS_NGINX_URL" -o "$CACHE/ingress-nginx.yaml"
$K apply --server-side --field-manager=local-dev -f "$CACHE/ingress-nginx.yaml" >/dev/null
$K -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=300s

log "chart render (charts/auth, release auth)"
# helm template leaves metadata.namespace off most parent-chart objects: every apply below takes -n $NS
$K create namespace $NS --dry-run=client -o yaml | $K apply -f - >/dev/null
chart="$CACHE/chart/auth"
rm -rf "$chart.new" && mkdir -p "$chart.new" && cp -R "$CHART_DIR/." "$chart.new/"
if [ -d "$chart/charts" ]; then cp -n "$chart"/charts/*.tgz "$chart.new/charts/" 2>/dev/null || true; fi
rm -rf "$chart" && mv "$chart.new" "$chart"
helm dependency build "$chart" --skip-refresh >/dev/null 2>&1 || helm dependency build "$chart" >/dev/null
# jinbe itself runs in compose: keep its ServiceAccount, RBAC and nothing else of it
helm template auth "$chart" -n $NS -f "$KIND_DIR/values-local.yaml" \
    --set jinbe.env.ENCRYPTION_KEY=unused-in-kind-jinbe-runs-in-compose \
  | yq 'select(. != null and .kind != "Pod" and
      ((.metadata.name == "auth-jinbe" or .metadata.name == "auth-jinbe-metrics" or .metadata.name == "auth-jinbe-bootstrap") and .kind != "ServiceAccount") == false)' \
  > "$STATE/chart.render.yaml"
# The chart can lag the pinned operator (the sandbox patched the same way, apply/06b): take the
# auth.w6d.io CRDs, every admission policy's rules and the cluster-wide ClusterRole from
# site-operator@ref, keep the chart's names, bindings and params, and add the operator's allowed
# Ingress annotations to the params.
SRC="$CACHE/site-operator-$(git -C "$SITE_OPERATOR_DIR" rev-parse --short=7 "$SITE_OPERATOR_REF")"
python3 - "$STATE/chart.render.yaml" "$SRC/config" "$STATE/chart.yaml" <<'PY'
import glob, sys, yaml
render, cfg, out = sys.argv[1:]
docs = [d for d in yaml.safe_load_all(open(render)) if d]
load = lambda pattern: [d for f in sorted(glob.glob(f"{cfg}/{pattern}")) for d in yaml.safe_load_all(open(f)) if d]
crds = load("crd/bases/*.yaml")
vaps = {d["metadata"]["name"]: d["spec"] for d in load("admission/*_policy.yaml") if d["kind"] == "ValidatingAdmissionPolicy"}
params = next(d for d in load("admission/params.yaml") if d["kind"] == "ConfigMap")["data"]
# cluster-wide grants (no resourceNames, so they carry over as is); the namespaced Role is the chart's
zones_rules = next(d for d in load("rbac/role.yaml") if d["kind"] == "ClusterRole")["rules"]
keep = []
for d in docs:
    if d["kind"] == "CustomResourceDefinition" and d["spec"]["group"] == "auth.w6d.io":
        continue
    name = d["metadata"]["name"]
    if d["kind"] == "ValidatingAdmissionPolicy" and name.removeprefix("auth-") in vaps:
        d["spec"] = {**vaps[name.removeprefix("auth-")], "paramKind": d["spec"]["paramKind"]}
    if d["kind"] == "ClusterRole" and name.endswith("-auth-site-operator-zones"):
        d["rules"] = zones_rules
    if d["kind"] == "ConfigMap" and name == "auth-site-operator-policy":
        split = lambda s: [k.strip() for k in s.split(",") if k.strip()]
        have = split(d["data"]["allowedIngressAnnotations"])
        d["data"]["allowedIngressAnnotations"] = ",".join(have + [k for k in split(params["allowedIngressAnnotations"]) if k not in have])
    keep.append(d)
yaml.safe_dump_all(crds + keep, open(out, "w"), sort_keys=False)
PY
yq 'select(.kind == "CustomResourceDefinition")' "$STATE/chart.yaml" > "$STATE/crds.yaml"
$K apply --server-side --field-manager=local-dev --force-conflicts -f "$STATE/crds.yaml" >/dev/null
$K wait --for=condition=Established crd --all --timeout=60s >/dev/null

log "bridge to the compose stack"
HOST_IP=$(podman exec "$NODE" getent hosts host.containers.internal | awk '{print $1; exit}')
[ -n "$HOST_IP" ] || die "host.containers.internal does not resolve in $NODE"
export HOST_IP
envsubst '${HOST_IP}' < "$KIND_DIR/manifests/bridge.yaml" | $K apply --server-side --field-manager=local-dev -f - >/dev/null
$K apply --server-side --field-manager=local-dev -f "$KIND_DIR/manifests/opa-authz-proxy.yaml" >/dev/null

log "apply chart"
# Once it exists the Oathkeeper Deployment's config volume belongs to the operator (Gateway): a
# re-apply would point it back at the seed ConfigMap. OATHKEEPER=1 re-applies it anyway.
skip=auth-oathkeeper
if [ "${OATHKEEPER:-0}" = 1 ] || ! $K -n $NS get deploy auth-oathkeeper >/dev/null 2>&1; then skip=; fi
yq "select(.kind != \"CustomResourceDefinition\" and (.kind == \"Deployment\" and .metadata.name == \"$skip\") == false)" "$STATE/chart.yaml" \
  | $KM -n $NS apply --server-side --field-manager=local-dev --force-conflicts -f - >/dev/null
for d in auth-gatekit auth-opa-authz-proxy auth-site-operator auth-oathkeeper; do
  $K -n $NS rollout status deploy/$d --timeout=300s
done

log "demo upstream + Zone local ($ZONE_DOMAIN)"
$K apply --server-side --field-manager=local-dev -f "$KIND_DIR/manifests/demo.yaml" >/dev/null

# Gateway `default`, adopted from the chart's base config exactly as jinbe adopts it on the first save.
# Created once; later edits (kuma) are never overwritten.
if ! $K -n $NS get gateway default >/dev/null 2>&1; then
  log "Gateway default (from auth-oathkeeper-config-base)"
  $K -n $NS get cm auth-oathkeeper-config-base -o jsonpath='{.data.config\.yaml}' \
    | yq '{"apiVersion": "auth.w6d.io/v1alpha1", "kind": "Gateway", "metadata": {"name": "default", "namespace": "auth"},
           "spec": {"authenticators": .authenticators, "authorizers": .authorizers, "mutators": .mutators,
                    "errors": {"handlers": .errors.handlers, "fallback": .errors.fallback}}}' \
    | $K create -f - >/dev/null
fi

log "jinbe ServiceAccount kubeconfig"
cat <<EOF | $K apply -f - >/dev/null
apiVersion: v1
kind: Secret
metadata:
  name: auth-jinbe-local-token
  namespace: $NS
  annotations: {kubernetes.io/service-account.name: auth-jinbe}
type: kubernetes.io/service-account-token
EOF
for _ in $(seq 30); do
  TOKEN=$($K -n $NS get secret auth-jinbe-local-token -o jsonpath='{.data.token}' | base64 -d)
  [ -n "$TOKEN" ] && break; sleep 1
done
CA=$($K config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
new=$(cat <<EOF
apiVersion: v1
kind: Config
clusters:
- name: $CLUSTER
  cluster:
    server: https://host.containers.internal:$API_PORT
    certificate-authority-data: $CA
users:
- name: auth-jinbe
  user:
    token: $TOKEN
contexts:
- name: $CONTEXT-jinbe
  context: {cluster: $CLUSTER, user: auth-jinbe, namespace: $NS}
current-context: $CONTEXT-jinbe
EOF
)
if [ "$new" != "$(cat "$JINBE_KC" 2>/dev/null)" ]; then
  # the container runs as DEV_UID (not the host user) and reads it through the ./dev/kind bind mount
  printf '%s\n' "$new" > "$JINBE_KC" && chmod 644 "$JINBE_KC"
  # jinbe builds its Kubernetes client once: restart it on a new cluster/token
  if docker inspect jinbe >/dev/null 2>&1; then
    log "restarting jinbe (new kubeconfig)"
    docker restart jinbe >/dev/null
  fi
fi

log "ready"
cat <<EOF
  kubectl:  kubectl --kubeconfig $ADMIN_KC --context $CONTEXT get sites,zones,gateways -A
  sites:    http://<site>.$ZONE_DOMAIN$([ "$HTTP_PORT" = 80 ] || echo ":$HTTP_PORT")  (demo upstream: echo.demo.svc.cluster.local:80)
  compose jinbe: SITES_KUBE=kubeconfig (docker-compose.yml); recreate it once with
                 docker compose up -d api   if it predates this wiring
EOF
