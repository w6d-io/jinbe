# Local kind cluster for Sites and the Gateway

The compose stack (jinbe, Kratos, OPA/OPAL, kuma) has no Kubernetes, so the kuma pages backed by it
(Sites apply/status, Zones, Gateway handlers) answered 503 `kubernetes_unavailable`. `up.sh` runs the
Kubernetes half of the platform in a local kind cluster and points the compose jinbe at it.

```sh
dev/kind/up.sh     # create or restart everything (idempotent, ~2 min from scratch)
dev/kind/down.sh   # delete the cluster (PURGE=1 also drops .state/ and .cache/)
```

After `up.sh`, a site plugged in kuma under `*.sites.localtest.me` (upstream `echo` / `demo` / 80 is
there to try) is served at `http://<site>.sites.localtest.me`. localtest.me resolves to 127.0.0.1 in
public DNS, nothing to configure.

## What runs where

| kind `auth-local`, namespace `auth` | compose (unchanged) |
|---|---|
| Oathkeeper v25.4.0 + maester sidecar (site Rules only) | jinbe `:3000`, kuma `:5173` |
| site-operator (`site-operator@d33f4b1`, built locally) | Kratos `:4433`, login-ui `:3001` |
| gatekit (the gatekit checkout's HEAD) | OPA/OPAL `:8181`, the compose gatekit |
| ingress-nginx on host `:80`, Zone `local` (`sites.localtest.me`) | oathkeeper `:4455`: the legacy rules (jinbe/kuma API) |
| `Gateway default`, `auth-opa-authz-proxy` (local stand-in), echo in `demo` | |

The in-kind Oathkeeper serves **site traffic only**. The compose `oathkeeper` keeps the legacy
jinbe-served rules. Their hosts never overlap, so jinbe runs with `SITES_MIXED_GATEWAY=true`, like
the sandbox: sites apply without the migration cut-over, and preview still refuses any overlap.

What gets deployed is `helm template` of `charts/charts/auth` (the checkout's branch, e.g.
`feat/opa-authz`) with `values-local.yaml`: only Oathkeeper, site-operator, gatekit and jinbe's
ServiceAccount + Sites RBAC are enabled, and jinbe's workload is dropped. Where the chart lags the
pinned operator, `up.sh` takes the `auth.w6d.io` CRDs, the admission-policy rules, the operator's
cluster-wide ClusterRole and the extra allowed Ingress annotations from `site-operator@$SITE_OPERATOR_REF`,
the same patch the sandbox needed (sandbox-e2e `apply/06b`).

kind reaches the compose stack through selector-less Services (`manifests/bridge.yaml`) whose
endpoints are podman's `host.containers.internal`. They carry the chart's names
(`auth-kratos-public`, and OPA behind `auth-opa-authz-proxy`), so the Oathkeeper config stays the
chart's. The only URL changed is the login redirect (`http://localhost:3001/login`). Bearer tokens
are forwarded to Kratos (`forward_http_headers: [x-session-token]`), as in the sandbox's live config.

## jinbe wiring (docker-compose.yml)

- `SITES_KUBE=kubeconfig`, `KUBECONFIG=/kind/kubeconfig`: `./dev/kind/jinbe` is mounted read-only,
  and up.sh writes `jinbe/kubeconfig` there (gitignored). It holds a token for the chart's
  `auth-jinbe` ServiceAccount (Role `auth-jinbe-site-writer`, ClusterRole `auth-auth-jinbe-zones`),
  not cluster-admin, and dials `https://host.containers.internal:6443` (the name is in the API
  server certificate).
- `SITES_NAMESPACE=auth`, `GATEWAY_OATHKEEPER_CONFIGMAP=auth-oathkeeper-config-base` (chart value
  when the operator owns the Gateway), `SITES_ZONE_ALLOWED_PARENTS=localtest.me`,
  `SITES_INGRESS_ADDRESSES=127.0.0.1`, reserved hosts and platform namespaces as rendered by the
  chart, `OATHKEEPER_ENABLED_AUTHORIZERS=allow,deny,remote_json` (sites render `deny` gates).
- jinbe still uses the compose `gatekit`, `GATEKIT_URL=http://gatekit:8080`. The operator uses the
  one in kind. Rebuild `gatekit:local` if they drift.
- jinbe builds its Kubernetes client once. up.sh restarts the `jinbe` container whenever the
  kubeconfig changes (new cluster). Without the cluster, jinbe answers 503 `kubernetes_unavailable`.
  To opt out, run `SITES_KUBE=off docker compose up -d api`.
- If jinbe was created before this wiring, run `docker compose up -d api` once to recreate it.

## kubectl

Everything uses the cluster's own kubeconfig. `kind create` never touches `~/.kube/config` or its
current context:

```sh
kubectl --kubeconfig dev/kind/.state/admin.kubeconfig --context kind-auth-local get sites,zones,gateways,rules -A
```

The chart applies run as `--as-group=system:masters`. kind's admin is in `kubeadm:cluster-admins`,
and the chart's admission policies let only `system:masters` (or Argo) write platform Rules.

## Try it

```sh
# anonymous: browser → login redirect, API → 401
curl -si -H 'Accept: text/html' http://echo.sites.localtest.me/ | grep -i ^location
curl -s -o /dev/null -w '%{http_code}\n' -H 'Accept: application/json' http://echo.sites.localtest.me/
# signed in (Kratos API flow for the dev admin, then the session token)
F=$(curl -s localhost:4433/self-service/login/api | jq -r .id)
T=$(curl -s -XPOST "localhost:4433/self-service/login?flow=$F" -H 'content-type: application/json' \
  -d '{"method":"password","identifier":"dev@localhost.dev","password":"dev-local-bootstrap-secret!!"}' | jq -r .session_token)
curl -s -H "X-Session-Token: $T" http://echo.sites.localtest.me/hello | jq .headers
```

## Limits and gotchas

- **Browser SSO**: the local Kratos cookie is set for `localhost`, so it never reaches
  `*.sites.localtest.me`. jinbe says so (`no_sso`). A browser gets the login redirect, but after
  signing in it is not signed in on the site. Use a session token or send the cookie by hand.
  Kratos may also refuse the `return_to` (not in its allowed return URLs).
- **Port 80**: Oathkeeper matches rules on the Host header, port included, and ingress-nginx passes
  the browser's port through. A site on `:8080` matches no rule (404). So the ingress is published
  on `:80`. For that, up.sh lowers `net.ipv4.ip_unprivileged_port_start` to 80 in the podman machine
  VM. The change is runtime only: down.sh puts it back and a VM restart forgets it. macOS lets the
  unprivileged gvproxy bind :80 only on all interfaces, so the sites are reachable from the LAN too,
  through Oathkeeper like any site. `KIND_HTTP_PORT=8080` binds 127.0.0.1 only, but site rules then
  don't match.
- **Podman**: the docker provider refuses rootless podman (cgroup delegation), so kind runs with
  `KIND_EXPERIMENTAL_PROVIDER=podman`. The images are built through podman's docker API with
  explicit `TARGETARCH` (its legacy builder leaves it empty and the Dockerfiles default to amd64).
- **No TLS**: there is no cert-manager (`enableCertificates=false`). Zones use `tls.mode: default`,
  plain http here.
- **Policy authorizer**: the chart's opa-authz-proxy image is amd64-only.
  `manifests/opa-authz-proxy.yaml` is a small node stand-in with the same contract (OPA
  `rbac/decision`: 200 + `X-User-Groups`, 404 `not_found`, 403 otherwise). It sends the compose
  OPA's token.
- **Oathkeeper Deployment**: once the Gateway exists, the operator owns its config volume, so re-runs
  of up.sh don't re-apply it. Run `OATHKEEPER=1 dev/kind/up.sh` after a chart change to it.
- **Site CRs are jinbe's intent**: after `down.sh && up.sh`, jinbe's sync loop re-creates the saved
  sites within `SITES_SYNC_INTERVAL_MS` (60 s).

## Files

`up.sh`, `down.sh`, `images.sh` (arm64/amd64 builds, skipped when the label matches the source rev),
`lib.sh` (names, ports, `$K`), `kind-config.yaml`, `values-local.yaml`, `manifests/` (bridge, authz
stand-in, demo upstream + Zone). Generated: `.state/` (admin kubeconfig, rendered chart), `.cache/`
(chart copy, site-operator source at the ref, oathkeeper-maester clone), `jinbe/kubeconfig`.
