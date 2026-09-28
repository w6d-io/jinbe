import { sitesConfig } from './config.js'
import { kubeSites, type IngressHosts, type ListenerHosts, type RouteHosts } from './kube-sites.js'

/**
 * Hosts other Ingresses already serve, anywhere in the cluster — asked before a Site or a Zone is
 * made, so the wizard refuses what the operator would otherwise report as `HostTaken` after the fact.
 *
 * The rules are the operator's own (site-operator internal/controller/hosts.go): an Ingress naming the
 * exact host takes it (blocking, `HostTaken`); a wildcard one label above it is only shadowed — nginx
 * routes the exact host to the Site and that Ingress's paths stop being served there (a warning,
 * `HostShadowsWildcard`). Skipped: the Site's own Ingresses, the operator's Zone wildcard Ingresses (a Site
 * under a wildcard Zone is meant to be served by them), and the operator's shared `host-<hash8>` Ingress
 * for the host itself (per-site Zones): it belongs to every Site on the host (owner references, none a
 * controller), so it is the Site's own, or its siblings' under other path prefixes — which site holds
 * which prefix is `hostOwner`'s question, not an Ingress collision (the operator's `ours`).
 *
 * A host under a zone with a Gateway also meets the Gateway side (the operator's routeCheck): an
 * HTTPRoute naming it exactly takes it, and so does a listener with that exact hostname on the zone's
 * Gateway (its own or a ListenerSet's: it wins the match); a wildcard route only shadows it. The
 * operator's shared `host-<hash8>` route for the host is the site's own.
 */

const MANAGED_BY = 'app.kubernetes.io/managed-by'
const OPERATOR = 'site-operator'
const SITE_LABEL = 'auth.w6d.io/site'
const ZONE_LABEL = 'auth.w6d.io/zone'

export interface IngressRef {
  namespace: string
  name: string
  /** The rule host that serves (or would be shadowed by) the host in question. */
  rule: string
  /** The paths that Ingress routes for that rule. */
  paths?: string[]
}

export function serves(rule: string, host: string): boolean {
  if (rule === host) return true
  if (!rule.startsWith('*.')) return false
  const suffix = rule.slice(1)
  return host.endsWith(suffix) && !host.slice(0, -suffix.length).includes('.')
}

const byOperator = (ing: IngressHosts) => ing.namespace === sitesConfig().namespace && ing.labels[MANAGED_BY] === OPERATOR
const zoneWildcard = (ing: IngressHosts) => byOperator(ing) && !!ing.labels[ZONE_LABEL] && ing.name.startsWith('zone-')
const ownedBy = (ing: IngressHosts, site: string | undefined) => !!site && byOperator(ing) && ing.labels[SITE_LABEL] === site
const HOST_INGRESS_LABEL = 'auth.w6d.io/host-ingress'
const HOST_ANNOTATION = 'auth.w6d.io/host'
const sharedFor = (ing: IngressHosts, host: string) =>
  byOperator(ing) && ing.labels[HOST_INGRESS_LABEL] === 'true' && ing.name.startsWith('host-') && ing.annotations?.[HOST_ANNOTATION]?.toLowerCase() === host

/**
 * Every Ingress of the cluster, or null when the cluster is not read (SITES_KUBE=off: nothing to
 * compare with). A cluster that is on but cannot answer throws 503, like every other cluster read.
 */
export async function clusterIngresses(): Promise<IngressHosts[] | null> {
  if (sitesConfig().SITES_KUBE === 'off') return null
  const list = await kubeSites().listIngresses()
  return list.sort((a, b) => `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`))
}

/** The Ingresses, not owned by `site`, that already serve `host`. */
export function hostCollisions(host: string, site: string | undefined, ingresses: readonly IngressHosts[]): IngressRef[] {
  const h = host.toLowerCase()
  return ingresses
    .filter((ing) => !zoneWildcard(ing) && !ownedBy(ing, site) && !sharedFor(ing, h))
    .flatMap((ing) => ing.hosts.filter((rule) => serves(rule.toLowerCase(), h)).map((rule) => ({ namespace: ing.namespace, name: ing.name, rule, paths: ing.paths?.[rule] ?? [] })))
}

type CollisionCheck = { level: 'error' | 'warn'; code: 'host_taken' | 'host_shadows_wildcard'; message: string; path: 'address.host'; ingress: IngressRef }

/**
 * One check per Ingress in the way: `host_taken` (error) when it names the host, `host_shadows_wildcard`
 * (warning) when it is a wildcard the host's own Ingress would shadow — worded as the operator's conditions.
 */
export function collisionChecks(host: string, site: string | undefined, ingresses: readonly IngressHosts[] | null): CollisionCheck[] {
  if (!ingresses) return []
  const h = host.toLowerCase()
  return hostCollisions(h, site, ingresses).map((c): CollisionCheck => {
    if (c.rule.toLowerCase() === h) {
      return { level: 'error', code: 'host_taken', message: `${c.namespace}/${c.name} serves ${h}; nothing would be created for this host`, path: 'address.host', ingress: c }
    }
    const lost = c.paths?.filter((p) => p !== '/') ?? []
    const paths = lost.length ? `paths of that Ingress, e.g. ${lost.slice(0, 3).join(', ')}, are not served on this host` : 'that Ingress no longer serves this host'
    return { level: 'warn', code: 'host_shadows_wildcard', message: `${c.namespace}/${c.name} serves ${c.rule}; nginx routes ${h} to this Site (${paths})`, path: 'address.host', ingress: c }
  })
}

/**
 * What a new `*.<domain>` wildcard would meet among the Ingresses not written by the operator:
 * `taken` — another wildcard for the same domain (the two collide); `shadowed` — exact hosts one
 * label under it, which keep their own Ingress while the wildcard answers every other name.
 * Either means the domain is shared, and a per-site Zone is the fitting mode.
 */
export function wildcardConflicts(domain: string, ingresses: readonly IngressHosts[]) {
  const foreign = ingresses.filter((ing) => !byOperator(ing))
  const taken: IngressRef[] = []
  const shadowed: IngressRef[] = []
  for (const ing of foreign) {
    for (const raw of ing.hosts) {
      const rule = raw.toLowerCase()
      if (rule === `*.${domain}`) taken.push({ namespace: ing.namespace, name: ing.name, rule: raw })
      else if (!rule.startsWith('*.') && serves(`*.${domain}`, rule)) shadowed.push({ namespace: ing.namespace, name: ing.name, rule: raw })
    }
  }
  return { taken, shadowed }
}

// ── Gateway API (zones with a gateway) ──────────────────────────────────────

export interface GatewayObjects {
  routes: RouteHosts[]
  listeners: ListenerHosts[]
}

const HOST_ROUTE_LABEL = 'auth.w6d.io/host-route'
const ownRoute = (r: RouteHosts, host: string) =>
  r.namespace === sitesConfig().namespace && r.labels[MANAGED_BY] === OPERATOR && r.labels[HOST_ROUTE_LABEL] === 'true' &&
  r.name.startsWith('host-') && r.annotations?.[HOST_ANNOTATION]?.toLowerCase() === host

/** A Gateway API wildcard hostname (`*.x`) covers every host ending in `.x`, one label or more. */
export function routeServesByWildcard(rule: string, host: string): boolean {
  return rule.startsWith('*.') && host.endsWith(rule.slice(1)) && host.length > rule.length - 1
}

/**
 * Every HTTPRoute and ListenerSet of the cluster, plus the listeners of the allowed Gateways — or null
 * when no Gateway is configured (SITES_GATEWAYS empty) or the cluster is not read: nothing to compare.
 */
export async function clusterGatewayObjects(): Promise<GatewayObjects | null> {
  const cfg = sitesConfig()
  const kube = kubeSites()
  if (cfg.SITES_KUBE === 'off' || cfg.SITES_GATEWAYS.length === 0 || !kube.listHTTPRoutes || !kube.listListenerSets || !kube.getGateway) return null
  const [routes, sets, gateways] = await Promise.all([
    kube.listHTTPRoutes(),
    kube.listListenerSets(),
    Promise.all(cfg.SITES_GATEWAYS.map(async (key) => {
      const [ns, name] = key.split('/')
      const gw = await kube.getGateway!(ns, name)
      return gw ? [{ kind: 'Gateway' as const, namespace: ns, name, gateway: key, listeners: (gw.spec.listeners ?? []).map((l) => ({ name: l.name, hostname: l.hostname, port: l.port, protocol: l.protocol })) }] : []
    })),
  ])
  return {
    routes: routes.sort((a, b) => `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`)),
    listeners: [...gateways.flat(), ...sets],
  }
}

type RouteCheck = { level: 'error' | 'warn'; code: 'host_taken' | 'host_shadows_wildcard'; message: string; path: 'address.host' }

/**
 * The Gateway side of a host under a zone attached to `gateway` (namespace/name): `host_taken` for a
 * foreign route or an exact-hostname listener on that Gateway, `host_shadows_wildcard` for a foreign
 * wildcard route — worded as the operator's RouteReady / HostShadowsWildcard.
 */
export function routeCollisions(host: string, gateway: string | undefined, objects: GatewayObjects | null): RouteCheck[] {
  if (!objects || !gateway) return []
  const h = host.toLowerCase()
  const out: RouteCheck[] = []
  for (const r of objects.routes) {
    if (ownRoute(r, h)) continue
    for (const raw of r.hostnames) {
      const rule = raw.toLowerCase()
      if (rule === h) out.push({ level: 'error', code: 'host_taken', message: `HTTPRoute ${r.namespace}/${r.name} serves ${h}; no route would be created for this host`, path: 'address.host' })
      else if (routeServesByWildcard(rule, h)) out.push({ level: 'warn', code: 'host_shadows_wildcard', message: `HTTPRoute ${r.namespace}/${r.name} serves ${raw}; the gateway routes ${h} to this Site`, path: 'address.host' })
    }
  }
  for (const l of objects.listeners) {
    if (l.gateway !== gateway) continue
    const hit = l.listeners.find((x) => x.hostname?.toLowerCase() === h)
    if (!hit) continue
    const who = l.kind === 'Gateway' ? `listener ${hit.name} of Gateway ${l.gateway}` : `ListenerSet ${l.namespace}/${l.name} (listener ${hit.name})`
    out.push({ level: 'error', code: 'host_taken', message: `${who} serves ${h} (exact hostname: it wins over the zone's listener)`, path: 'address.host' })
  }
  return out
}
