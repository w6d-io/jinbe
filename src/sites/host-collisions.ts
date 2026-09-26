import { sitesConfig } from './config.js'
import { kubeSites, type IngressHosts } from './kube-sites.js'

/**
 * Hosts other Ingresses already serve, anywhere in the cluster — asked before a Site or a Zone is
 * made, so the wizard refuses what the operator would otherwise report as `HostTaken` after the fact.
 *
 * The rules are the operator's own (site-operator internal/controller/hosts.go): an Ingress naming the
 * exact host takes it (blocking, `HostTaken`); a wildcard one label above it is only shadowed — nginx
 * routes the exact host to the Site and that Ingress's paths stop being served there (a warning,
 * `HostShadowsWildcard`). Skipped: the Site's own Ingresses, and the operator's Zone wildcard Ingresses (a Site
 * under a wildcard Zone is meant to be served by them).
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
    .filter((ing) => !zoneWildcard(ing) && !ownedBy(ing, site))
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
