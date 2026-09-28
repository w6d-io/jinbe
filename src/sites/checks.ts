import { redisRbacRepository, type OathkeeperRule } from '../services/redis-rbac.repository.js'
import { findRouteTies, loadPublishedRouteRules, describeRouteTie, type PinnedHosts } from '../policy/route-ties.js'
import { SYSTEM_SITES, type Site } from './schemas.js'
import type { Check, Rendered } from './render.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { gatekit, type Probe } from './gatekit.client.js'
import { examplePath } from './patterns.js'
import { sitesConfig } from './config.js'
import { liveAddresses } from './address.js'

/**
 * The checks render cannot make alone because they need the rest of the platform: other services'
 * routes, existing groups, other sites' hosts, and gatekit's verdict on the live rule set.
 */

export type SiteError = Error & { statusCode: number; code: string; checks?: Check[] }

export const siteError = (statusCode: number, code: string, message: string, checks?: Check[]): SiteError =>
  Object.assign(new Error(message), { statusCode, code, ...(checks ? { checks } : {}) })

export function assertNotSystem(name: string): void {
  if ((SYSTEM_SITES as readonly string[]).includes(name)) {
    throw siteError(403, 'system_site', `'${name}' is a system service; it cannot be changed through the Sites API`)
  }
}

export const errorsOf = (checks: Check[]) => checks.filter((c) => c.level === 'error')

/** Every rule the gateway serves today: the legacy/system rules and each applied site's rules. */
export async function liveRules(except?: string, records?: SiteRecord[]): Promise<OathkeeperRule[]> {
  const legacy = await redisRbacRepository.getAccessRules()
  const sites = (records ?? (await sitesRepository.list())).filter((r) => r.site.name !== except && r.applied)
  return [...legacy, ...sites.flatMap((r) => r.applied!.rules)]
}

/**
 * Hosts of every app-pinned service: applied sites, plus the candidate. An applied site is pinned to
 * the host it serves now (`live`, its applied version's), which a later saved move may not share yet.
 */
export function pinnedHostsOf(records: SiteRecord[], candidate: Site, live?: Map<string, Site['address']>): PinnedHosts {
  const hosts: PinnedHosts = Object.fromEntries(records.filter((r) => r.applied).map((r) => [r.site.name, [(live?.get(r.site.name) ?? r.site.address).host]]))
  hosts[candidate.name] = [candidate.address.host]
  return hosts
}

const prefixesOverlap = (a?: string, b?: string) => !a || !b || a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`)

/**
 * The other site already serving this host (and path prefix), if any. A site holds both its saved
 * address and, until a move is applied, the one it still serves (`live`): neither may be taken.
 */
export function hostOwner(host: string, prefix: string | undefined, except: string | undefined, records: SiteRecord[], live?: Map<string, Site['address']>): { owner?: string; sharedWith: string[]; moving?: boolean } {
  const h = host.toLowerCase()
  const claims = records.filter((r) => r.site.name !== except).flatMap((r) => {
    const held = live?.get(r.site.name)
    return [
      ...(r.site.address.host === h ? [{ name: r.site.name, prefix: r.site.address.pathPrefix, moving: false }] : []),
      ...(held && (held.host !== r.site.address.host || held.pathPrefix !== r.site.address.pathPrefix) && held.host === h ? [{ name: r.site.name, prefix: held.pathPrefix, moving: true }] : []),
    ]
  })
  const owner = claims.find((c) => prefixesOverlap(prefix, c.prefix))
  const sharedWith = [...new Set(claims.filter((c) => c.name !== owner?.name).map((c) => c.name))]
  return { owner: owner?.name, sharedWith, ...(owner?.moving ? { moving: true } : {}) }
}

export async function contextChecks(site: Site, rendered: Rendered, records?: SiteRecord[]): Promise<Check[]> {
  const checks: Check[] = []
  const all = records ?? (await sitesRepository.list())
  const mine = all.find((r) => r.site.name === site.name)
  if ((await redisRbacRepository.serviceExists(site.name)) && !mine?.applied) {
    checks.push({ level: 'error', code: 'service_exists', message: `'${site.name}' is already a service not managed as a site; adopt it through the migration instead`, path: 'name' })
  }

  const live = await liveAddresses(all)
  const ties = findRouteTies(site.name, rendered.routeMap, await loadPublishedRouteRules(), pinnedHostsOf(all, site, live))
  for (const tie of ties) checks.push({ level: 'error', code: 'route_tie', message: describeRouteTie(tie), path: 'routes' })

  const groups = await redisRbacRepository.getGroups()
  for (const group of Object.keys(rendered.groups.platform)) {
    if (!groups[group]) checks.push({ level: 'error', code: 'unknown_group', message: `platform group '${group}' does not exist`, path: `groups.platform.${group}` })
  }
  for (const group of Object.keys(rendered.groups.orgGrantable)) {
    const others = Object.keys(groups[group] ?? {}).filter((svc) => svc !== site.name)
    if (others.length > 0) checks.push({ level: 'error', code: 'group_taken', message: `group '${group}' already covers ${others.join(', ')}`, path: `groups.orgGrantable.${group}` })
  }

  const cfg = sitesConfig()
  const host = site.address.host
  if (cfg.SITES_RESERVED_HOSTS.includes(host)) checks.push({ level: 'error', code: 'host_reserved', message: `${host} is a platform host`, path: 'address.host' })
  const { owner, moving } = hostOwner(host, site.address.pathPrefix, site.name, all, live)
  if (owner) checks.push({ level: 'error', code: 'host_taken', message: moving ? `${host} is still served by site '${owner}' until its address change is applied` : `${host} is already served by site '${owner}'`, path: 'address.host' })
  // Zone, depth and SSO are render's checks (the zones are part of the platform it is given).
  return checks
}

/** gatekit: every generated pattern compiles, and no request matches two rules gateway-wide. Throws 503 when gatekit cannot answer. */
export async function gatekitChecks(site: Site, rendered: Rendered, records?: SiteRecord[]): Promise<Check[]> {
  const checks: Check[] = []
  const compiled = await gatekit.compile(rendered.rules.map((r) => ({ id: r.id, url: r.match.url, methods: r.match.methods })))
  for (const result of compiled.filter((c) => !c.ok)) {
    checks.push({ level: 'error', code: 'pattern_invalid', message: `rule ${result.id} does not compile: ${result.error ?? 'invalid'}`, path: 'gates' })
  }
  const candidate = new Set(rendered.rules.map((r) => r.id))
  const host = site.address.host
  const probes: Probe[] = []
  for (const row of rendered.routeMap) probes.push({ method: row.method, url: `https://${host}${examplePath(row.path)}` })
  if (rendered.rules.some((r) => r.match.methods.includes('OPTIONS'))) {
    probes.push({ method: 'OPTIONS', url: `https://${host}${site.address.pathPrefix ?? ''}/` })
  }
  const result = await gatekit.overlap([...(await liveRules(site.name, records)), ...rendered.rules], dedupe(probes), [host])
  for (const o of result.overlaps.filter((x) => candidate.has(x.a) || candidate.has(x.b))) {
    checks.push({ level: 'error', code: 'rule_overlap', message: `${o.method} ${o.exampleUrl} is matched by both ${o.a} and ${o.b}`, path: 'routes' })
  }
  for (const bad of (result.invalid ?? []).filter((x) => candidate.has(x.id))) {
    checks.push({ level: 'error', code: 'pattern_invalid', message: `rule ${bad.id} is refused by the matcher: ${bad.error}`, path: 'gates' })
  }
  return checks
}

function dedupe(probes: Probe[]): Probe[] {
  const seen = new Set<string>()
  return probes.filter((p) => (seen.has(`${p.method} ${p.url}`) ? false : (seen.add(`${p.method} ${p.url}`), true)))
}
