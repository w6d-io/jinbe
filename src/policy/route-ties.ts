/**
 * Two services declaring the same route at the same rank.
 *
 * The policy (opal-policies rbac.rego, `owning_apps`) gives a request to the service holding its
 * most specific matching route. When two services tie at that rank it refuses to pick one and
 * answers `not_found` — fail-closed, but silent: the second registration "works" and every request
 * on that route is then refused for everybody. So a write that would create a tie is refused here,
 * where the author can still be told which service already owns the route.
 *
 * Mirrors `route_specificity` and `path_matches` in rbac.rego exactly; keep them in step. A
 * different rank is not a tie: the more specific route wins in policy, which is intended.
 */
import { redisRbacRepository, type RouteRule } from '../services/redis-rbac.repository.js'

type Rule = Pick<RouteRule, 'method' | 'path'>

export type RouteTie = {
  method: string
  service: string
  path: string
  otherService: string
  otherPath: string
}

const ANY = ':any*'
const isParam = (segment: string) => segment.startsWith(':')

/** rbac.rego `route_specificity`: exact 100000+segments, :param 10000+literals, :any* 1000+prefix depth. */
export function routeSpecificity(path: string): number {
  if (!path.includes(':')) return 100000 + path.split('/').length
  if (!path.includes(ANY)) return 10000 + path.split('/').filter((p) => !isParam(p)).length
  return 1000 + anyPrefix(path).filter((p) => p !== '').length
}

// rbac.rego's `trim_suffix(trim_suffix(pattern, ":any*"), "/")`, split on '/'.
function anyPrefix(path: string): string[] {
  const noAny = path.endsWith(ANY) ? path.slice(0, -ANY.length) : path
  return (noAny.endsWith('/') ? noAny.slice(0, -1) : noAny).split('/')
}

// rbac.rego `part_matches`, symmetric: some URL segment satisfies both pattern segments.
const segmentsOverlap = (a: string, b: string) => isParam(a) || isParam(b) || a === b

/** Whether some request URL is matched by both patterns (both already at the same rank). */
function patternsOverlap(a: string, b: string): boolean {
  if (!a.includes(':')) return a === b
  if (!a.includes(ANY)) {
    const pa = a.split('/')
    const pb = b.split('/')
    return pa.length === pb.length && pa.every((s, i) => segmentsOverlap(s, pb[i]))
  }
  // :any* matches its prefix and anything below it, so only the common depth has to agree.
  const pa = anyPrefix(a)
  const pb = anyPrefix(b)
  return pa.slice(0, Math.min(pa.length, pb.length)).every((s, i) => segmentsOverlap(s, pb[i]))
}

/** Whether two rules would both be the best match for some request — the policy's tie. */
export function routesTie(a: Rule, b: Rule): boolean {
  if (a.method !== b.method) return false
  if (a.path.includes(ANY) !== b.path.includes(ANY)) return false
  if (routeSpecificity(a.path) !== routeSpecificity(b.path)) return false
  return patternsOverlap(a.path, b.path)
}

/**
 * The hosts an app-pinned service is served on (a Site: its Oathkeeper rules put `"app":"<site>"` in
 * the payload). The policy never asks `owning_apps` for such a request, so two pinned services only
 * compete where they share a host. A service absent from the map is unpinned and competes everywhere.
 */
export type PinnedHosts = Record<string, readonly string[]>

function hostsDisjoint(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  if (!a?.length || !b?.length) return false
  const mine = new Set(a.map((h) => h.toLowerCase()))
  return !b.some((h) => mine.has(h.toLowerCase()))
}

/** Ties between `rules` (for `service`) and every OTHER service's rules. A service never ties with itself. */
export function findRouteTies(
  service: string,
  rules: readonly Rule[],
  others: Record<string, readonly Rule[]>,
  pinnedHosts: PinnedHosts = {},
): RouteTie[] {
  const ties: RouteTie[] = []
  for (const [otherService, otherRules] of Object.entries(others)) {
    if (otherService === service) continue
    if (hostsDisjoint(pinnedHosts[service], pinnedHosts[otherService])) continue
    for (const rule of rules) {
      for (const other of otherRules) {
        if (routesTie(rule, other)) {
          ties.push({ method: rule.method, service, path: rule.path, otherService, otherPath: other.path })
        }
      }
    }
  }
  return dedupe(ties)
}

/** Every tie across a whole set of route maps, each colliding pair reported once. */
export function findAllRouteTies(maps: Record<string, readonly Rule[]>): RouteTie[] {
  const names = Object.keys(maps)
  return names.flatMap((service, i) =>
    findRouteTies(service, maps[service], Object.fromEntries(names.slice(i + 1).map((n) => [n, maps[n]]))),
  )
}

// One path declared with several permissions is several rules; it is still one tie.
function dedupe(ties: RouteTie[]): RouteTie[] {
  const seen = new Set<string>()
  return ties.filter((t) => {
    const key = `${t.method} ${t.service} ${t.path} ${t.otherService} ${t.otherPath}`
    return seen.has(key) ? false : (seen.add(key), true)
  })
}

/** The rules OPA sees: the route map of every registered service (what /opal-datasource publishes). */
export async function loadPublishedRouteRules(): Promise<Record<string, RouteRule[]>> {
  const services = await redisRbacRepository.getServices()
  const maps = await Promise.all(services.map((svc) => redisRbacRepository.getRouteMap(svc)))
  return Object.fromEntries(services.map((svc, i) => [svc, maps[i]?.rules ?? []]))
}

export function describeRouteTie(t: RouteTie): string {
  return `${t.service} ${t.method} ${t.path} ties with ${t.otherService} ${t.method} ${t.otherPath}`
}

/** A 409 naming every tie, for the writers that refuse one. */
export function routeTieConflict(ties: RouteTie[]): Error & { statusCode: number; ties: RouteTie[] } {
  return Object.assign(
    new Error(
      `Route conflict: ${ties.map(describeRouteTie).join('; ')}. ` +
        'Two services at the same specificity leave the route with no owner, so the policy refuses ' +
        'every request on it. Make one route more specific or remove it from one service.',
    ),
    { statusCode: 409, ties },
  )
}
