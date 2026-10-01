/**
 * The route table jinbe publishes about ITSELF: which permission each of its routes requires.
 *
 * Collected as Fastify registers each route, from what the route DECLARES (`config.permission` /
 * `config.access`, policy/route-access.ts) — the same declaration the hook turns into the guard, so a
 * row and the refusal behind it cannot disagree, and an undeclared route fails the boot instead of
 * appearing here as open. Guards still carry the permission they enforce (`enforcing`), so a route
 * with its own guard is checked against its declaration.
 *
 * Read by the delegation gate (what scope a token needs), `GET /api/catalog` (which routes need each
 * permission) and the generated jinbe route_map.
 */

export type DeclaredRoute = {
  method: string
  path: string
  /** `public` | `authenticated` | `authorized` — what is required before the handler runs. */
  class: 'public' | 'authenticated' | 'authorized'
  /** Only for `authorized`: the permission the guard checks. */
  permission?: string
  /** Why no permission is needed (route-access.ts `Access`). */
  access?: 'public' | 'machine' | 'self' | 'authenticated'
  /** A second factor proven within 15 minutes is required. */
  stepUp?: boolean
  /** Org-scoped: the route parameter naming the organisation. */
  org?: string
  /** Machine routes only: reachable through the gateway (SCIM). Default false: no gateway row. */
  edge?: boolean
  /** Permissions the route's own guard also accepts on part of its input (one more row each). */
  alsoAccepts?: string[]
  /** Its own guard narrows the answer per caller (the audit scope): the gateway lets any signed-in person through. */
  scopedBy?: string
  /** The authorization model the route exists in; absent = both (authz-v2). */
  model?: 'v1' | 'v2'
}

/** What a route declared about itself, as the route-access hook read it. */
export type Declaration = Pick<DeclaredRoute, 'permission' | 'access' | 'stepUp' | 'org' | 'edge' | 'alsoAccepts' | 'scopedBy' | 'model'>

/** The property a guard carries to say what it enforces. */
export const ENFORCES = Symbol.for('jinbe.enforces')

/** Marks a guard with the permission it requires, so the table can be read off it. */
export function enforcing<T extends object>(guard: T, permission: string): T {
  Object.defineProperty(guard, ENFORCES, { value: permission, enumerable: false })
  return guard
}

/** The permission a guard enforces, or null when it is not one of ours. */
export function enforcedBy(guard: unknown): string | null {
  if (guard === null || (typeof guard !== 'function' && typeof guard !== 'object')) return null
  return (guard as Record<symbol, string | undefined>)[ENFORCES] ?? null
}

/** The property a guard carries to say it narrows the answer per caller (the audit scope). */
export const SCOPED_BY = Symbol.for('jinbe.scopedBy')

/** Marks a guard as deciding per caller, so the gateway admits any signed-in person to its route. */
export function scopedBy<T extends object>(guard: T, by: string): T {
  Object.defineProperty(guard, SCOPED_BY, { value: by, enumerable: false })
  return guard
}

/** What a guard says it narrows by, or null. */
export function scopedByOf(guard: unknown): string | null {
  if (guard === null || (typeof guard !== 'function' && typeof guard !== 'object')) return null
  return (guard as Record<symbol, string | undefined>)[SCOPED_BY] ?? null
}

const collected = new Map<string, DeclaredRoute>()

/**
 * Records one route as Fastify registers it.
 *
 * With a declaration (the route-access hook), the row IS the declaration. Without one, the permission
 * is read off the guards — two levels deep, since a route's preHandler may itself be an array.
 *
 * `public` is asserted only for the paths this service answers with no credential at all. Anything
 * else carrying no permission is `authenticated`, because the session gate runs before every route —
 * calling an unguarded route `public` would be the comfortable reading and the wrong one.
 */
export function recordRoute(
  method: string | string[],
  path: string,
  guards: unknown,
  isPublic: (path: string) => boolean,
  declared?: Declaration,
): void {
  const permission = declared ? declared.permission ?? null : [guards].flat(2).map(enforcedBy).find((p) => p !== null) ?? null
  const extra: Declaration = {}
  if (declared?.access) extra.access = declared.access
  if (declared?.stepUp) extra.stepUp = true
  if (declared?.org) extra.org = declared.org
  if (declared?.edge) extra.edge = true
  if (declared?.alsoAccepts?.length) extra.alsoAccepts = [...declared.alsoAccepts]
  if (declared?.model) extra.model = declared.model
  const by = declared?.scopedBy ?? [guards].flat(2).map(scopedByOf).find((b) => b !== null)
  if (by) extra.scopedBy = by
  for (const verb of [method].flat()) {
    collected.set(`${verb} ${path}`, permission
      ? { method: verb, path, class: 'authorized', permission, ...extra }
      : { method: verb, path, class: isPublic(path) ? 'public' : 'authenticated', ...extra })
  }
}

/** Everything recorded so far, ordered so a diff between two versions is readable. */
export function declaredRoutes(): DeclaredRoute[] {
  return [...collected.values()].sort(
    (a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
  )
}

/**
 * The row for one route PATTERN (`request.routeOptions.url`), or null when nothing recorded it. HEAD
 * is answered by the GET route Fastify exposes for it.
 */
export function declaredRoute(method: string, path: string): DeclaredRoute | null {
  const verb = method.toUpperCase()
  return collected.get(`${verb} ${path}`) ?? (verb === 'HEAD' ? collected.get(`GET ${path}`) ?? null : null)
}

/** Test seam. */
export function resetDeclaredRoutes(): void {
  collected.clear()
}
