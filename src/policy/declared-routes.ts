/**
 * The route table jinbe publishes about ITSELF: which permission each of its routes requires.
 *
 * DERIVED FROM THE GATES, never written beside them. Each guard carries the permission it enforces,
 * and this table is collected from the guards Fastify actually attached — so a row and the refusal
 * behind it cannot disagree, and a route added without a guard is absent rather than silently
 * described as open.
 *
 * Why publish it at all, when jinbe is not behind the gateway and nothing looks it up to decide:
 *
 *   - a console could not say what `admin:read` opens, so the screen that hands out rights showed
 *     "no route declares it" beside every administrative permission;
 *   - the 76 rows that did describe these routes were seeded into Redis, which nothing reads any
 *     more, and had drifted to a vocabulary the model no longer knows (`clusters:list`);
 *   - and the permission was spelled once in the guard and once in that dead table — two
 *     descriptions, free to disagree.
 *
 * It describes what IS enforced, not what ought to be. Refining `admin:read` into the resource tree
 * is a real authorization change and belongs in its own review, not in the act of writing it down.
 */

export type DeclaredRoute = {
  method: string
  path: string
  /** `public` | `authenticated` | `authorized` — what is required before the handler runs. */
  class: 'public' | 'authenticated' | 'authorized'
  /** Only for `authorized`: the permission the guard checks. */
  permission?: string
}

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

const collected = new Map<string, DeclaredRoute>()

/**
 * Records one route as Fastify registers it.
 *
 * `public` is asserted only for the paths this service answers with no credential at all. Anything
 * else carrying no permission-bearing guard is `authenticated`, because the session gate runs before
 * every route — calling an unguarded route `public` would be the comfortable reading and the wrong
 * one.
 */
export function recordRoute(
  method: string | string[],
  path: string,
  guards: unknown,
  isPublic: (path: string) => boolean,
): void {
  const permission = [guards].flat().map(enforcedBy).find((p) => p !== null) ?? null
  for (const verb of [method].flat()) {
    collected.set(`${verb} ${path}`, permission
      ? { method: verb, path, class: 'authorized', permission }
      : { method: verb, path, class: isPublic(path) ? 'public' : 'authenticated' })
  }
}

/** Everything recorded so far, ordered so a diff between two versions is readable. */
export function declaredRoutes(): DeclaredRoute[] {
  return [...collected.values()].sort(
    (a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
  )
}

/** Test seam. */
export function resetDeclaredRoutes(): void {
  collected.clear()
}
