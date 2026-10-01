/**
 * Which guards a route runs, read off Fastify itself — for the explainer
 * (POST /api/admin/rbac/explain-route), which runs them in a dry run.
 *
 * Fastify builds a route's hooks at ready from the hooks of the instance the route was registered on
 * (global ones such as the delegation gate, and a plugin's own such as a scope guard on the audit
 * routes) followed by the route's `preHandler` option. Recorded here: that instance and those
 * options, as the onRoute hook sees them (route-access.ts), so the chain read back later is the one
 * Fastify runs — never a list kept beside it by hand.
 *
 * `findRoute` gives a path's params but not its pattern, so the pattern is the recorded one that
 * matches the path with exactly those params (static segments preferred, as the router does).
 */

type Hook = (...args: never[]) => unknown
type RouteOpts = { method: string | string[]; url: string; preHandler?: unknown; config?: Record<string, unknown> }

interface Recorded {
  instance: object
  opts: RouteOpts
}

const recorded = new Map<string, Recorded>()

/** Called by the onRoute hook with the instance the route is registered on. */
export function recordRouteContext(instance: unknown, opts: RouteOpts): void {
  if (typeof instance !== 'object' || instance === null) return
  for (const method of [opts.method].flat()) recorded.set(`${method.toUpperCase()} ${opts.url}`, { instance, opts })
}

// Fastify keeps an instance's hooks under an unexported symbol; found by its description.
function hooksOf(instance: object): Record<string, Hook[]> | null {
  for (let o: object | null = instance; o; o = Object.getPrototypeOf(o) as object | null) {
    const sym = Object.getOwnPropertySymbols(o).find((s) => s.description === 'fastify.hooks')
    if (sym) return (o as Record<symbol, Record<string, Hook[]>>)[sym] ?? null
  }
  return null
}

const asHooks = (v: unknown): Hook[] => [v].flat(2).filter((h): h is Hook => typeof h === 'function')

export interface RouteChain {
  onRequest: Hook[]
  preHandler: Hook[]
  config: Record<string, unknown>
  /** False when Fastify's instance hooks could not be read: only the route's own guards are listed. */
  complete: boolean
}

/** The hooks Fastify runs for one route pattern, in order; null when nothing recorded it. */
export function routeChain(method: string, pattern: string): RouteChain | null {
  const verb = method.toUpperCase()
  const entry = recorded.get(`${verb} ${pattern}`) ?? (verb === 'HEAD' ? recorded.get(`GET ${pattern}`) : undefined)
  if (!entry) return null
  const hooks = hooksOf(entry.instance)
  return {
    onRequest: asHooks(hooks?.onRequest),
    preHandler: [...asHooks(hooks?.preHandler), ...asHooks(entry.opts.preHandler)],
    config: entry.opts.config ?? {},
    complete: hooks !== null,
  }
}

function paramsOf(pattern: string, path: string): Record<string, string> | null {
  const want = pattern.split('/')
  const got = path.split('/')
  const params: Record<string, string> = {}
  for (let i = 0; i < want.length; i++) {
    const seg = want[i]
    if (seg === '*') {
      params['*'] = got.slice(i).join('/')
      return params
    }
    if (i >= got.length) return null
    if (seg.startsWith(':')) {
      if (got[i] === '') return null
      try {
        params[seg.slice(1)] = decodeURIComponent(got[i])
      } catch {
        return null
      }
    } else if (seg !== got[i]) return null
  }
  return want.length === got.length ? params : null
}

const staticSegments = (pattern: string) => pattern.split('/').filter((s) => s !== '' && !s.startsWith(':') && s !== '*').length

const sameParams = (a: Record<string, string>, b: Record<string, string>) =>
  Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([k, v]) => b[k] === v)

/**
 * The recorded pattern a path resolves to, given the params the router found for it (`findRoute`);
 * null when no recorded pattern agrees.
 */
export function patternFor(method: string, path: string, found: Record<string, string | undefined>): string | null {
  const verb = method.toUpperCase()
  const want = Object.fromEntries(Object.entries(found).filter((e): e is [string, string] => e[1] !== undefined))
  const candidates = [...recorded.keys()]
    .filter((k) => k.startsWith(`${verb} `) || (verb === 'HEAD' && k.startsWith('GET ')))
    .map((k) => k.slice(k.indexOf(' ') + 1))
    .map((pattern) => ({ pattern, params: paramsOf(pattern, path) }))
    .filter((c): c is { pattern: string; params: Record<string, string> } => c.params !== null && sameParams(c.params, want))
    .sort((a, b) => staticSegments(b.pattern) - staticSegments(a.pattern))
  return candidates[0]?.pattern ?? null
}

/** Test seam. */
export function resetRouteContexts(): void {
  recorded.clear()
}
