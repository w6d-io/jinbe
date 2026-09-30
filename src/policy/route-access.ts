import { EVERYTHING, isCatalogPermission, specOf, type Permission } from './catalog.js'
import { enforcedBy, recordRoute } from './declared-routes.js'
import { requirePermission } from '../middleware/require-permission.js'
import { requireGlobalSuperAdmin, requireRecentMfa } from '../middleware/require-admin.js'
import { isPublicRoute } from '../middleware/require-auth.js'
import { recordRouteContext } from './route-guards.js'

/**
 * Every route says what it needs, in its own options, and ONE hook turns that into the gate.
 *
 *   config: { permission: 'sites:apply' }   → requirePermission (+ requireRecentMfa when the catalogue
 *                                             says stepUp), recorded in the route table
 *   config: { permission: '*' }             → requireGlobalSuperAdmin (the legacy infrastructure)
 *   config: { access: 'self' | ... }        → no permission, for a reason the value names
 *
 * A route declaring neither, a permission outside the catalogue, or a guard of its own that enforces
 * a DIFFERENT permission than the one it declares fails the boot: an undeclared route is one nobody
 * decided about.
 *
 * A route whose check depends on the request (an edit needs what it changes, the audit scope narrows
 * an org admin) keeps its own guard, marked with `enforcing(guard, permission)`; the hook sees that
 * mark and attaches nothing but the step-up.
 */

/** Why a route requires no permission. */
export type Access =
  /** Answered with no credential at all (login-ui, liveness); must be on the session gate's bypass list. */
  | 'public'
  /** Its own credential, checked by the route: OPAL token, webhook secret, SCIM bearer, machine or actor token. */
  | 'machine'
  /** Answers about, or changes only, the caller: their keys, their saved views, their briefing. */
  | 'self'
  /** Any signed-in person; the answer is the same for all of them (the catalogue, whether MCP is on). */
  | 'authenticated'

export const ACCESS_VALUES: readonly Access[] = ['public', 'machine', 'self', 'authenticated']

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The catalogue permission this route requires (policy/catalog.ts), or `*` for super admins alone. */
    permission?: Permission | typeof EVERYTHING
    /** Why this route requires no permission. Exactly one of `permission` and `access`. */
    access?: Access
    /** A step-up on this route even though its permission does not need one everywhere. */
    stepUp?: boolean
    /**
     * Decided per organisation by the plugin's own org gate (OPA rbac.decision, org admin roster),
     * named by this route parameter. The hook attaches no platform guard: an org admin holds nothing
     * across the platform.
     */
    org?: string
  }
}

/** Route options that declare a permission. Spread into a route's options. */
export function needs(permission: Permission | typeof EVERYTHING, extra: { stepUp?: boolean; org?: string } = {}) {
  return { config: { permission, ...extra } }
}

/** Route options that declare why no permission is needed. */
export function open(access: Access) {
  return { config: { access } }
}

/** Registered by plugins that cannot take route options: the API documentation (ENABLE_SWAGGER). */
const UNDECLARED = /^\/docs(\/|$)/

export class RouteAccessError extends Error {}

type RouteOptions = {
  method: string | string[]
  url: string
  preHandler?: unknown
  config?: { permission?: string; access?: string; stepUp?: boolean; org?: string } & Record<string, unknown>
}

/**
 * The onRoute hook: validates the declaration, attaches the guard and the step-up, records the row.
 * Throws (the boot fails) on a missing or contradictory declaration.
 */
export function attachRouteAccess(route: RouteOptions, isPublic: (path: string) => boolean): void {
  const where = `${[route.method].flat().join(',')} ${route.url}`
  const { permission, access, stepUp, org } = route.config ?? {}

  if (!permission && !access) {
    if (UNDECLARED.test(route.url)) {
      recordRoute(route.method, route.url, [], isPublic, { access: 'public' })
      return
    }
    throw new RouteAccessError(`${where} declares neither config.permission nor config.access`)
  }
  if (permission && access) throw new RouteAccessError(`${where} declares both a permission and access '${access}'`)

  const chain = [route.preHandler].flat(2).filter((h) => h !== undefined && h !== null)

  if (access) {
    if (!(ACCESS_VALUES as readonly string[]).includes(access)) throw new RouteAccessError(`${where}: unknown access '${access}'`)
    if (access === 'public' && !isPublic(route.url)) {
      throw new RouteAccessError(`${where} declares access 'public' but the session gate does not let it through`)
    }
    recordRoute(route.method, route.url, chain, isPublic, { access: access as Access })
    return
  }

  if (permission !== EVERYTHING && !isCatalogPermission(permission!)) {
    throw new RouteAccessError(`${where} requires '${permission}', which is not in the catalogue`)
  }
  const own = chain.map(enforcedBy).filter((p): p is string => p !== null)
  const other = own.find((p) => p !== permission)
  if (other) throw new RouteAccessError(`${where} declares '${permission}' but its own guard enforces '${other}'`)
  if (org !== undefined && !route.url.split('/').includes(`:${org}`)) {
    throw new RouteAccessError(`${where} is org-scoped by ':${org}', which is not a parameter of its path`)
  }

  const gate = own.length > 0 || org !== undefined
    ? []
    : [permission === EVERYTHING ? requireGlobalSuperAdmin : requirePermission(permission as Permission)]
  const wantsStepUp = (specOf(permission!)?.stepUp || stepUp === true) && !chain.includes(requireRecentMfa)
  route.preHandler = [...gate, ...chain, ...(wantsStepUp ? [requireRecentMfa] : [])]

  recordRoute(route.method, route.url, route.preHandler, isPublic, {
    permission: permission!,
    stepUp: wantsStepUp || chain.includes(requireRecentMfa),
    ...(org !== undefined ? { org } : {}),
  })
}

/**
 * Installs the hook on an instance, BEFORE any route is registered: on the root in server.ts, and on
 * the throwaway app of a test that mounts one plugin.
 */
export function installRouteAccess(fastify: { addHook(name: 'onRoute', fn: (this: unknown, route: RouteOptions) => void): unknown }): void {
  fastify.addHook('onRoute', function (this: unknown, route) {
    attachRouteAccess(route, isPublicRoute)
    // `this` is the instance the route is registered on: whose hooks Fastify runs before it.
    recordRouteContext(this, route)
  })
}
