import { declaredRoute } from './declared-routes.js'
import { scopeOf } from './catalog.js'

/**
 * What each OpenAPI operation says about its own authorization, written from the SAME declaration
 * the route-access hook turned into the guard (routing-remap §2.1): openapi.yaml becomes the
 * reviewable contract, and CI checks it against the declarations and the catalogue.
 *
 *   x-permission       the catalogue permission, matched exactly by the gateway
 *   x-scope            where it is decided: platform, or org (inside the organisation named by x-org-param)
 *   x-access           why no permission is needed: public | self | authenticated | machine
 *   x-org-param        the route parameter naming the organisation (org scope)
 *   x-step-up          a second factor proven within 15 minutes
 *   x-also-accepts     permissions the route's own guard also accepts on part of its input
 *   x-scoped-by        its own guard narrows the answer per caller (the audit scope)
 *   x-edge             machine routes: whether the gateway forwards it at all
 */
export function declarationExtensions(method: string, url: string): Record<string, unknown> {
  // A route registered as `/` under a prefix reaches swagger with its trailing slash, the table without.
  const row = declaredRoute(method, url) ?? (url.length > 1 && url.endsWith('/') ? declaredRoute(method, url.slice(0, -1)) : null)
  if (!row) return {}
  const ext: Record<string, unknown> = {}
  if (row.permission) {
    ext['x-permission'] = row.permission
    const scope = scopeOf(row.permission)
    if (scope) ext['x-scope'] = scope
  }
  if (row.access) ext['x-access'] = row.access
  if (!row.permission && !row.access) ext['x-access'] = row.class === 'public' ? 'public' : 'authenticated'
  if (row.org) ext['x-org-param'] = row.org
  if (row.stepUp) ext['x-step-up'] = true
  if (row.alsoAccepts?.length) ext['x-also-accepts'] = row.alsoAccepts
  if (row.scopedBy) ext['x-scoped-by'] = row.scopedBy
  if (row.access === 'machine') ext['x-edge'] = row.edge === true
  return ext
}

/** The @fastify/swagger `transform`: the route's schema plus its declaration's extensions. */
export function withDeclaration({ schema, url, route }: { schema?: unknown; url: string; route: { method: string | string[] } }) {
  const method = [route.method].flat().find((m) => m !== 'HEAD') ?? 'GET'
  const ext = declarationExtensions(method, url)
  return { schema: { ...((schema as Record<string, unknown> | undefined) ?? {}), ...ext }, url }
}
