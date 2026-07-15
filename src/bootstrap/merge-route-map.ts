import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger, RouteRule } from './types.js'

/**
 * Merge built-in jinbe routes into the existing route_map.
 *
 * Behavior, keyed per `method + path`:
 * - User-added routes (paths not in the built-in set) are preserved verbatim.
 * - If the operator has CUSTOMIZED a built-in path in place — i.e. that path
 *   carries any permission that is NOT one of the current built-in variants for
 *   it (e.g. they tightened `admin:read` to a stricter `admin:superread`) — the
 *   path is treated as operator-owned: nothing is added, so a code-driven re-run
 *   can never silently resurrect the weaker built-in default alongside their
 *   override and re-widen access.
 * - Otherwise (the path carries only current built-in permissions, or is new)
 *   any MISSING built-in permission variant is appended. This is how a single
 *   method+path safely carries several permissions (e.g. a legacy `admin:read`
 *   rule AND a delegated `org:manage_users` rule) — OPA allows on ANY matching
 *   rule, so adding a variant widens by exactly that one role and leaves the
 *   others intact.
 *
 * The merge is append-only: it never deletes or rewrites an existing rule.
 */
const pathKey = (r: RouteRule): string => `${r.method}:${r.path}`
const perm = (r: RouteRule): string => r.permission ?? ''

export async function mergeJinbeRouteMap(
  builtInRoutes: readonly RouteRule[],
  logger: BootstrapLogger,
): Promise<{ added: number; total: number }> {
  const existing = await redisRbacRepository.getRouteMap('jinbe')
  const existingRules = existing?.rules ?? []

  // Existing permissions grouped by method+path.
  const existingPermsByPath = new Map<string, Set<string>>()
  for (const r of existingRules) {
    const k = pathKey(r)
    if (!existingPermsByPath.has(k)) existingPermsByPath.set(k, new Set())
    existingPermsByPath.get(k)!.add(perm(r))
  }

  // Built-in permission variants grouped by method+path.
  const builtInByPath = new Map<string, RouteRule[]>()
  for (const r of builtInRoutes) {
    const k = pathKey(r)
    if (!builtInByPath.has(k)) builtInByPath.set(k, [])
    builtInByPath.get(k)!.push(r)
  }

  const toAdd: RouteRule[] = []
  for (const [k, variants] of builtInByPath) {
    const existingPerms = existingPermsByPath.get(k)
    if (!existingPerms) {
      toAdd.push(...variants) // path absent → seed all built-in variants
      continue
    }
    const builtInPerms = new Set(variants.map(perm))
    const operatorCustomized = [...existingPerms].some((p) => !builtInPerms.has(p))
    if (operatorCustomized) {
      logger.info(
        { path: k },
        'Jinbe route_map: operator-customized path — preserving, skipping built-in variants',
      )
      continue
    }
    for (const r of variants) {
      if (!existingPerms.has(perm(r))) toAdd.push(r)
    }
  }

  if (toAdd.length === 0) {
    logger.debug({ total: existingRules.length }, 'Jinbe route_map up to date — no new built-in routes')
    return { added: 0, total: existingRules.length }
  }

  const merged = [...existingRules, ...toAdd]
  await redisRbacRepository.setRouteMap('jinbe', { rules: merged })
  logger.info({ added: toAdd.length, total: merged.length }, 'Jinbe route_map updated with new built-in routes')
  return { added: toAdd.length, total: merged.length }
}
