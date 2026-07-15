import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger, RouteRule } from './types.js'

/**
 * Merge built-in jinbe routes into existing route_map.
 *
 * Behavior:
 * - User-added routes are preserved verbatim.
 * - User-modified `permission` overrides on built-in routes are preserved.
 * - New built-in routes (not present by `${method}:${path}` key) are appended.
 *
 * The merge is keyed on `method + path + permission`. If a built-in route
 * already exists (same method + path + permission), the existing version wins
 * so user customizations survive code-driven re-runs. Keying on the permission
 * too lets a single method+path carry MULTIPLE permission variants (e.g. a
 * legacy `admin:read` rule AND a delegated `org:manage_users` rule) — the OPA
 * policy allows a request if the caller satisfies ANY matching rule, so this is
 * how an endpoint is opened to more than one role without disturbing the others.
 */
const ruleKey = (r: RouteRule): string => `${r.method}:${r.path}:${r.permission ?? ''}`

export async function mergeJinbeRouteMap(
  builtInRoutes: readonly RouteRule[],
  logger: BootstrapLogger,
): Promise<{ added: number; total: number }> {
  const existing = await redisRbacRepository.getRouteMap('jinbe')
  const existingRules = existing?.rules ?? []
  const existingKeys = new Set(existingRules.map(ruleKey))
  const toAdd = builtInRoutes.filter((r) => !existingKeys.has(ruleKey(r)))

  if (toAdd.length === 0) {
    logger.debug({ total: existingRules.length }, 'Jinbe route_map up to date — no new built-in routes')
    return { added: 0, total: existingRules.length }
  }

  const merged = [...existingRules, ...toAdd]
  await redisRbacRepository.setRouteMap('jinbe', { rules: merged })
  logger.info({ added: toAdd.length, total: merged.length }, 'Jinbe route_map updated with new built-in routes')
  return { added: toAdd.length, total: merged.length }
}
