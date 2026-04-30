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
 * The merge is keyed on `method + path`. If a built-in route already exists
 * (same method + path), the existing version wins so user customizations of
 * the permission field survive code-driven re-runs.
 */
export async function mergeJinbeRouteMap(
  builtInRoutes: readonly RouteRule[],
  logger: BootstrapLogger,
): Promise<{ added: number; total: number }> {
  const existing = await redisRbacRepository.getRouteMap('jinbe')
  const existingRules = existing?.rules ?? []
  const existingKeys = new Set(existingRules.map((r) => `${r.method}:${r.path}`))
  const toAdd = builtInRoutes.filter((r) => !existingKeys.has(`${r.method}:${r.path}`))

  if (toAdd.length === 0) {
    logger.debug({ total: existingRules.length }, 'Jinbe route_map up to date — no new built-in routes')
    return { added: 0, total: existingRules.length }
  }

  const merged = [...existingRules, ...toAdd]
  await redisRbacRepository.setRouteMap('jinbe', { rules: merged })
  logger.info({ added: toAdd.length, total: merged.length }, 'Jinbe route_map updated with new built-in routes')
  return { added: toAdd.length, total: merged.length }
}
