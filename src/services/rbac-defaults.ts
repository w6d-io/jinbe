import type { FlatRolesMap } from './redis-rbac.repository.js'

/**
 * The default role set every service gets: operator/editor/viewer scoped to `<service>:` permissions,
 * and `admin` — every permission the service declares (its routes' permissions) plus the operator
 * set. Never `*`: matching is exact, so a role holds exactly the names it lists.
 *
 * Single source of truth shared by `createService` (initial seed), site presets (render.ts) and the
 * RBAC bundle importer (autofix — guarantees every imported service still ends up with the full
 * default roles even if the bundle omitted some).
 */
export function defaultServiceRoles(name: string, declared: readonly string[] = []): FlatRolesMap {
  const operator = [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`, `${name}:delete`, `${name}:execute`]
  return {
    admin: [...new Set([...operator, ...declared])].sort(),
    operator,
    editor: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`],
    viewer: [`${name}:list`, `${name}:read`],
  }
}
