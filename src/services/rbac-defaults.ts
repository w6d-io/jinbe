import type { FlatRolesMap } from './redis-rbac.repository.js'

/**
 * The default role set every service gets: `admin` (wildcard) plus
 * operator/editor/viewer scoped to `<service>:` permissions.
 *
 * Single source of truth shared by `createService` (initial seed) and the RBAC
 * bundle importer (autofix — guarantees every imported service still ends up
 * with the full default roles even if the bundle omitted some).
 */
export function defaultServiceRoles(name: string): FlatRolesMap {
  return {
    admin: ['*'],
    operator: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`, `${name}:delete`, `${name}:execute`],
    editor: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`],
    viewer: [`${name}:list`, `${name}:read`],
  }
}
