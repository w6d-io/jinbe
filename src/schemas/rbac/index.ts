/**
 * RBAC Schemas Module
 *
 * This module exports all RBAC-related schemas.
 */

// Schema exports
export * from './bindings.schema.js'
export * from './groups.schema.js'
export * from './roles.schema.js'
export * from './access-rules.schema.js'
export * from './route-map.schema.js'
export * from './deploy.schema.js'
export * from './history.schema.js'

/**
 * File paths for RBAC config files
 *
 * Note: Groups are now stored in a separate groups.json file
 * Kustomization is at repository root (not in configmaps/)
 */
export const RBAC_FILES = {
  BINDINGS: 'configmaps/bindings.json',
  GROUPS: 'configmaps/groups.json',
  ACCESS_RULES: 'configmaps/access-rules.json',
  KUSTOMIZATION: 'kustomization.yaml',
  ROLES_PATTERN: 'configmaps/roles/roles.*.json',
  ROUTES_PATTERN: 'configmaps/routes/route_map.*.json',
} as const

/**
 * Get roles file path for a service
 */
export function getRolesFilePath(serviceName: string): string {
  return `configmaps/roles/roles.${serviceName}.json`
}

/**
 * Get route map file path for a service
 */
export function getRouteMapFilePath(serviceName: string): string {
  return `configmaps/routes/route_map.${serviceName}.json`
}

/**
 * Extract service name from a roles file path
 */
export function getServiceNameFromRolesPath(filePath: string): string | null {
  const match = filePath.match(/^(?:configmaps\/)?roles\/roles\.(.+)\.json$/)
  return match ? match[1] : null
}

/**
 * Extract service name from a route map file path
 */
export function getServiceNameFromRouteMapPath(filePath: string): string | null {
  const match = filePath.match(/^(?:configmaps\/)?routes\/route_map\.(.+)\.json$/)
  return match ? match[1] : null
}

/**
 * Default roles to assign to standard groups when a new service is created
 *
 * When a service is created, these groups (if they exist in groups.json)
 * will automatically receive the specified roles for the new service.
 *
 * Group hierarchy:
 * - super_admins (T0): Platform owners - NOT included here because they have
 *   global super_admin access and don't need per-service roles
 * - admins (T1): Service administrators
 * - infra (T2): SRE/Ops team, operations access
 * - devs (T3): Developers, read + write
 * - viewers (T4): Read-only access
 */
export const DEFAULT_GROUP_SERVICE_ROLES: Record<string, string[]> = {
  super_admins: ['admin'],
  admins: ['admin'],
  infra: ['operator'],
  devs: ['editor'],
  viewers: ['viewer'],
}
