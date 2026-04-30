import type { RouteRule } from './types.js'

/**
 * Built-in jinbe service route map.
 *
 * Routes without a `permission` field are public (OPA policy: routes
 * with no permission requirement allow all authenticated users).
 *
 * Routes with `permission` are gated by the OPA policy comparing
 * the user's aggregated permissions against the route's required permission.
 */
export const JINBE_BUILT_IN_ROUTES: readonly RouteRule[] = [
  // Public routes
  { method: 'GET',    path: '/api/health' },
  { method: 'GET',    path: '/api/whoami' },
  { method: 'GET',    path: '/docs/:any*' },

  // Clusters
  { method: 'GET',    path: '/api/clusters',                        permission: 'clusters:list' },
  { method: 'POST',   path: '/api/clusters',                        permission: 'clusters:create' },
  { method: 'GET',    path: '/api/clusters/:id',                    permission: 'clusters:read' },
  { method: 'PUT',    path: '/api/clusters/:id',                    permission: 'clusters:update' },
  { method: 'DELETE', path: '/api/clusters/:id',                    permission: 'clusters:delete' },
  { method: 'POST',   path: '/api/clusters/verify',                 permission: 'clusters:create' },
  { method: 'POST',   path: '/api/clusters/:id/verify',             permission: 'clusters:update' },
  { method: 'POST',   path: '/api/clusters/:id/databases',          permission: 'databases:create' },
  { method: 'POST',   path: '/api/clusters/:id/backups',            permission: 'backups:create' },
  { method: 'POST',   path: '/api/clusters/:clusterId/jobs',        permission: 'jobs:create' },
  { method: 'GET',    path: '/api/clusters/:clusterId/jobs',        permission: 'jobs:list' },
  { method: 'GET',    path: '/api/clusters/:clusterId/jobs/pods',   permission: 'jobs:read' },

  // Databases
  { method: 'GET',    path: '/api/databases',                       permission: 'databases:list' },
  { method: 'GET',    path: '/api/databases/:id',                   permission: 'databases:read' },
  { method: 'GET',    path: '/api/databases/:id/list',              permission: 'databases:read' },
  { method: 'PUT',    path: '/api/databases/:id',                   permission: 'databases:update' },
  { method: 'DELETE', path: '/api/databases/:id',                   permission: 'databases:delete' },
  { method: 'GET',    path: '/api/databases/:id/api',               permission: 'databases:read' },
  { method: 'POST',   path: '/api/databases/:id/api',               permission: 'databases:create' },

  // Backups
  { method: 'GET',    path: '/api/backups',                         permission: 'backups:list' },
  { method: 'GET',    path: '/api/backups/:id',                     permission: 'backups:read' },
  { method: 'DELETE', path: '/api/backups/:id',                     permission: 'backups:delete' },
  { method: 'POST',   path: '/api/backups/:id/items',               permission: 'backups:create' },

  // Backup items
  { method: 'GET',    path: '/api/backup-items',                    permission: 'backups:list' },
  { method: 'GET',    path: '/api/backup-items/:id',                permission: 'backups:read' },
  { method: 'PUT',    path: '/api/backup-items/:id',                permission: 'backups:update' },
  { method: 'DELETE', path: '/api/backup-items/:id',                permission: 'backups:delete' },

  // Database APIs
  { method: 'GET',    path: '/api/database-apis',                   permission: 'databases:list' },
  { method: 'GET',    path: '/api/database-apis/:id',               permission: 'databases:read' },
  { method: 'PUT',    path: '/api/database-apis/:id',               permission: 'databases:update' },
  { method: 'DELETE', path: '/api/database-apis/:id',               permission: 'databases:delete' },

  // Admin user management
  { method: 'GET',    path: '/api/admin/users',                     permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/users',                     permission: 'admin:create' },
  { method: 'GET',    path: '/api/admin/users/:id',                 permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/users/:id',                 permission: 'admin:update' },
  { method: 'DELETE', path: '/api/admin/users/:id',                 permission: 'admin:delete' },
  { method: 'PATCH',  path: '/api/admin/users/:id/state',           permission: 'admin:update' },
  { method: 'PATCH',  path: '/api/admin/users/:id/metadata',        permission: 'admin:update' },
  { method: 'PATCH',  path: '/api/admin/users/:id/organization',    permission: 'admin:update' },
  { method: 'GET',    path: '/api/admin/users/:id/sessions',        permission: 'admin:read' },
  { method: 'DELETE', path: '/api/admin/users/:id/sessions',        permission: 'admin:delete' },
  { method: 'DELETE', path: '/api/admin/sessions/:sessionId',       permission: 'admin:delete' },
  { method: 'GET',    path: '/api/admin/users/:email/groups',       permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/users/:email/groups',       permission: 'admin:update' },
  { method: 'POST',   path: '/api/admin/users/:id/recovery-email',  permission: 'admin:update' },

  // RBAC management
  { method: 'GET',    path: '/api/admin/rbac/users',                permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/rbac/groups',               permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/rbac/groups',               permission: 'admin:create' },
  { method: 'PUT',    path: '/api/admin/rbac/groups/:name',         permission: 'admin:update' },
  { method: 'DELETE', path: '/api/admin/rbac/groups/:name',         permission: 'admin:delete' },
  { method: 'GET',    path: '/api/admin/rbac/services',             permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/rbac/services',             permission: 'admin:create' },
  { method: 'DELETE', path: '/api/admin/rbac/services/:name',       permission: 'admin:delete' },
  { method: 'GET',    path: '/api/admin/rbac/services/:name/roles', permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/rbac/services/:name/routes', permission: 'admin:update' },
  { method: 'GET',    path: '/api/admin/rbac/access-rules',         permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/rbac/access-rules',         permission: 'admin:create' },
  { method: 'PUT',    path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:update' },
  { method: 'DELETE', path: '/api/admin/rbac/access-rules/:id',     permission: 'admin:delete' },
  { method: 'POST',   path: '/api/admin/rbac/simulate',             permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/rbac/history',              permission: 'admin:read' },

  // Audit
  { method: 'GET',    path: '/api/admin/audit/:any*',               permission: 'admin:read' },

  // Organization users
  { method: 'GET',    path: '/api/organizations/:organizationId/users',     permission: 'admin:read' },
  { method: 'POST',   path: '/api/organizations/:organizationId/users',     permission: 'admin:create' },
  { method: 'GET',    path: '/api/organizations/:organizationId/users/:id', permission: 'admin:read' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id', permission: 'admin:update' },
  { method: 'DELETE', path: '/api/organizations/:organizationId/users/:id', permission: 'admin:delete' },
] as const
