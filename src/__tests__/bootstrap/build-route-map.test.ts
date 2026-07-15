import { describe, it, expect } from 'vitest'
import { JINBE_BUILT_IN_ROUTES } from '../../bootstrap/build-route-map.js'

describe('bootstrap/build-route-map', () => {
  it('contains the public health/whoami/docs routes without permission', () => {
    const publicRoutes = JINBE_BUILT_IN_ROUTES.filter((r) => !r.permission)
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/api/health' })
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/api/whoami' })
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/docs/:any*' })
  })

  it('admin user-management routes require admin permissions', () => {
    const adminRoutes = JINBE_BUILT_IN_ROUTES.filter((r) =>
      r.path.startsWith('/api/admin/users'),
    )
    for (const r of adminRoutes) {
      expect(r.permission).toMatch(/^admin:/)
    }
  })

  it('rbac management routes require admin permissions', () => {
    const rbacRoutes = JINBE_BUILT_IN_ROUTES.filter((r) =>
      r.path.startsWith('/api/admin/rbac'),
    )
    for (const r of rbacRoutes) {
      expect(r.permission).toMatch(/^admin:/)
    }
  })

  it('recovery-email route is included with admin:update', () => {
    const recovery = JINBE_BUILT_IN_ROUTES.find(
      (r) => r.method === 'POST' && r.path === '/api/admin/users/:id/recovery-email',
    )
    expect(recovery).toBeDefined()
    expect(recovery?.permission).toBe('admin:update')
  })

  it('every route has a unique (method, path, permission) tuple', () => {
    // A method+path MAY appear more than once with DIFFERENT permissions (e.g.
    // the org-user endpoints carry both a legacy admin:* rule and a delegated
    // org:manage_users rule); OPA allows if the caller satisfies ANY matching
    // rule. The full tuple must still be unique — no exact-duplicate rules.
    const keys = JINBE_BUILT_IN_ROUTES.map((r) => `${r.method}:${r.path}:${r.permission ?? ''}`)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('org-user endpoints carry an org:manage_users delegation rule alongside admin:*', () => {
    const orgManage = JINBE_BUILT_IN_ROUTES.filter((r) => r.permission === 'org:manage_users')
    // GET/POST/PUT/DELETE users, GET/PUT users/:id/groups, GET assignable-groups
    expect(orgManage.length).toBeGreaterThanOrEqual(8)
    expect(orgManage.every((r) => r.path.startsWith('/api/organizations/:organizationId/'))).toBe(true)
  })

  it('cluster CRUD routes are gated by clusters:* permissions', () => {
    const clusterCrud = JINBE_BUILT_IN_ROUTES.filter(
      (r) => r.path === '/api/clusters' || r.path === '/api/clusters/:id',
    )
    for (const r of clusterCrud) {
      expect(r.permission).toMatch(/^clusters:/)
    }
  })
})
