import { describe, it, expect } from 'vitest'
import { JINBE_BUILT_IN_ROUTES } from '../../bootstrap/build-route-map.js'

describe('bootstrap/build-route-map', () => {
  it('contains the public health/whoami/docs routes without permission', () => {
    const publicRoutes = JINBE_BUILT_IN_ROUTES.filter((r) => !r.permission)
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/api/health' })
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/api/whoami' })
    expect(publicRoutes).toContainEqual({ method: 'GET', path: '/docs/:any*' })
  })

  it('admin user-management routes require admin or user-management permissions', () => {
    const adminRoutes = JINBE_BUILT_IN_ROUTES.filter((r) =>
      r.path.startsWith('/api/admin/users'),
    )
    for (const r of adminRoutes) {
      expect(r.permission).toMatch(/^(admin|users|sessions):/)
    }
  })

  it('user routes carry their fine permission BESIDE the admin:* rule, never instead of it', () => {
    const fine: Array<[string, string, string]> = [
      ['GET', '/api/admin/users', 'users:read'],
      ['GET', '/api/admin/users/search', 'users:read'],
      ['GET', '/api/admin/users/:id', 'users:read'],
      ['POST', '/api/admin/users', 'users:create'],
      ['PUT', '/api/admin/users/:id', 'users:update'],
      ['PUT', '/api/admin/users/:id', 'users:update_email'],
      ['DELETE', '/api/admin/users/:id', 'users:delete'],
      ['PUT', '/api/admin/users/:email/groups', 'users:assign_group'],
      ['GET', '/api/admin/users/:id/sessions', 'sessions:read'],
      ['DELETE', '/api/admin/users/:id/sessions', 'sessions:revoke'],
      ['DELETE', '/api/admin/sessions/:sessionId', 'sessions:revoke'],
      ['POST', '/api/admin/users/:id/recovery-email', 'users:recovery'],
      ['POST', '/api/admin/users/:id/login-link', 'users:send_login_link'],
    ]
    for (const [method, path, permission] of fine) {
      expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method, path, permission })
      // Administrators keep the route: an admin:* rule stays on the same method + path.
      expect(JINBE_BUILT_IN_ROUTES.some((r) => r.method === method && r.path === path && r.permission?.startsWith('admin:'))).toBe(true)
    }
    expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method: 'GET', path: '/api/me/permissions' })
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
  it('every /api/organizations/:organizationId route names its org param (J-1)', () => {
    const orgRoutes = JINBE_BUILT_IN_ROUTES.filter((r) => r.path.startsWith('/api/organizations/'))
    expect(orgRoutes.length).toBeGreaterThan(0)
    for (const r of orgRoutes) expect(r.org_param).toBe('organizationId')
    // Nothing outside the org tree claims one.
    for (const r of JINBE_BUILT_IN_ROUTES.filter((x) => !x.path.startsWith('/api/organizations/'))) {
      expect(r.org_param).toBeUndefined()
    }
  })

  it('declares the API-key routes with org:manage_api_keys and org_param (J-3)', () => {
    const base = '/api/organizations/:organizationId/api-keys'
    for (const [method, path] of [['GET', base], ['POST', base], ['GET', `${base}/:clientId`], ['DELETE', `${base}/:clientId`]]) {
      expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method, path, permission: 'org:manage_api_keys', org_param: 'organizationId' })
    }
  })

  it('declares the grant routes (org admin) and the admin access view (J-1)', () => {
    const org = '/api/organizations/:organizationId'
    expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method: 'GET', path: `${org}/grants`, permission: 'org:manage_users', org_param: 'organizationId' })
    expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method: 'PUT', path: `${org}/users/:id/grants`, permission: 'org:manage_users', org_param: 'organizationId' })
    expect(JINBE_BUILT_IN_ROUTES).toContainEqual({ method: 'GET', path: '/api/admin/users/:id/access', permission: 'admin:read' })
  })
})
