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

  it('every route has unique (method, path) tuple', () => {
    const keys = JINBE_BUILT_IN_ROUTES.map((r) => `${r.method}:${r.path}`)
    expect(new Set(keys).size).toBe(keys.length)
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
