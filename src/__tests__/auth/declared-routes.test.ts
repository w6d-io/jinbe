import { describe, it, expect, beforeEach } from 'vitest'
import { enforcing, enforcedBy, recordRoute, declaredRoutes, resetDeclaredRoutes } from '../../policy/declared-routes.js'

const never = () => false
const publicPaths = (p: string) => p === '/api/health'

describe('a guard says what it enforces', () => {
  it('carries the permission, and the marking does not show up as data', () => {
    const guard = enforcing(async () => {}, 'admin:read')
    expect(enforcedBy(guard)).toBe('admin:read')
    // Non-enumerable: a guard must not start serialising itself into a response body.
    expect(Object.keys(guard)).toEqual([])
    expect(JSON.stringify({ guard })).toBe('{}')
  })

  it('answers null for anything that is not one of ours', () => {
    for (const other of [undefined, null, async () => {}, {}, 'admin:read', 42]) {
      expect(enforcedBy(other)).toBeNull()
    }
  })
})

describe('the table collected from the guards', () => {
  beforeEach(() => resetDeclaredRoutes())

  it('reads the permission off the guard rather than being told it', () => {
    recordRoute('GET', '/api/admin/users', [enforcing(async () => {}, 'admin:read')], never)
    expect(declaredRoutes()).toEqual([
      { method: 'GET', path: '/api/admin/users', class: 'authorized', permission: 'admin:read' },
    ])
  })

  it('finds the guard wherever in the chain it sits', () => {
    recordRoute('PUT', '/x', [async () => {}, enforcing(async () => {}, 'admin:write')], never)
    expect(declaredRoutes()[0].permission).toBe('admin:write')
  })

  it('records every verb a route is registered for', () => {
    recordRoute(['GET', 'HEAD'], '/x', [enforcing(async () => {}, 'admin:read')], never)
    expect(declaredRoutes().map((r) => r.method)).toEqual(['GET', 'HEAD'])
  })

  it('calls an unguarded route authenticated, never public', () => {
    // The session gate runs before every route. "Public" would be the comfortable reading and the
    // wrong one: it would describe a guarded route as open to anyone.
    recordRoute('GET', '/api/admin/stats', [], never)
    expect(declaredRoutes()[0]).toEqual({ method: 'GET', path: '/api/admin/stats', class: 'authenticated' })
  })

  it('calls public only what this service answers with no credential at all', () => {
    recordRoute('GET', '/api/health', [], publicPaths)
    expect(declaredRoutes()[0].class).toBe('public')
  })

  it('replaces a route rather than listing it twice when registration repeats', () => {
    recordRoute('GET', '/x', [enforcing(async () => {}, 'admin:read')], never)
    recordRoute('GET', '/x', [enforcing(async () => {}, 'admin:write')], never)
    expect(declaredRoutes()).toHaveLength(1)
    expect(declaredRoutes()[0].permission).toBe('admin:write')
  })

  it('orders rows so a diff between two versions is readable', () => {
    recordRoute('POST', '/b', [], never)
    recordRoute('GET', '/a', [], never)
    recordRoute('DELETE', '/a', [], never)
    expect(declaredRoutes().map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /a', 'GET /a', 'POST /b'])
  })
})
