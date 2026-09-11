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

describe('a gate put on a whole plugin', () => {
  beforeEach(() => resetDeclaredRoutes())

  it('is recorded, which a root-level collector alone cannot see', async () => {
    const { guardAll } = await import('../../policy/declared-routes.js')
    const gate = enforcing(async () => {}, 'admin:read')
    let onRoute: ((r: { method: string; url: string; preHandler?: unknown }) => void) | null = null
    const fastify = {
      addHook: (name: string, fn: unknown) => { if (name === 'onRoute') onRoute = fn as never },
    }
    guardAll(fastify as never, gate, never)
    // Fastify reports only PER-ROUTE handlers to an onRoute hook, so the gate a plugin puts on all
    // of its routes was enforced and invisible at the same time.
    onRoute!({ method: 'GET', url: '/api/admin/users' })
    expect(declaredRoutes()[0]).toEqual({
      method: 'GET', path: '/api/admin/users', class: 'authorized', permission: 'admin:read',
    })
  })

  it('does not let a blinder sighting overwrite one that found the permission', () => {
    recordRoute('GET', '/api/admin/users', [enforcing(async () => {}, 'admin:read')], never)
    // The root collector sees the same route with no per-route guard. Letting it win would describe
    // a guarded route as merely authenticated.
    recordRoute('GET', '/api/admin/users', [], never)
    expect(declaredRoutes()[0].class).toBe('authorized')
    expect(declaredRoutes()[0].permission).toBe('admin:read')
  })
})

describe('what the running service ends up declaring', () => {
  it('covers the administration API rather than a handful of routes', async () => {
    // Guarded against the failure that shipped once already: the gate was attached by a plugin
    // hook, `onRoute` on the root instance could not see it, and the table came out EMPTY while
    // every one of those routes was in fact enforced. A count is what catches that.
    process.env.NODE_ENV = 'development'
    process.env.DEV_BYPASS_AUTH = 'true'
    process.env.ENCRYPTION_KEY = 'x'.repeat(32)
    process.env.DEV_USER_EMAIL = 'dev@localhost.io'
    resetDeclaredRoutes()

    const { buildServer } = await import('../../server.js')
    const app = await buildServer()
    try {
      const rows = declaredRoutes()
      const authorized = rows.filter((r) => r.class === 'authorized')
      expect(authorized.length).toBeGreaterThan(80)
      expect(rows.find((r) => r.path === '/api/admin/users' && r.method === 'GET')).toEqual({
        method: 'GET', path: '/api/admin/users', class: 'authorized', permission: 'admin:read',
      })
      // The session gate is a hook, not a route guard, so these must not be called authorized.
      expect(rows.find((r) => r.path === '/api/health')?.class).toBe('public')
      expect(rows.find((r) => r.path === '/api/telemetry')?.class).toBe('public')
    } finally {
      await app.close()
    }
  }, 30_000)
})
