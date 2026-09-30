import { describe, it, expect, beforeEach } from 'vitest'
import Fastify from 'fastify'
import { patternFor, recordRouteContext, resetRouteContexts, routeChain } from '../../policy/route-guards.js'
import { installRouteAccess, needs } from '../../policy/route-access.js'

// The explainer reads a route's guards off Fastify (the instance's hooks + the route's own), and
// resolves a path to its pattern with the params the router found.

beforeEach(() => resetRouteContexts())

describe('patternFor', () => {
  const at = (url: string) => recordRouteContext({}, { method: 'GET', url })

  it('prefers the static segment, as the router does, and needs the router’s params to agree', () => {
    at('/api/admin/users/:id')
    at('/api/admin/users/search')
    expect(patternFor('GET', '/api/admin/users/search', {})).toBe('/api/admin/users/search')
    expect(patternFor('GET', '/api/admin/users/u-1', { id: 'u-1' })).toBe('/api/admin/users/:id')
    expect(patternFor('GET', '/api/admin/users/u-1', { other: 'u-1' })).toBeNull()
    expect(patternFor('POST', '/api/admin/users/u-1', { id: 'u-1' })).toBeNull()
  })

  it('HEAD resolves to the GET route', () => {
    at('/api/health')
    expect(patternFor('HEAD', '/api/health', {})).toBe('/api/health')
  })
})

describe('routeChain', () => {
  it("lists the instance's preHandlers (global, then the plugin's) before the route's own", async () => {
    const app = Fastify()
    installRouteAccess(app)
    async function globalGuard() {}
    async function pluginGuard() {}
    async function ownGuard() {}
    app.addHook('preHandler', globalGuard)
    await app.register(async (plugin) => {
      plugin.addHook('preHandler', pluginGuard)
      plugin.get('/x', { ...needs('stats:read'), preHandler: ownGuard }, async () => ({}))
    }, { prefix: '/api' })
    await app.ready()
    const chain = routeChain('GET', '/api/x')!
    expect(chain.complete).toBe(true)
    expect(chain.preHandler.map((h) => h.name)).toEqual(['globalGuard', 'pluginGuard', 'requirePermission', 'ownGuard'])
    expect(chain.config).toMatchObject({ permission: 'stats:read' })
    await app.close()
  })
})
