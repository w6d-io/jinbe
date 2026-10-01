import { describe, it, expect, beforeEach } from 'vitest'
import Fastify from 'fastify'
import { attachRouteAccess, installRouteAccess, RouteAccessError } from '../../policy/route-access.js'
import { declaredRoute, enforcedBy, enforcing, resetDeclaredRoutes } from '../../policy/declared-routes.js'
import { requireRecentMfa } from '../../middleware/require-admin.js'

const open = (p: string) => p === '/api/health'
const route = (over: Record<string, unknown>) => ({ method: 'GET', url: '/api/x', ...over }) as Parameters<typeof attachRouteAccess>[0]
const chain = (r: { preHandler?: unknown }) => [r.preHandler].flat().filter((h) => h !== undefined) as unknown[]

beforeEach(() => resetDeclaredRoutes())

describe('the route-access hook refuses to boot on an undecided route', () => {
  it.each([
    ['no declaration', {}, /declares neither/],
    ['both', { config: { permission: 'users:read', access: 'self' } }, /both/],
    ['a name outside the catalogue', { config: { permission: 'admin:read' } }, /not in the catalogue/],
    ['an unknown access', { config: { access: 'everyone' } }, /unknown access/],
    ['public off the bypass list', { config: { access: 'public' } }, /session gate/],
    ['an own guard enforcing something else', { config: { permission: 'users:read' }, preHandler: enforcing(async () => {}, 'users:delete') }, /its own guard enforces 'users:delete'/],
    ['an org param not in the path', { config: { permission: 'org.keys:read', org: 'organizationId' } }, /not a parameter/],
  ])('%s', (_label, over, message) => {
    expect(() => attachRouteAccess(route(over), open)).toThrow(RouteAccessError)
    expect(() => attachRouteAccess(route(over), open)).toThrow(message)
  })

  it('fails the whole Fastify boot, not just one request', () => {
    const app = Fastify()
    installRouteAccess(app)
    expect(() => app.get('/api/undeclared', async () => ({}))).toThrow(/declares neither/)
  })

  it('lets the API documentation through undeclared (a plugin that takes no route options)', () => {
    expect(() => attachRouteAccess(route({ url: '/docs/json' }), open)).not.toThrow()
    expect(declaredRoute('GET', '/docs/json')).toMatchObject({ access: 'public' })
  })
})

describe('it attaches the gate the declaration names', () => {
  it("the catalogue guard, then the route's own, then the step-up the catalogue asks for", () => {
    const own = async () => {}
    const r = route({ method: 'DELETE', config: { permission: 'users:delete' }, preHandler: own })
    attachRouteAccess(r, open)
    const [gate, mine, stepUp] = chain(r)
    expect(enforcedBy(gate)).toBe('users:delete')
    expect(mine).toBe(own)
    expect(stepUp).toBe(requireRecentMfa)
    expect(declaredRoute('DELETE', '/api/x')).toEqual({ method: 'DELETE', path: '/api/x', class: 'authorized', permission: 'users:delete', stepUp: true })
  })

  it('no step-up where the catalogue asks none, unless the route adds one', () => {
    const plain = route({ config: { permission: 'recert:manage' } })
    attachRouteAccess(plain, open)
    expect(chain(plain)).toHaveLength(1)
    const extra = route({ url: '/api/y', config: { permission: 'recert:manage', stepUp: true } })
    attachRouteAccess(extra, open)
    expect(chain(extra)[1]).toBe(requireRecentMfa)
  })

  it('`*` is no permission at all: the boot refuses it', () => {
    expect(() => attachRouteAccess(route({ config: { permission: '*' } }), open)).toThrow(/not in the catalogue/)
  })

  it('a route with its own guard for the same permission keeps it and gets no second one', () => {
    const own = enforcing(async () => {}, 'audit:read')
    const r = route({ config: { permission: 'audit:read' }, preHandler: own })
    attachRouteAccess(r, open)
    expect(chain(r)).toEqual([own])
  })

  it('an org-scoped route gets the org gate, never a platform guard; scope must match the shape', () => {
    const r = route({ url: '/api/organizations/:organizationId/x', config: { permission: 'org.members:read', org: 'organizationId' } })
    attachRouteAccess(r, open)
    expect(chain(r)).toHaveLength(1)
    expect(enforcedBy(chain(r)[0])).toBeNull()
    expect(() => attachRouteAccess(route({ url: '/api/y', config: { permission: 'org.members:read' } }), open)).toThrow(/org permission/)
    expect(() => attachRouteAccess(route({ url: '/api/organizations/:organizationId/z', config: { permission: 'users:read', org: 'organizationId' } }), open)).toThrow(/platform permission/)
    expect(declaredRoute('GET', '/api/organizations/:organizationId/x')).toMatchObject({ permission: 'org.members:read', org: 'organizationId' })
  })

  it('an access declaration attaches nothing and says why in the table', () => {
    const r = route({ config: { access: 'self' } })
    attachRouteAccess(r, open)
    expect(chain(r)).toEqual([])
    expect(declaredRoute('GET', '/api/x')).toEqual({ method: 'GET', path: '/api/x', class: 'authenticated', access: 'self' })
  })

  it('never mutates a preHandler array shared between routes', () => {
    const shared = [async () => {}]
    attachRouteAccess(route({ url: '/api/a', config: { permission: 'sites:write' }, preHandler: shared }), open)
    expect(shared).toHaveLength(1)
  })
})
