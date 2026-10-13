import { describe, it, expect, beforeEach, vi } from 'vitest'
import Fastify from 'fastify'
import { payrollSite } from './fixtures.js'
import type { Site } from '../../sites/schemas.js'

// Sites by address (Sites redesign, phase 1): the sites grouped by host, each host listing the services
// mounted on it — nesting, backend, page or API, access at a glance, waiting work, shared backends — and,
// for one host, every route with the path its backend receives. A reading: nothing is merged or saved.

const h = vi.hoisted(() => ({
  records: [] as Array<Record<string, unknown>>,
  drafts: [] as Array<{ name: string; draft: Record<string, unknown> }>,
  pending: [] as Array<{ site: string }>,
}))

vi.mock('../../sites/repository.js', async (orig) => ({
  ...(await orig<object>()),
  sitesRepository: { list: async () => h.records, drafts: async () => h.drafts },
}))
vi.mock('../../sites/requests.js', () => ({ listRequests: async () => h.pending }))
vi.mock('../../sites/platform.js', async (orig) => ({
  ...(await orig<object>()),
  loadZones: async () => [{ suffix: 'dev.example.com', wildcardTls: true }],
}))

import { accessSummaryOf, backendPathOf, getHost, kindOf, listHosts } from '../../sites/hosts.js'

const HOST = 'shell.dev.example.com'
const api = (id: string) => ({ id, label: 'API', authenticators: [{ handler: 'oauth2_introspection' }], authorizer: 'policy' as const, mutators: [{ handler: 'header' }], errors: 'api' as const })
const at = (name: string, pathPrefix: string | undefined, over: Partial<Site> = {}): Site =>
  payrollSite({ name, displayName: name, address: { host: HOST, ...(pathPrefix ? { pathPrefix } : {}) }, ...over })
const record = (site: Site, applied = true) => ({ site, version: 1, etag: 'e', savedAt: 't', savedBy: 'x', ...(applied ? { applied: { version: 1, at: 't', by: 'x', rules: [] } } : {}) })

beforeEach(() => {
  h.records = []
  h.drafts = []
  h.pending = []
})

describe('the path a backend receives', () => {
  it('strips strip_path, then puts upstream.path in front, as the gateway forwards it', () => {
    expect(backendPathOf('/api/v1/earnings/days', { stripPath: '/api/v1', path: '/api/external' })).toBe('/api/external/earnings/days')
    expect(backendPathOf('/api/earnings/persons/:personId', { stripPath: '/api/v1' })).toBe('/api/earnings/persons/:personId')
    expect(backendPathOf('/x', { path: '/base/' })).toBe('/base/x')
    expect(backendPathOf('/x', null)).toBe('/x')
  })
})

describe('what a service is', () => {
  it('an API when every gate its routes use answers in JSON; a page otherwise', () => {
    expect(kindOf(payrollSite())).toBe('page')
    const apiOnly = payrollSite({ gates: [api('api')], routes: { items: [{ id: 'days', methods: ['GET'], path: '/days', gate: 'api', access: { kind: 'permission', permission: 'earnings.external:read' }, source: 'manual' }], catchAll: { gate: 'api', access: { kind: 'deny' } } } })
    expect(kindOf(apiOnly)).toBe('api')
  })

  it('sums up who may reach it: public, any signed-in account, the permissions asked, organization keys', () => {
    expect(accessSummaryOf(payrollSite())).toEqual({ public: true, signedIn: true, permissions: ['payslips:create', 'payslips:read'], orgKeys: false })
    const keys = payrollSite({ gates: [api('api')], routes: { items: [], catchAll: { gate: 'api', access: { kind: 'permission', permission: 'x.y:read' } } }, organizations: { enabled: true } })
    expect(accessSummaryOf(keys)).toMatchObject({ public: false, signedIn: false, permissions: ['x.y:read'], orgKeys: true })
  })
})

describe('GET /hosts', () => {
  it('groups by host, nests by the longest prefix, flags drafts, requests and shared backends', async () => {
    h.records = [
      record(at('shell', undefined)),
      record(at('cab', '/cab')),
      record(at('cab-pricing', '/cab/api/pricing', { upstream: { service: 'pricing', namespace: 'stairling', port: 80 } })),
      record(payrollSite({ name: 'other', displayName: 'Other', address: { host: 'other.dev.example.com' } }), false),
    ]
    h.drafts = [{ name: 'cab', draft: { site: { ...at('cab', '/cab'), displayName: 'Cab (edited)' }, baseVersion: 1, updatedBy: 'x' } }]
    h.pending = [{ site: 'cab-pricing' }]
    const list = await listHosts()
    expect(list.map((x) => x.host)).toEqual(['other.dev.example.com', HOST])
    const shell = list.find((x) => x.host === HOST)!
    expect(shell.zone).toBe('dev.example.com')
    expect(shell.services.map((s) => [s.site, s.pathPrefix, s.parent])).toEqual([['shell', null, null], ['cab', '/cab', 'shell'], ['cab-pricing', '/cab/api/pricing', 'cab']])
    expect(shell.services.find((s) => s.site === 'cab')).toMatchObject({ draft: true, status: 'live' })
    expect(shell.services.find((s) => s.site === 'cab-pricing')).toMatchObject({ pendingRequest: true, sharedBackendWith: [] })
    // shell and cab reach the same backend (payroll.payroll) as the site on the other host.
    expect(shell.services.find((s) => s.site === 'shell')!.sharedBackendWith).toEqual(['cab', 'other'])
    expect(shell.counts).toEqual({ services: 3, live: 3, drafts: 1, pendingRequests: 1 })
    expect(list.find((x) => x.host === 'other.dev.example.com')!.services[0].status).toBe('draft')
  })

  it('lists a never-saved draft under the host it names; one without a host is left out', async () => {
    h.drafts = [
      { name: 'fresh', draft: { site: at('fresh', '/fresh'), baseVersion: 0, updatedBy: 'x' } },
      { name: 'half', draft: { site: { displayName: 'Half' }, baseVersion: 0, updatedBy: 'x' } },
    ]
    const list = await listHosts()
    expect(list).toHaveLength(1)
    expect(list[0].services[0]).toMatchObject({ site: 'fresh', status: 'draft', draft: true })
  })
})

describe('GET /hosts/detail?host=', () => {
  it('gives each route and the catch-all with the path its backend receives', async () => {
    h.records = [record(at('earnings', undefined, { upstream: { service: 'earning-service', namespace: 'stairling', port: 80, stripPath: '/api/v1', path: '/api/external' } }))]
    const one = await getHost(HOST.toUpperCase())
    const svc = one.services[0]
    expect(svc.routes.find((r) => r.id === 'payslips')).toMatchObject({ path: '/api/orgs/:orgId/payslips', backendPath: '/api/external/api/orgs/:orgId/payslips' })
    expect(svc.catchAll).toMatchObject({ access: { kind: 'signed-in' }, backendPath: '/api/external/…' })
  })

  it('is 404 for a host no site is on', async () => {
    await expect(getHost('nope.dev.example.com')).rejects.toMatchObject({ statusCode: 404 })
  })

  it('the routes ask sites:read; the host is a query parameter (a path ending in .com is refused by the WAF)', async () => {
    const { sitesRoutes } = await import('../../sites/routes.js')
    const { declaredRoutes, resetDeclaredRoutes } = await import('../../policy/declared-routes.js')
    const { installRouteAccess } = await import('../../policy/route-access.js')
    resetDeclaredRoutes()
    const app = Fastify()
    installRouteAccess(app)
    await app.register(sitesRoutes, { prefix: '/api/admin/sites' })
    await app.ready()
    const perm = (path: string) => declaredRoutes().find((r) => r.method === 'GET' && r.path === `/api/admin/sites${path}`)?.permission
    expect(perm('/hosts')).toBe('sites:read')
    expect(perm('/hosts/detail')).toBe('sites:read')
    expect(perm('/hosts/:host')).toBeUndefined()
    await app.close()
  })
})
