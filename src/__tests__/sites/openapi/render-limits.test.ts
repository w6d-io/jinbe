import { describe, it, expect, beforeEach } from 'vitest'
import { render, MATCH_URL_MAX } from '../../../sites/render.js'
import { siteSchema, type Route } from '../../../sites/schemas.js'
import { resetSitesConfig } from '../../../sites/config.js'
import { payrollSite, platform } from '../fixtures.js'

// W2: the limits an import can hit. A gate's match URL longer than the Site CRD allows (4096) is a
// render error at save, not an API-server refusal at apply; the route count is SITES_MAX_ROUTES.

const route = (i: number, gate: string): Route => ({ id: `r${i}`, methods: ['GET'], path: `/api/some-rather-long-resource-name-${i}/:id`, gate, access: gate === 'public' ? { kind: 'public' } : { kind: 'permission', permission: 'x:read' }, source: 'openapi', op: `op${i}` })

describe('match_url_too_long', () => {
  it('is an error once an enumerated gate outgrows the CRD limit', () => {
    const site = payrollSite()
    site.routes.items = Array.from({ length: 150 }, (_, i) => route(i, 'public'))
    const checks = render(site, platform).checks
    const long = checks.find((c) => c.code === 'match_url_too_long')
    expect(long).toMatchObject({ level: 'error', path: 'routes' })
    expect(render(site, platform).siteCr.spec.gates.some((g) => g.match.url.length > MATCH_URL_MAX)).toBe(true)
  })

  it('routes on the catch-all gate cost no pattern at all', () => {
    const site = payrollSite()
    site.routes.items = Array.from({ length: 1000 }, (_, i) => route(i, 'web'))
    const rendered = render(site, platform)
    expect(rendered.checks.find((c) => c.code === 'match_url_too_long')).toBeUndefined()
    expect(rendered.routeMap.length).toBeGreaterThan(1000)
  })
})

describe('SITES_MAX_ROUTES', () => {
  beforeEach(() => {
    delete process.env.SITES_MAX_ROUTES
    resetSitesConfig()
  })

  it('defaults to 500 and may be raised to 2000, never past it', () => {
    const site = (n: number) => ({ ...payrollSite(), routes: { ...payrollSite().routes, items: Array.from({ length: n }, (_, i) => route(i, 'web')) } })
    expect(siteSchema.safeParse(site(500)).success).toBe(true)
    expect(siteSchema.safeParse(site(501)).success).toBe(false)
    process.env.SITES_MAX_ROUTES = '2000'
    resetSitesConfig()
    expect(siteSchema.safeParse(site(2000)).success).toBe(true)
    expect(siteSchema.safeParse(site(2001)).success).toBe(false)
  })

  it('login.twoFactor.routes follows SITES_MAX_ROUTES', () => {
    const site = (n: number) => ({ ...payrollSite(), login: { twoFactor: { scope: 'routes', routes: Array.from({ length: n }, (_, i) => `r${i}`), clients: 'exempt' }, reach: 'granted' } })
    expect(siteSchema.safeParse(site(500)).success).toBe(true)
    expect(siteSchema.safeParse(site(501)).success).toBe(false)
    process.env.SITES_MAX_ROUTES = '2000'
    resetSitesConfig()
    expect(siteSchema.safeParse(site(2000)).success).toBe(true)
    expect(siteSchema.safeParse(site(2001)).success).toBe(false)
  })

  it('accepts the import fields: op on a route, routes.openapi', () => {
    const site = payrollSite()
    const parsed = siteSchema.safeParse({ ...site, routes: { ...site.routes, openapi: { sha256: 'a'.repeat(64), title: 't', version: '1', source: 'upload', importedAt: '2026-09-28T10:00:00.000Z', importedBy: 'sam@x.test' } } })
    expect(parsed.success).toBe(true)
  })
})
