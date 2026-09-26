import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import rateLimit from '@fastify/rate-limit'
import { payrollSite, platform } from './fixtures.js'
import { fakeGatekit } from './mocks.js'

// S-4a / S-4: per-site login. Route-map rows carry the route id; data.site_login[<site>] is
// published with the permissions; the public branding lookup is exact-host only; the logo is a
// strictly checked PNG/WebP; browser gates of a 2FA site send `forbidden` to login-ui /access,
// which asks jinbe why (access-reason) with the visitor's own session.

const h = vi.hoisted(() => ({
  kube: { ping: vi.fn(), get: vi.fn(async () => null), apply: vi.fn(), delete: vi.fn(), listZones: vi.fn() },
  gatekit: {
    compile: (patterns: Array<{ id: string }>) => ({ results: patterns.map((p) => ({ id: p.id, ok: true })) }) as unknown,
    overlap: (_b: unknown) => ({ overlaps: [] }) as unknown,
    status: 200,
    calls: [] as Array<{ path: string; body: Record<string, unknown> }>,
  },
  session: vi.fn(),
  opa: vi.fn(),
}))

vi.mock('../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('./mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../services/redis-rbac.repository.js', async () => {
  const { makeRbacStore } = await import('./mocks.js')
  const store = makeRbacStore()
  return { redisRbacRepository: store.repo, __store: store }
})
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { invalidateBundle: vi.fn() } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn() } }))
vi.mock('../../services/kratos-session.service.js', async (orig) => {
  const real = await orig<typeof import('../../services/kratos-session.service.js')>()
  return { ...real, kratosSessionService: { validateSession: h.session } }
})
vi.mock('../../services/opa-client.js', async (orig) => {
  const real = await orig<typeof import('../../services/opa-client.js')>()
  return { ...real, queryOpa: h.opa }
})
vi.mock('../../middleware/require-admin.js', () => ({
  requireSuperAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireSitesApply: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireRecentMfa: async () => {},
}))

import { render } from '../../sites/render.js'
import { siteLoginOf } from '../../sites/login.js'
import { sitesRoutes } from '../../sites/routes.js'
import { publicSitesRoutes } from '../../sites/public.routes.js'
import { setKubeSites } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import * as redisClient from '../../services/redis-client.service.js'
import * as rbacRepo from '../../services/redis-rbac.repository.js'
import type { Site } from '../../sites/schemas.js'

type Store = ReturnType<typeof import('./mocks.js').makeRbacStore>
const store = (rbacRepo as unknown as { __store: Store }).__store
const redis = (redisClient as unknown as { __redis: import('./mocks.js').InlineRedisMock }).__redis
const W = { 'x-test-write': '1' }

const twoFactor = (scope: 'none' | 'writes' | 'all' | 'routes', routes?: string[]): Site => payrollSite({
  login: {
    twoFactor: { scope, clients: 'refused', ...(routes ? { routes } : {}) },
    reach: 'granted',
    branding: { name: 'Payroll HQ', accent: '#1A2B3C', welcome: 'Hello', helpUrl: 'https://help.example.com/' },
  },
})

const PNG = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.from([0, 0, 0, 13]), Buffer.from('IHDR'), Buffer.from([0, 0, 0, 16, 0, 0, 0, 16, 8, 6, 0, 0, 0]), Buffer.alloc(4),
  Buffer.from([0, 0, 0, 0]), Buffer.from('IEND'), Buffer.alloc(4),
])

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  await app.register(rateLimit, { global: false })
  app.addHook('onRequest', async (request) => {
    if (request.url.startsWith('/sites')) request.userContext = { id: 'sam', email: 'sam@x.test', name: 'Sam' }
  })
  await app.register(sitesRoutes, { prefix: '/sites' })
  await app.register(publicSitesRoutes, { prefix: '/api/public/sites' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  redis.clear()
  store.reset()
  process.env.GATEKIT_URL = 'http://gatekit:8080'
  process.env.SITES_KUBE = 'off'
  process.env.SITES_ZONES = '[{"suffix":"dev.stairling.com","wildcardTls":true}]'
  process.env.SITES_COOKIE_DOMAIN = '.dev.stairling.com'
  process.env.SITES_APPLY_POLL_MS = '0'
  process.env.SITES_PUBLIC_RATE_LIMIT = '1000'
  process.env.SITES_ACCESS_URL = 'https://auth.dev.stairling.com/access'
  resetSitesConfig()
  h.kube.apply.mockImplementation(async () => {})
  setKubeSites(h.kube)
  h.session.mockReset()
  h.opa.mockReset()
  vi.stubGlobal('fetch', fakeGatekit(h.gatekit))
})

async function saveAndApply(site: Site) {
  const put = await app.inject({ method: 'PUT', url: `/sites/${site.name}`, headers: W, payload: { site } })
  expect(put.statusCode).toBe(200)
  const res = await app.inject({ method: 'POST', url: `/sites/${site.name}/apply`, headers: W, payload: { version: put.json().version } })
  expect(res.statusCode).toBe(200)
}

describe('S-4a — route ids and data.site_login', () => {
  it('every route-map row carries its route id; the catch-all is "catch-all"', () => {
    const { routeMap } = render(payrollSite(), platform)
    expect(routeMap.slice(0, 3).map((r) => r.id)).toEqual(['health', 'payslips', 'create'])
    expect(routeMap.slice(3).every((r) => r.id === 'catch-all')).toBe(true)
  })

  it('site_login is null when 2FA is off, the policy shape otherwise', () => {
    expect(siteLoginOf(payrollSite())).toBeNull()
    expect(siteLoginOf(twoFactor('none'))).toBeNull()
    expect(siteLoginOf(twoFactor('writes'))).toEqual({ min_aal: 'aal2', scope: 'writes', routes: [], clients: 'refused' })
    expect(siteLoginOf(twoFactor('routes', ['create']))).toEqual({ min_aal: 'aal2', scope: 'routes', routes: ['create'], clients: 'refused' })
  })

  it('refuses a 2FA route pick naming no route', () => {
    const r = render(twoFactor('routes', ['nope']), platform)
    expect(r.checks.some((c) => c.level === 'error' && c.code === 'unknown_2fa_route')).toBe(true)
  })

  it('apply publishes the site_login entry with the permissions, and drops it when 2FA is off', async () => {
    await saveAndApply(twoFactor('all'))
    expect(JSON.parse(redis.hashes.get('rbac:sites:login')!.get('payroll')!)).toMatchObject({ min_aal: 'aal2', scope: 'all' })
    const etag = (await app.inject({ method: 'GET', url: '/sites/payroll' })).headers.etag as string
    const put = await app.inject({ method: 'PUT', url: '/sites/payroll', headers: { ...W, 'if-match': etag }, payload: { site: payrollSite() } })
    await app.inject({ method: 'POST', url: '/sites/payroll/apply', headers: W, payload: { version: put.json().version } })
    expect(redis.hashes.get('rbac:sites:login')?.get('payroll')).toBeUndefined()
  })
})

describe('per-site 2FA on the gateway', () => {
  it('browser gates of a 2FA site redirect forbidden+html to /access and send aal to the policy', () => {
    const r = render(twoFactor('writes'), { ...platform, accessUrl: 'https://auth.dev.stairling.com/access' })
    const web = r.siteCr.spec.gates.find((g) => g.name === 'web')!
    expect(web.errors?.[0]).toEqual({
      handler: 'redirect',
      config: {
        to: 'https://auth.dev.stairling.com/access?site=payroll',
        return_to_query_param: 'return_to',
        when: [{ error: ['forbidden'], request: { header: { accept: ['text/html'] } } }],
      },
    })
    expect(web.errors?.slice(1)).toEqual([{ handler: 'redirect' }, { handler: 'json' }])
    expect(String((web.authorizer.config as { payload: string }).payload)).toContain('"aal"')
    // The public gate (platform errors) is untouched.
    expect(r.siteCr.spec.gates.find((g) => g.name === 'public')!.errors).toBeUndefined()
  })

  it('a site without 2FA renders exactly as before', () => {
    const web = render(payrollSite(), { ...platform, accessUrl: 'https://auth.dev.stairling.com/access' }).siteCr.spec.gates.find((g) => g.name === 'web')!
    expect(web.errors).toEqual([{ handler: 'redirect' }, { handler: 'json' }])
    expect(String((web.authorizer.config as { payload: string }).payload)).not.toContain('"aal"')
  })

  it('2FA on with no access page configured is an error', () => {
    const r = render(twoFactor('all'), platform)
    expect(r.checks.some((c) => c.level === 'error' && c.code === 'access_url_missing')).toBe(true)
  })
})

describe('S-4 — public branding', () => {
  it('by-host answers the exact host only, with cache headers and no internal fields', async () => {
    await saveAndApply(twoFactor('writes'))
    const res = await app.inject({ method: 'GET', url: '/api/public/sites/by-host/PAYROLL.dev.stairling.com' })
    expect(res.statusCode).toBe(200)
    expect(res.headers['cache-control']).toBe('public, max-age=60')
    expect(res.json()).toEqual({
      name: 'payroll', displayName: 'Payroll HQ', logoUrl: null, accent: '#1A2B3C', welcome: 'Hello',
      helpUrl: 'https://help.example.com/', minAal: 'aal2', scope: 'writes',
    })
    expect((await app.inject({ method: 'GET', url: '/api/public/sites/by-host/dev.stairling.com' })).statusCode).toBe(404)
    expect((await app.inject({ method: 'GET', url: '/api/public/sites/by-host/x.payroll.dev.stairling.com' })).statusCode).toBe(404)
    expect((await app.inject({ method: 'GET', url: '/api/public/sites/payroll/login' })).json().name).toBe('payroll')
  })

  it('a saved but never applied site is unknown to the public', async () => {
    await app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site: twoFactor('writes') } })
    expect((await app.inject({ method: 'GET', url: '/api/public/sites/by-host/payroll.dev.stairling.com' })).statusCode).toBe(404)
  })

  it('is rate limited', async () => {
    process.env.SITES_PUBLIC_RATE_LIMIT = '2'
    resetSitesConfig()
    const limited = Fastify()
    await limited.register(rateLimit, { global: false })
    await limited.register(publicSitesRoutes, { prefix: '/p' })
    const codes = []
    for (let i = 0; i < 3; i++) codes.push((await limited.inject({ method: 'GET', url: '/p/by-host/a.dev.stairling.com' })).statusCode)
    expect(codes).toEqual([404, 404, 429])
    await limited.close()
  })
})

describe('S-4 — logo', () => {
  const upload = (body: Buffer, type = 'image/png', headers: Record<string, string> = W) =>
    app.inject({ method: 'PUT', url: '/sites/payroll/logo', headers: { ...headers, 'content-type': type }, payload: body })

  it('stores a valid PNG and serves it with safe headers; by-host then names it', async () => {
    await saveAndApply(twoFactor('writes'))
    expect((await upload(PNG)).statusCode).toBe(200)
    const logo = await app.inject({ method: 'GET', url: '/api/public/sites/payroll/logo' })
    expect(logo.statusCode).toBe(200)
    expect(logo.headers['content-type']).toBe('image/png')
    expect(logo.headers['x-content-type-options']).toBe('nosniff')
    expect(logo.rawPayload.equals(PNG)).toBe(true)
    const branding = (await app.inject({ method: 'GET', url: '/api/public/sites/by-host/payroll.dev.stairling.com' })).json()
    expect(branding.logoUrl).toBe('/api/public/sites/payroll/logo')
  })

  it('refuses SVG, a PNG label on other bytes, oversize files and callers without admin:write', async () => {
    await app.inject({ method: 'PUT', url: '/sites/payroll', headers: W, payload: { site: payrollSite() } })
    expect((await upload(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/svg+xml')).statusCode).toBe(415)
    expect((await upload(Buffer.from('GIF89a......'))).statusCode).toBe(422)
    expect((await upload(Buffer.concat([PNG, Buffer.alloc(300 * 1024)]))).statusCode).toBe(413)
    expect((await upload(PNG, 'image/png', {})).statusCode).toBe(403)
    expect((await app.inject({ method: 'GET', url: '/api/public/sites/payroll/logo' })).statusCode).toBe(404)
  })
})

describe('access-reason (login-ui /access)', () => {
  const ask = (url: string, cookie = 'ory_kratos_session=abc') =>
    app.inject({ method: 'GET', url: `/api/public/sites/payroll/access-reason?url=${encodeURIComponent(url)}`, headers: cookie ? { cookie } : {} })

  it('asks OPA with the session email and aal, and returns only reason + minAal', async () => {
    await saveAndApply(twoFactor('all'))
    h.session.mockResolvedValue({ session: { email: 'nina@x.test', aal: 'aal1' } })
    h.opa.mockResolvedValue({ allow: false, reason: 'needs_2fa', groups: ['g'], organizations: [] })
    const res = await ask('https://payroll.dev.stairling.com/api/orgs/1/payslips?x=1')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ reason: 'needs_2fa', minAal: 'aal2' })
    expect(h.opa).toHaveBeenCalledWith('rbac/decision', {
      email: 'nina@x.test', object: '/api/orgs/1/payslips', action: 'GET', app: 'payroll', aal: 'aal1', client: false,
    })
  })

  it('refuses without a session, for another host, and 503 when OPA cannot answer', async () => {
    await saveAndApply(twoFactor('all'))
    expect((await ask('https://payroll.dev.stairling.com/', '')).statusCode).toBe(401)
    h.session.mockResolvedValue({ session: null, error: 'expired' })
    expect((await ask('https://payroll.dev.stairling.com/')).statusCode).toBe(401)
    h.session.mockResolvedValue({ session: { email: 'nina@x.test', aal: 'aal1' } })
    expect((await ask('https://evil.dev.stairling.com/')).statusCode).toBe(400)
    expect((await ask('not a url')).statusCode).toBe(400)
    const { OpaUnavailableError } = await import('../../services/opa-client.js')
    h.opa.mockRejectedValue(new OpaUnavailableError('off'))
    expect((await ask('https://payroll.dev.stairling.com/')).statusCode).toBe(503)
  })

  it('an unknown reason from OPA is reported as forbidden, never ok', async () => {
    await saveAndApply(twoFactor('all'))
    h.session.mockResolvedValue({ session: { email: 'nina@x.test', aal: 'aal2' } })
    h.opa.mockResolvedValue(undefined)
    expect((await ask('https://payroll.dev.stairling.com/')).json()).toEqual({ reason: 'forbidden', minAal: 'aal2' })
  })
})
