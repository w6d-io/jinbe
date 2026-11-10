import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess } from '../../policy/route-access.js'
import { ROLES } from '../../policy/roles.js'
import type { Site } from '../../sites/schemas.js'
import { payrollSite } from './fixtures.js'

// The sites one person can open in a browser, asked of the policy (rbac/decision for a GET of each
// entry page, at aal2): which are listed, how each is labelled, what the links are, and what it costs.

const BOB = '20000000-0000-4000-8000-000000000001'
const NOBODY = '20000000-0000-4000-8000-000000000002'
const NAMELESS = '20000000-0000-4000-8000-000000000003'
const GHOST = '99999999-9999-4999-8999-999999999999'
const PROBE = 'site-verify@jinbe.invalid'

/** The stand-in policy: who may GET a site's pages. */
type Rule = { public?: boolean; signedIn?: boolean; holders?: string[] }

const s = vi.hoisted(() => ({
  // Read when the services are constructed, so set before any import.
  env: { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', KRATOS_ADMIN_URL: 'http://kratos-admin:4434' } as Record<string, unknown>,
  policy: {} as Record<string, { public?: boolean; signedIn?: boolean; holders?: string[] }>,
  opaDown: false,
  records: [] as Array<{ site: unknown; version: number; applied?: { version: number } }>,
  versions: {} as Record<string, unknown>,
  decisions: [] as Array<Record<string, unknown>>,
  callerPermissions: [] as string[],
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in s.env ? s.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../sites/repository.js', () => ({
  sitesRepository: {
    list: async () => s.records,
    get: async (name: string) => s.records.find((r) => (r.site as Site).name === name) ?? null,
    version: async (name: string, v: number) => s.versions[`${name}@${v}`] ?? { v, site: s.records.find((r) => (r.site as Site).name === name)?.site },
  },
}))
vi.mock('../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { userAccessRoutes } from '../../routes/user-access.routes.js'
import { resetReachableSites } from '../../sites/reachable.js'
import { clearAuthzCache } from '../../authz/opa.js'

/** A published site with pages: payroll's gates, its own name, address and label. */
function site(name: string, host: string, over: Partial<Site> = {}): Site {
  return { ...payrollSite(), name, displayName: name[0].toUpperCase() + name.slice(1), address: { host }, organizations: undefined, orgs: [], ...over }
}
const published = (x: Site, over: Record<string, unknown> = {}) => ({ site: x, version: 1, applied: { version: 1 }, ...over })

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string } }
      return Response.json({ result: { email: q.email, groups: [], roles: [], permissions: s.callerPermissions } })
    }
    if (url === 'http://opal-client:8181/v1/data/rbac/decision') {
      if (s.opaDown) throw new TypeError('fetch failed')
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string; app: string; object: string; action: string; aal: string; client: boolean } }
      s.decisions.push(q)
      const rule: Rule = s.policy[q.app] ?? {}
      const allow = q.action === 'GET' && (rule.public === true || (q.email !== '' && rule.signedIn === true) || (rule.holders ?? []).includes(q.email))
      return Response.json({ result: { allow, reason: allow ? 'ok' : 'forbidden' } })
    }
    if (url.startsWith('http://kratos-admin:4434/admin/identities/')) {
      const id = new URL(url).pathname.split('/').pop()
      const traits = id === BOB ? { email: 'bob@example.com', name: 'Bob' } : id === NOBODY ? { email: 'nobody@example.com' } : id === NAMELESS ? {} : null
      return traits ? Response.json({ id, schema_id: 'default', state: 'active', traits, created_at: '', updated_at: '' }) : Response.json({ error: { code: 404 } }, { status: 404 })
    }
    throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`)
  }))
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    if (who) request.userContext = { id: who, email: `${who}@example.com`, name: who, sessionId: `sess-${who}`, aal: 'aal1', authVia: 'session' } as never
  })
  await app.register(async (api) => { await api.register(userAccessRoutes, { prefix: '/admin' }) }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})

beforeEach(() => {
  s.callerPermissions = [...ROLES.support.permissions]
  s.opaDown = false
  s.decisions = []
  s.versions = {}
  const apiOnly = site('ledger', 'ledger.dev.example.com')
  apiOnly.gates = apiOnly.gates.map((g) => ({ ...g, errors: 'api' as const }))
  s.records = [
    published(site('crm', 'crm.dev.example.com')),
    published(site('wiki', 'wiki.dev.example.com', { displayName: 'Team wiki' })),
    published(site('brochure', 'www.dev.example.com')),
    published(site('hr', 'hr.dev.example.com')),
    // Two sites on one host, each under its own prefix.
    published(site('billing', 'apps.dev.example.com', { address: { host: 'apps.dev.example.com', pathPrefix: '/billing' } })),
    published(site('reports', 'apps.dev.example.com', { address: { host: 'apps.dev.example.com', pathPrefix: '/reports' } })),
    // Its own landing page and login name.
    published(site('portal', 'portal.dev.example.com', { login: { twoFactor: { scope: 'none', clients: 'exempt' }, defaultReturnUrl: 'https://portal.dev.example.com/home', branding: { name: 'Customer portal' } } as never })),
    // Never listed, whatever the policy says.
    published(site('frozen', 'frozen.dev.example.com', { state: 'paused' })),
    { site: site('sketch', 'sketch.dev.example.com'), version: 1 },
    published(site('kuma', 'kuma.dev.example.com')),
    published(apiOnly),
  ]
  s.policy = {
    crm: { holders: ['bob@example.com'] },
    wiki: { signedIn: true },
    brochure: { public: true },
    hr: { holders: ['hana@example.com'] },
    billing: { holders: ['bob@example.com'] },
    reports: { signedIn: true },
    portal: { holders: ['bob@example.com'] },
    frozen: { signedIn: true }, sketch: { signedIn: true }, kuma: { signedIn: true }, ledger: { signedIn: true },
  }
  resetReachableSites()
  clearAuthzCache()
})

const get = (id = BOB, who: string | null = 'support') =>
  app.inject({ url: `/api/admin/users/${id}/reachable-sites`, headers: who ? { 'x-test-user': who } : {} })
const names = async (id = BOB) => ((await get(id)).json().sites as Array<{ name: string }>).map((x) => x.name)

describe('GET /api/admin/users/:id/reachable-sites', () => {
  it('lists what the person can open: role sites first, then the ones open to any signed-in person, by title', async () => {
    const res = await get()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      sites: [
        { name: 'billing', title: 'Billing', url: 'https://apps.dev.example.com/billing/', access: 'role' },
        { name: 'crm', title: 'Crm', url: 'https://crm.dev.example.com/', access: 'role' },
        { name: 'portal', title: 'Customer portal', url: 'https://portal.dev.example.com/home', access: 'role' },
        { name: 'reports', title: 'Reports', url: 'https://apps.dev.example.com/reports/', access: 'signed-in' },
        { name: 'wiki', title: 'Team wiki', url: 'https://wiki.dev.example.com/', access: 'signed-in' },
      ],
    })
  })

  it('a person holding nothing still gets the sites open to any signed-in person, and no role site', async () => {
    expect((await get(NOBODY)).json().sites).toEqual([
      { name: 'reports', title: 'Reports', url: 'https://apps.dev.example.com/reports/', access: 'signed-in' },
      { name: 'wiki', title: 'Team wiki', url: 'https://wiki.dev.example.com/', access: 'signed-in' },
    ])
  })

  it('leaves out what they cannot open, and public pages', async () => {
    const listed = await names()
    expect(listed).not.toContain('hr')
    expect(listed).not.toContain('brochure')
  })

  it.each(['frozen', 'sketch', 'kuma', 'ledger'])('never lists %s (paused, unpublished, system, API-only), and never asks the policy about it', async (name) => {
    expect(await names()).not.toContain(name)
    expect(s.decisions.map((d) => d.app)).not.toContain(name)
  })

  it('links two sites sharing a host each under its own prefix', async () => {
    const sites = (await get()).json().sites as Array<{ name: string; url: string }>
    expect(sites.find((x) => x.name === 'billing')!.url).toBe('https://apps.dev.example.com/billing/')
    expect(sites.find((x) => x.name === 'reports')!.url).toBe('https://apps.dev.example.com/reports/')
    expect(s.decisions.filter((d) => d.app === 'billing').map((d) => d.object)).toEqual(expect.arrayContaining(['/billing/']))
  })

  it('goes by the APPLIED version: a saved, unpublished move or rename shows nothing yet', async () => {
    s.records[0] = published(site('crm', 'crm-new.dev.example.com', { displayName: 'New CRM' }), { version: 2 })
    s.versions['crm@1'] = { v: 1, site: site('crm', 'crm.dev.example.com') }
    const crm = ((await get()).json().sites as Array<{ name: string; url: string; title: string }>).find((x) => x.name === 'crm')!
    expect(crm).toMatchObject({ url: 'https://crm.dev.example.com/', title: 'Crm' })
  })

  it('falls back to the name when a site has no label', async () => {
    s.records[0] = published(site('crm', 'crm.dev.example.com', { displayName: '' }))
    expect(((await get()).json().sites as Array<{ name: string; title: string }>).find((x) => x.name === 'crm')!.title).toBe('crm')
  })

  it('asks the gateway\'s question: a GET of the entry path in the site\'s app, as a person at aal2', async () => {
    await get()
    expect(s.decisions.find((d) => d.app === 'portal' && d.email === 'bob@example.com')).toEqual({ email: 'bob@example.com', object: '/home', action: 'GET', app: 'portal', aal: 'aal2', client: false })
    // How it opens: an anonymous visitor (no address, no level), then a signed-in account holding nothing.
    expect(s.decisions.find((d) => d.app === 'crm' && d.email === '')).toEqual({ email: '', object: '/', action: 'GET', app: 'crm', aal: '', client: false })
    expect(s.decisions.find((d) => d.app === 'crm' && d.email === PROBE)).toEqual({ email: PROBE, object: '/', action: 'GET', app: 'crm', aal: 'aal2', client: false })
  })

  it('costs one decision per candidate site for the person, two more only for the sites they can open, then nothing for 30 s', async () => {
    await get()
    // 7 candidates asked for Bob; 6 allowed (hr refused) → anonymous asked for 6, the probe for the 5 that are not public.
    expect(s.decisions.filter((d) => d.email === 'bob@example.com')).toHaveLength(7)
    expect(s.decisions.filter((d) => d.email === '')).toHaveLength(6)
    expect(s.decisions.filter((d) => d.email === PROBE)).toHaveLength(5)
    const before = s.decisions.length
    await get()
    expect(s.decisions).toHaveLength(before)
    // Another person: their own decisions only; how each site opens is already known.
    await get(NOBODY)
    expect(s.decisions.slice(before).every((d) => d.email === 'nobody@example.com')).toBe(true)
    expect(s.decisions.slice(before)).toHaveLength(7)
  })

  it('a person without an address opens nothing, and the policy is not asked', async () => {
    const res = await get(NAMELESS)
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ sites: [] })
    expect(s.decisions).toEqual([])
  })

  it('404 for an unknown user', async () => {
    const res = await get(GHOST)
    expect(res.statusCode).toBe(404)
    expect(res.json()).toMatchObject({ message: 'User not found' })
  })

  it('503 policy_unavailable when the policy cannot be asked — never a shorter list', async () => {
    s.opaDown = true
    const res = await get()
    expect(res.statusCode).toBe(503)
    expect(res.json().error).toBe('policy_unavailable')
    // Nothing was kept: it answers as soon as the policy does.
    s.opaDown = false
    expect((await get()).json().sites).toHaveLength(5)
  })

  it('needs access:read, and nothing more: no second factor', async () => {
    s.callerPermissions = ['users:read', 'users:impersonate']
    const refused = await get()
    expect(refused.statusCode).toBe(403)
    expect(refused.json()).toMatchObject({ code: 'permission_required', permission: 'access:read' })
    clearAuthzCache()
    s.callerPermissions = ['access:read']
    expect((await get()).statusCode).toBe(200)
    expect(ROLES.support.permissions).toContain('access:read')
  })
})
