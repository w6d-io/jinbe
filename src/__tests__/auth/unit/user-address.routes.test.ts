import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// POST /admin/users/:id/email and /admin/users/:id/verification (mcp-write-wave.md §3): the address
// changes unverified, a link goes to the new one (Kratos, method link), the old one is owed a notice
// (recorded), a taken address is a generic 409, never your own, never a stronger account; the resend
// is for an unverified address only and limited per target and per caller. No address in the audit.

const TARGET = '11111111-1111-4111-8111-111111111111'
const OTHER = '22222222-2222-4222-8222-222222222222'
const ME = '33333333-3333-4333-8333-333333333333'

const h = vi.hoisted(() => ({
  identities: new Map<string, Record<string, unknown>>(),
  patches: [] as Array<{ id: string; patches: unknown[] }>,
  rights: {} as Record<string, string[]>,
  counters: new Map<string, number>(),
  emits: [] as Array<Record<string, unknown>>,
  fetches: [] as Array<{ url: string; body?: string }>,
  offersLink: true,
  patchStatus: 200,
  mine: ['users:update_email', 'users:verify', 'users:read'] as string[],
}))

vi.mock('../../../services/kratos.service.js', async (importOriginal) => {
  const { KratosApiError } = await importOriginal<typeof import('../../../services/kratos.service.js')>()
  return {
    KratosApiError,
    kratosService: {
      getIdentity: vi.fn(async (id: string) => {
        const i = h.identities.get(id)
        if (!i) throw new KratosApiError(404, 'nope')
        return structuredClone(i)
      }),
      findByEmail: vi.fn(async (email: string) => [...h.identities.values()].find((i) => (i.traits as { email: string }).email === email) ?? null),
      patchIdentity: vi.fn(async (id: string, patches: Array<{ op: string; path: string; value: unknown }>) => {
        if (h.patchStatus !== 200) throw new KratosApiError(h.patchStatus, 'kratos')
        h.patches.push({ id, patches })
        const i = h.identities.get(id)!
        for (const p of patches) {
          if (p.path === '/traits/email') {
            ;(i.traits as Record<string, unknown>).email = p.value
            i.verifiable_addresses = [{ id: OTHER, value: p.value, verified: false, via: 'email', status: 'pending' }]
          }
          if (p.path === '/metadata_admin') i.metadata_admin = p.value
          if (p.path === '/metadata_admin/email_history') (i.metadata_admin as Record<string, unknown>).email_history = p.value
        }
        return structuredClone(i)
      }),
      invalidateGroupsCache: vi.fn(),
    },
  }
})
vi.mock('../../../authz/opa.js', () => ({ rights: vi.fn(async (email: string) => ({ groups: [], roles: [], permissions: h.rights[email] ?? [] })) }))
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    incr: async (k: string) => { h.counters.set(k, (h.counters.get(k) ?? 0) + 1); return h.counters.get(k) },
    expire: async () => 1,
    ttl: async () => 600,
  }),
}))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { h.emits.push(e); return '1-0' }) } }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../middleware/require-permission.js', async () => (await import('../../helpers/permission-stand-ins.js')).permissionStandIn())
vi.mock('../../../middleware/require-admin.js', async () => (await import('../../helpers/permission-stand-ins.js')).adminStandIn())

import { installRouteAccess } from '../../../policy/route-access.js'
import { userAddressRoutes } from '../../../routes/user-address.routes.js'
import { declaredRoutes } from '../../../policy/declared-routes.js'

let app: FastifyInstance
const H = { 'x-test-perms': 'users:update_email,users:verify', 'x-test-mfa': '1' }

beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: String(request.headers['x-user'] ?? ME), email: 'me@x.test', name: 'Me' } as never
    request.rbacInfo = { email: 'me@x.test', groups: [], roles: [], permissions: h.mine } as never
  })
  await app.register(userAddressRoutes, { prefix: '/admin' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  h.identities = new Map([
    [TARGET, { id: TARGET, schema_id: 'default', traits: { email: 'old@x.test' }, metadata_admin: { groups: ['users'] }, verifiable_addresses: [{ id: TARGET, value: 'old@x.test', verified: true, via: 'email', status: 'completed' }] }],
    [OTHER, { id: OTHER, schema_id: 'default', traits: { email: 'taken@x.test' }, verifiable_addresses: [{ id: OTHER, value: 'taken@x.test', verified: false, via: 'email', status: 'pending' }] }],
  ])
  h.patches = []
  h.rights = {}
  h.counters.clear()
  h.emits = []
  h.fetches = []
  h.offersLink = true
  h.patchStatus = 200
  h.mine = ['users:update_email', 'users:verify', 'users:read']
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { body?: string }) => {
    h.fetches.push({ url: String(url), body: init?.body })
    if (String(url).endsWith('/self-service/verification/api')) {
      return new Response(JSON.stringify({ id: 'flow-1', ui: { nodes: h.offersLink ? [{ group: 'link' }] : [{ group: 'code' }] } }), { status: 200 })
    }
    return new Response('{}', { status: 200 })
  }))
})

const changeEmail = (email: string, id = TARGET, headers: Record<string, string> = H) =>
  app.inject({ method: 'POST', url: `/admin/users/${id}/email`, headers, payload: { email } })
const resend = (id = TARGET, payload?: object, headers: Record<string, string> = H) =>
  app.inject({ method: 'POST', url: `/admin/users/${id}/verification`, headers, ...(payload ? { payload } : {}) })
const noAddressIn = (value: unknown) => expect(JSON.stringify(value)).not.toContain('@')

describe('route table', () => {
  it('declares users:update_email (with step-up) and users:verify', () => {
    const row = (m: string, p: string) => declaredRoutes().find((r) => r.method === m && r.path === p)
    expect(row('POST', '/admin/users/:id/email')).toMatchObject({ permission: 'users:update_email', stepUp: true })
    expect(row('POST', '/admin/users/:id/verification')).toMatchObject({ permission: 'users:verify' })
    expect(row('POST', '/admin/users/:id/verification')?.stepUp).toBeUndefined()
  })
})

describe('POST /admin/users/:id/email', () => {
  it('sets the new address unverified, keeps a hashed history, sends a link, records the notice', async () => {
    const res = await changeEmail('New@X.test')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ id: TARGET, email: 'new@x.test', verified: false, verificationSent: true, oldAddressNotice: { delivered: false, recorded: true, channel: 'audit' } })

    // One patch: the address and the history together.
    expect(h.patches).toHaveLength(1)
    const [address, hist] = h.patches[0].patches as Array<{ path: string; value: unknown }>
    expect(address).toEqual({ op: 'replace', path: '/traits/email', value: 'new@x.test' })
    expect(hist.path).toBe('/metadata_admin/email_history')
    const entries = hist.value as Array<{ digest: string; by: string }>
    expect(entries).toHaveLength(1)
    expect(entries[0].digest).toMatch(/^hmac-sha256:[a-f0-9]{32}$/)
    expect(entries[0].by).toBe(ME)
    noAddressIn(entries)

    const submit = h.fetches.find((f) => f.url.includes('/self-service/verification?flow=flow-1'))
    expect(JSON.parse(submit!.body!)).toEqual({ email: 'new@x.test', method: 'link' })

    const changed = h.emits.find((e) => e.v1Event === 'user.email_changed')!
    expect(changed).toMatchObject({ targetId: TARGET, severity: 'high', result: 'applied' })
    noAddressIn(changed.details)
    const notice = h.emits.find((e) => e.v1Event === 'user.address_notice_pending')!
    expect((notice.details as { to: string }).to).toBe(entries[0].digest)
  })

  it('answers a taken address with a generic 409 that names nobody', async () => {
    const res = await changeEmail('taken@x.test')
    expect(res.statusCode).toBe(409)
    expect(res.json()).toEqual({ error: 'address_unavailable', message: 'This address cannot be used. Choose another one.' })
    expect(JSON.stringify(res.json())).not.toContain(OTHER)
    expect(h.patches).toHaveLength(0)
  })

  it('answers the same generic 409 when Kratos refuses the address as taken (race)', async () => {
    h.patchStatus = 409
    expect((await changeEmail('fresh@x.test')).json().error).toBe('address_unavailable')
  })

  it('refuses your own address: use your account settings', async () => {
    h.identities.set(ME, { id: ME, schema_id: 'default', traits: { email: 'me@x.test' } })
    const res = await changeEmail('elsewhere@x.test', ME)
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('own_address')
  })

  it('refuses a target holding administrative rights the caller does not', async () => {
    h.rights['old@x.test'] = ['groups.members:write']
    const res = await changeEmail('new@x.test')
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('outranked')
    expect(h.patches).toHaveLength(0)
  })

  it('refuses without users:update_email, and without a recent second factor', async () => {
    expect((await changeEmail('new@x.test', TARGET, { 'x-test-perms': 'users:update', 'x-test-mfa': '1' })).statusCode).toBe(403)
    expect((await changeEmail('new@x.test', TARGET, { 'x-test-perms': 'users:update_email' })).statusCode).toBe(422)
    expect(h.patches).toHaveLength(0)
  })

  it('reports an address that did not change, and an unknown user', async () => {
    expect((await changeEmail('OLD@x.test')).statusCode).toBe(400)
    expect((await changeEmail('new@x.test', '44444444-4444-4444-8444-444444444444')).statusCode).toBe(404)
  })

  it('still changes the address when Kratos verifies by code only, and says the link was not sent', async () => {
    h.offersLink = false
    const res = await changeEmail('new@x.test')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ verificationSent: false, verificationError: 'verification_link_unavailable' })
  })

  it('keeps at most 30 days of history', async () => {
    const old = new Date(Date.now() - 40 * 24 * 3600 * 1000).toISOString()
    ;(h.identities.get(TARGET)!.metadata_admin as Record<string, unknown>).email_history = [{ digest: 'hmac-sha256:old', changedAt: old, by: null }]
    await changeEmail('new@x.test')
    const hist = (h.patches[0].patches[1] as { value: Array<{ digest: string }> }).value
    expect(hist.map((e) => e.digest)).not.toContain('hmac-sha256:old')
  })
})

describe('POST /admin/users/:id/verification', () => {
  it('sends a link for the unverified address: 202, the link never returned', async () => {
    const res = await resend(OTHER)
    expect(res.statusCode).toBe(202)
    expect(res.json()).toEqual({ sent: true })
    const submit = h.fetches.find((f) => f.url.includes('/self-service/verification?flow='))
    expect(JSON.parse(submit!.body!)).toEqual({ email: 'taken@x.test', method: 'link' })
    const ev = h.emits.find((e) => e.v1Event === 'user.verification_sent')!
    noAddressIn(ev.details)
  })

  it('answers 409 already_verified when nothing is unverified', async () => {
    const res = await resend(TARGET)
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('already_verified')
  })

  it('refuses an address that is not the user\'s', async () => {
    expect((await resend(OTHER, { address: 'someone@x.test' })).statusCode).toBe(422)
  })

  it('allows 3 links per target per 15 minutes, then 429 with Retry-After', async () => {
    for (let i = 0; i < 3; i++) expect((await resend(OTHER)).statusCode).toBe(202)
    const res = await resend(OTHER)
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('600')
    expect(res.json().error).toBe('rate_limited')
  })

  it('allows 30 links per caller per hour', async () => {
    h.counters.set(`jinbe:verify-link:caller:${ME}`, 30)
    const res = await resend(OTHER)
    expect(res.statusCode).toBe(429)
    expect(res.json().message).toContain('last hour')
  })

  it('refuses when Kratos verifies by code only (a bare code would be useless)', async () => {
    h.offersLink = false
    const res = await resend(OTHER)
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('verification_link_unavailable')
  })

  it('needs users:verify', async () => {
    expect((await resend(OTHER, undefined, { 'x-test-perms': 'users:update' })).statusCode).toBe(403)
  })
})
