import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

const cfg = vi.hoisted(() => ({ OPA_URL: undefined as string | undefined, OPA_TOKEN: undefined as string | undefined }))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return {
    ...real,
    env: new Proxy(real.env, {
      get: (target, key) => (key in cfg ? cfg[key as keyof typeof cfg] : target[key as keyof typeof target]),
    }),
  }
})

import { accessCheckRoutes } from '../../../routes/access-check.routes.js'
import { GENERATED_ROUTE_MAP } from '../../../policy/route-map.generated.js'

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
type Registered = { method: string; path: string; opts: { preHandler?: unknown }; handler: Handler }

function createMockFastify() {
  const routes: Registered[] = []
  const record = (method: string) => (path: string, opts: Registered['opts'], handler: Handler) => {
    routes.push({ method, path, opts, handler })
  }
  return {
    registeredRoutes: routes,
    get: vi.fn(record('GET')),
    post: vi.fn(record('POST')),
    addHook: vi.fn(),
  } as unknown as FastifyInstance & { registeredRoutes: Registered[] }
}

function createMockReply() {
  const reply = {
    _status: 200,
    _body: undefined as unknown,
    status: vi.fn(function (this: typeof reply, s: number) { this._status = s; return this }),
    send: vi.fn(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply as unknown as FastifyReply & { _status: number; _body: unknown }
}

const request = (body: unknown) => ({ body, log: { warn: vi.fn(), error: vi.fn() } }) as unknown as FastifyRequest

const opaAnswer = (result: unknown, status = 200) =>
  ({ ok: status < 300, status, json: async () => (result === undefined ? {} : { result }) }) as Response

describe('POST /access-check', () => {
  let route: Registered
  const TOKEN = 'o'.repeat(40)

  beforeEach(async () => {
    vi.restoreAllMocks()
    cfg.OPA_URL = 'http://opal-client:8181'
    cfg.OPA_TOKEN = TOKEN
    const fastify = createMockFastify()
    await accessCheckRoutes(fastify)
    route = fastify.registeredRoutes.find((r) => r.method === 'POST' && r.path === '/access-check')!
  })

  it('is declared access:check in the jinbe route_map — never anonymous', () => {
    expect(GENERATED_ROUTE_MAP).toContainEqual({ method: 'POST', path: '/api/admin/rbac/access-check', permission: 'access:check' })
  })

  it('answers 503 with a clear message when OPA is not configured', async () => {
    cfg.OPA_TOKEN = undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const reply = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/api/x' }), reply)
    expect(reply._status).toBe(503)
    expect(reply._body).toMatchObject({ error: 'policy_unavailable' })
    expect(JSON.stringify(reply._body)).toMatch(/OPA_URL.*OPA_TOKEN/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects malformed input at the boundary', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const body of [
      {},
      { email: 'not-an-email', method: 'GET', path: '/x' },
      { email: 'a@example.com', method: 'BREW', path: '/x' },
      { email: 'a@example.com', method: 'GET', path: 'no-leading-slash' },
      { email: 'a@example.com', method: 'GET', path: '/x', app: '../etc' },
    ]) {
      const reply = createMockReply()
      await route.handler(request(body), reply)
      expect(reply._status).toBe(400)
    }
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('asks OPA with the bearer token and explains the verdict', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = String(url)
      if (u.endsWith('/v1/data/rbac/decision')) return opaAnswer({ allow: false, reason: 'forbidden', groups: ['devs'], organizations: [] })
      if (u.endsWith('/v1/data/rbac/owning_apps')) return opaAnswer(['billing'])
      if (u.endsWith('/v1/data/rbac/simulate')) {
        return opaAnswer({
          allow: false,
          matching_rules: [{ method: 'DELETE', path: '/api/invoices/:id', permission: 'invoices:delete' }],
          groups: ['devs'], roles: ['viewer'], permissions: ['invoices:read'],
        })
      }
      throw new Error(`unexpected ${u}`)
    })

    const reply = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'delete', path: '/api/invoices/42' }), reply)

    expect(reply._status).toBe(200)
    expect(reply._body).toEqual({
      allow: false,
      reason: 'forbidden',
      app: 'billing',
      owners: ['billing'],
      matchingRules: [{ method: 'DELETE', path: '/api/invoices/:id', permission: 'invoices:delete' }],
      groups: ['devs'],
      roles: ['viewer'],
      permissions: ['invoices:read'],
    })
    for (const [, init] of fetchSpy.mock.calls) {
      expect((init as RequestInit).headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` })
      expect(JSON.parse(String((init as RequestInit).body)).input).toMatchObject({
        email: 'a@example.com', action: 'DELETE', object: '/api/invoices/42',
      })
    }
    const simulateInput = JSON.parse(String((fetchSpy.mock.calls.find(([u]) => String(u).endsWith('/simulate'))![1] as RequestInit).body)).input
    expect(simulateInput.app).toBe('billing')
  })

  it('reports not_found with no app and both owners when two services tie on the route', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = String(url)
      if (u.endsWith('/decision')) return opaAnswer({ allow: false, reason: 'not_found', groups: [], organizations: [] })
      if (u.endsWith('/owning_apps')) return opaAnswer(['a', 'b'])
      return opaAnswer({ allow: false, matching_rules: [], groups: [], roles: [], permissions: [] })
    })
    const reply = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/nowhere' }), reply)
    expect(reply._status).toBe(200)
    expect(reply._body).toMatchObject({ allow: false, reason: 'not_found', app: null, owners: ['a', 'b'], matchingRules: [] })
  })

  it('needs_2fa: asked at the level given, and says the sign-in level alone fails, who demands aal2, and that aal2 passes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const u = String(url)
      const input = JSON.parse(String((init as RequestInit).body)).input
      if (u.endsWith('/v1/data/rbac/decision')) {
        return opaAnswer(input.aal === 'aal2' ? { allow: true, reason: 'ok', groups: ['super_admins'] } : { allow: false, reason: 'needs_2fa', groups: ['super_admins'] })
      }
      if (u.endsWith('/owning_apps')) return opaAnswer(['echo-mfa'])
      if (u.endsWith('/simulate')) return opaAnswer({ matching_rules: [{ method: 'GET', path: '/', permission: 'echo:read' }], roles: ['super_admin'], permissions: ['users:read'] })
      if (u.endsWith('/site_login_cfg')) return opaAnswer({ min_aal: 'aal2', scope: 'all' })
      if (u.endsWith('/second_factor_required')) return opaAnswer(true)
      throw new Error(`unexpected ${u}`)
    })
    const reply = createMockReply()
    await route.handler(request({ email: 'root@example.com', method: 'GET', path: '/', aal: 'aal1' }), reply)
    expect(reply._status).toBe(200)
    expect(reply._body).toMatchObject({
      allow: false, reason: 'needs_2fa', aal: 'aal1',
      stepUp: { requiredAal: 'aal2', allowedAtAal2: true, requiredBy: ['site', 'platform_group'] },
    })
    const first = JSON.parse(String((fetchSpy.mock.calls.find(([u]) => String(u).endsWith('/decision'))![1] as RequestInit).body)).input
    expect(first.aal).toBe('aal1')
  })

  it('asked at aal2, or refused for another reason: no stepUp', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const u = String(url)
      if (u.endsWith('/decision')) return opaAnswer({ allow: false, reason: 'forbidden', groups: [] })
      if (u.endsWith('/owning_apps')) return opaAnswer(['a'])
      if (u.endsWith('/simulate')) return opaAnswer({})
      throw new Error(`unexpected ${u}`)
    })
    for (const aal of ['aal1', 'aal2']) {
      const reply = createMockReply()
      await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/x', aal }), reply)
      expect((reply._body as Record<string, unknown>).stepUp).toBeUndefined()
    }
    const bad = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/x', aal: 'aal3' }), bad)
    expect(bad._status).toBe(400)
  })

  it('answers 502 when OPA refuses or is unreachable, without leaking the token', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(opaAnswer({ code: 'unauthorized' }, 401))
    const reply = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/api/x' }), reply)
    expect(reply._status).toBe(502)
    expect(JSON.stringify(reply._body)).not.toContain(TOKEN)

    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'))
    const reply2 = createMockReply()
    await route.handler(request({ email: 'a@example.com', method: 'GET', path: '/api/x' }), reply2)
    expect(reply2._status).toBe(502)
  })
})
