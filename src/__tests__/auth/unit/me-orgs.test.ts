import { describe, it, expect, vi, beforeEach } from 'vitest'

// GET /api/me/orgs?app=<site>: the caller's organizations served by that site, each with their org
// roles of the site and what they may do there — the policy's own answer (rbac.orgs_in_app), named.

const s = vi.hoisted(() => ({
  held: {} as Record<string, { roles: string[]; permissions: string[] }>,
  asked: [] as Array<[string, string]>,
  down: false,
}))

vi.mock('../../../config/env.js', () => ({ env: { ORGANISATION_SOURCE: 'directory', DEV_BYPASS_AUTH: false, NODE_ENV: 'test' } }))
vi.mock('../../../config/index.js', () => ({ env: { ORGANISATION_SOURCE: 'directory', DEV_BYPASS_AUTH: false, NODE_ENV: 'test' } }))
vi.mock('../../../authz/opa.js', () => ({
  orgPermissionsByOrg: vi.fn(),
  orgsInApp: vi.fn(async (email: string, app: string) => {
    s.asked.push([email, app])
    if (s.down) {
      const { AuthzUnavailableError } = await vi.importActual<typeof import('../../../authz/opa.js')>('../../../authz/opa.js')
      throw new AuthzUnavailableError('opa down')
    }
    return s.held
  }),
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: () => true,
  organisationsById: vi.fn(async (ids: string[]) => ids.filter((id) => id === 'acme').map((id) => ({ id, name: 'Acme', tenant: 'acme', attributes: {} }))),
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: {} }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: {} }))

const { meRoutes } = await import('../../../routes/me.routes.js')

async function call(query: Record<string, string>, email = 'ann@x.io') {
  let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | null = null
  let schema: Record<string, unknown> = {}
  await meRoutes({
    get: (path: string, opts: { schema: Record<string, unknown> }, fn: typeof handler) => {
      if (path === '/orgs') {
        handler = fn
        schema = opts.schema
      }
    },
  } as never)
  const answer: { code: number; body?: Record<string, unknown> } = { code: 200 }
  const reply = {
    status: (c: number) => { answer.code = c; return reply },
    send: (b: Record<string, unknown>) => { answer.body = b; return reply },
  }
  await handler!({ query, userContext: { id: 'ann', email }, log: { warn: vi.fn() } }, reply)
  return { ...answer, schema }
}

beforeEach(() => {
  s.held = {}
  s.asked = []
  s.down = false
})

describe('GET /api/me/orgs', () => {
  it("lists the caller's orgs in the app with their roles and permissions there, named", async () => {
    s.held = { initech: { roles: ['member'], permissions: ['cars:read'] }, acme: { roles: ['admin'], permissions: ['cars:read', 'cars:write'] } }
    const res = await call({ app: 'shop' })
    expect(s.asked).toEqual([['ann@x.io', 'shop']])
    expect(res.body).toEqual({
      app: 'shop',
      organizations: [
        { id: 'acme', name: 'Acme', roles: ['admin'], permissions: ['cars:read', 'cars:write'] },
        { id: 'initech', name: null, roles: ['member'], permissions: ['cars:read'] },
      ],
    })
  })

  it('needs the app, a session, and answers 503 — not an empty list — when the policy cannot', async () => {
    const { schema } = await call({ app: 'shop' })
    expect(schema).toMatchObject({ querystring: { required: ['app'] } })
    expect((await call({ app: 'shop' }, 'unknown')).code).toBe(401)
    s.down = true
    const res = await call({ app: 'shop' })
    expect(res.code).toBe(503)
    expect(res.body).toMatchObject({ error: 'policy_unavailable' })
  })
})
