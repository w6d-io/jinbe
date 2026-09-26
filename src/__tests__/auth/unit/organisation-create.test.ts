import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Story 3 (create): an organisation is its own entity. Creating one needs a name and nothing else —
// no bundle of services has to come with it, because org membership never decides site access.

const { poolState, envState, store } = vi.hoisted(() => ({
  poolState: { query: vi.fn(async () => ({ rows: [] as unknown[] })), end: vi.fn(async () => {}) },
  envState: {
    env: {
      ORGANISATION_DATABASE_URL: 'postgres://somewhere/db',
      ORGANISATION_DATABASE_POOL_MAX: 5,
      ORGANISATION_DATABASE_TIMEOUT_MS: 5000,
    } as Record<string, unknown>,
  },
  store: {
    organisationStoreConfigured: vi.fn(() => true),
    createOrganisation: vi.fn(async (input: { name: string; tenant: string }) => ({
      id: '33333333-3333-3333-3333-333333333333',
      attributes: {},
      ...input,
    })),
  },
}))

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('pg', () => ({ Pool: vi.fn(function () { return poolState }) }))

describe('createOrganisation (store)', () => {
  let real: typeof import('../../../services/organisation-store.js')

  beforeEach(async () => {
    real = await vi.importActual('../../../services/organisation-store.js')
    await real.closeOrganisationStore()
    poolState.query.mockReset()
    poolState.query.mockResolvedValue({ rows: [] })
  })

  it('inserts a new organisation with a fresh id and binds every value', async () => {
    const created = await real.createOrganisation({ name: "Acme'; --", tenant: 'acme' })

    const insert = poolState.query.mock.calls.find((c) => String(c[0]).includes('INSERT INTO organisations'))!
    expect(String(insert[0])).not.toContain('Acme')
    expect(insert[1]).toEqual([created.id, "Acme'; --", 'acme', '{}'])
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('writes no deployment: an organisation needs no service bundle', async () => {
    await real.createOrganisation({ name: 'Acme', tenant: 'acme' })

    const inserts = poolState.query.mock.calls.map((c) => String(c[0])).filter((q) => q.startsWith('INSERT'))
    expect(inserts).toHaveLength(1)
    expect(inserts[0]).toContain('INSERT INTO organisations ')
  })
})

vi.mock('../../../services/organisation-store.js', () => store)
vi.mock('../../../authz/opa.js', () => ({
  holdsInJinbe: vi.fn(async () => true),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async () => {}) },
}))

const { organisationAdminRoutes } = await import('../../../routes/organisation-admin.routes.js')
const { enforcedBy } = await import('../../../policy/declared-routes.js')

type Handler = (request: unknown, reply: unknown) => Promise<unknown>

async function mount() {
  const routes: { path: string; opts: { preHandler: unknown; schema: Record<string, unknown> }; handler: Handler }[] = []
  await organisationAdminRoutes({
    post: (path: string, opts: never, handler: Handler) => routes.push({ path, opts, handler }),
  } as never)
  return routes
}

async function call(body: unknown) {
  const [route] = await mount()
  const answer: { code?: number; body?: Record<string, unknown> } = {}
  const reply = {
    status: (code: number) => {
      answer.code = code
      return reply
    },
    send: (b: Record<string, unknown>) => {
      answer.body = b
      return reply
    },
  } as unknown as FastifyReply
  const request = {
    body,
    userContext: { id: 'subject-sam', email: 'sam@example.com' },
    ip: '127.0.0.1',
    headers: {},
    log: { error: vi.fn(), warn: vi.fn() },
  } as unknown as FastifyRequest
  await route.handler(request, reply)
  return answer
}

describe('POST /api/admin/organizations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    store.organisationStoreConfigured.mockReturnValue(true)
  })

  it('is guarded by the platform permission to write organisations and documented', async () => {
    const [route] = await mount()

    expect(route.path).toBe('/organizations')
    expect(enforcedBy(route.opts.preHandler)).toBe('admin.organisation:write')
    expect(route.opts.schema).toMatchObject({ tags: ['admin'], body: { required: ['name'] } })
  })

  it('creates one from a name alone, deriving its tenant', async () => {
    const answer = await call({ name: 'Acme Corp' })

    expect(answer.code).toBe(201)
    expect(store.createOrganisation).toHaveBeenCalledWith({ name: 'Acme Corp', tenant: 'acme-corp' })
    expect(answer.body).toMatchObject({ name: 'Acme Corp', tenant: 'acme-corp', applications: [] })
  })

  it('keeps an explicit tenant', async () => {
    await call({ name: 'Acme Corp', tenant: 'acme' })

    expect(store.createOrganisation).toHaveBeenCalledWith({ name: 'Acme Corp', tenant: 'acme' })
  })

  it('refuses a name that yields no tenant rather than inventing one', async () => {
    const answer = await call({ name: '株式会社' })

    expect(answer.code).toBe(400)
    expect(store.createOrganisation).not.toHaveBeenCalled()
  })

  it('answers 503 when there is no directory to keep it in', async () => {
    store.organisationStoreConfigured.mockReturnValue(false)

    const answer = await call({ name: 'Acme' })

    expect(answer.code).toBe(503)
  })

  it('answers 503 when the directory cannot be written', async () => {
    store.createOrganisation.mockRejectedValueOnce(new Error('read only'))

    const answer = await call({ name: 'Acme' })

    expect(answer.code).toBe(503)
  })
})
