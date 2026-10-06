import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// Story 3 (create): an organisation is its own entity, made for its owner: a name and the owner's
// address — no bundle of services has to come with it, because org membership never decides site
// access. An account with that address is named owner; an unknown address is invited as owner.

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
    organisationStoreNotConfigured: () => ({
      error: 'organisation_directory_unavailable',
      reason: 'not_configured',
      message: 'No organisation database is configured: set ORGANISATION_DATABASE_URL.',
    }),
    createOrganisation: vi.fn(async (input: { name: string; tenant: string }) => ({
      id: '33333333-3333-3333-3333-333333333333',
      attributes: {},
      ...input,
    })),
  },
}))

const rbacStore = vi.hoisted(() => ({ orgSites: {} as Record<string, string[]>, forgotten: [] as string[] }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { setOrgSites: vi.fn(async (o: string, sites: string[]) => { if (sites.length) rbacStore.orgSites[o] = sites; else delete rbacStore.orgSites[o] }) },
}))
const people = vi.hoisted(() => ({
  accounts: {} as Record<string, { id: string }>,
  owners: [] as Array<[string, string, string[]]>,
  joined: [] as Array<[string, string]>,
  invited: [] as Array<{ org: string; email: string; roles: string[]; byPlatform?: boolean }>,
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: {
    forgetOrg: vi.fn(async (o: string) => { rbacStore.forgotten.push(o) }),
    setForMember: vi.fn(async (o: string, id: string, roles: string[]) => { people.owners.push([o, id, roles]) }),
  },
}))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { findByEmail: vi.fn(async (e: string) => people.accounts[e] ?? null) } }))
vi.mock('../../../services/org-membership.service.js', () => ({ joinOrganisation: vi.fn(async (i: { id: string }, o: string) => { people.joined.push([i.id, o]) }) }))
vi.mock('../../../services/org-invitations.js', () => ({
  orgInvitations: { create: vi.fn(async (input: { org: string; email: string; roles: string[]; byPlatform?: boolean }) => { people.invited.push(input); return { invitation: { id: 'inv-1', expiresAt: '2026-10-13T00:00:00.000Z' }, token: 'tok-1' } }) },
  invitationLink: (t: string) => `https://auth.example.com/invitation?token=${t}`,
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/direct-grants.repository.js', () => ({ directGrantsRepository: {} }))
vi.mock('../../../sites/signup/store.js', () => ({ signUpStore: {} }))
vi.mock('../../../sites/repository.js', () => ({ sitesRepository: {} }))
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

type Handler = (request: unknown, reply: unknown) => Promise<unknown>

async function mount() {
  const routes: { path: string; opts: { preHandler: unknown; schema: Record<string, unknown> }; handler: Handler }[] = []
  await organisationAdminRoutes({
    post: (path: string, opts: never, handler: Handler) => routes.push({ path, opts, handler }),
    // Change and delete are tested in organisation-admin.routes.test.ts.
    patch: () => {},
    delete: () => {},
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
    expect((route.opts as { config?: { permission?: string } }).config?.permission).toBe('orgs:write')
    expect(route.opts.schema).toMatchObject({ tags: ['admin'], body: { required: ['name', 'owner'] } })
  })

  it("creates one for an existing account, named owner at once, deriving its tenant", async () => {
    people.accounts['ann@acme.io'] = { id: 'subject-ann' }
    const answer = await call({ name: 'Acme Corp', owner: 'Ann@Acme.io' })

    expect(answer.code).toBe(201)
    expect(store.createOrganisation).toHaveBeenCalledWith({ name: 'Acme Corp', tenant: 'acme-corp' })
    expect(answer.body).toMatchObject({ name: 'Acme Corp', tenant: 'acme-corp', sites: ['jinbe'], owner: { email: 'ann@acme.io', id: 'subject-ann', status: 'owner' } })
    expect(answer.body).not.toHaveProperty('invitation')
    const id = answer.body!.id as string
    expect(people.joined).toContainEqual(['subject-ann', id])
    expect(people.owners).toContainEqual([id, 'subject-ann', ['jinbe:owner']])
    // Entitled to jinbe from birth: its org routes answer at once.
    expect(rbacStore.orgSites[id]).toEqual(['jinbe'])
  })

  it('invites an address with no account as owner (by the platform), the token shown once', async () => {
    const answer = await call({ name: 'Globex', owner: 'new@globex.io' })

    expect(answer.code).toBe(201)
    expect(answer.body).toMatchObject({ owner: { email: 'new@globex.io', id: null, status: 'invited' }, invitation: { id: 'inv-1', token: 'tok-1', link: 'https://auth.example.com/invitation?token=tok-1' } })
    expect(people.invited).toContainEqual(expect.objectContaining({ email: 'new@globex.io', roles: ['jinbe:owner'], byPlatform: true }))
  })

  it('takes an address, never an id, for the owner', async () => {
    expect((await call({ name: 'Acme' })).code).toBe(400)
    expect((await call({ name: 'Acme', owner: '33333333-3333-3333-3333-333333333333' })).code).toBe(400)
    expect(store.createOrganisation).not.toHaveBeenCalled()
  })

  it('keeps an explicit tenant', async () => {
    await call({ name: 'Acme Corp', tenant: 'acme', owner: 'ann@acme.io' })

    expect(store.createOrganisation).toHaveBeenCalledWith({ name: 'Acme Corp', tenant: 'acme' })
  })

  it('refuses a name that yields no tenant rather than inventing one', async () => {
    const answer = await call({ name: '株式会社', owner: 'ann@acme.io' })

    expect(answer.code).toBe(400)
    expect(store.createOrganisation).not.toHaveBeenCalled()
  })

  it('answers 503 when there is no directory to keep it in', async () => {
    store.organisationStoreConfigured.mockReturnValue(false)

    const answer = await call({ name: 'Acme', owner: 'ann@acme.io' })

    expect(answer.code).toBe(503)
    expect(answer.body).toMatchObject({ error: 'organisation_directory_unavailable', reason: 'not_configured' })
  })

  it('answers 503 when the directory cannot be written', async () => {
    store.createOrganisation.mockRejectedValueOnce(new Error('read only'))

    const answer = await call({ name: 'Acme', owner: 'ann@acme.io' })

    expect(answer.code).toBe(503)
  })
})
