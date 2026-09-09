import { describe, it, expect, vi, beforeEach } from 'vitest'

// The list a global administrator is offered when assigning somebody to an organisation.
//
// It used to be inferred from organisations already IN USE — those with a service mapping, and those
// somebody already carried on their identity. Once this service owned organisations, the one an
// administrator was about to assign for the first time belonged to neither set, so the only
// organisations offered were the ones that needed no assigning.

const { storeState, redisState, kratosState } = vi.hoisted(() => ({
  storeState: {
    organisationStoreConfigured: vi.fn(() => true),
    organisationsById: vi.fn(async () => []),
    allOrganisations: vi.fn(async () => [
      { id: 'held-and-empty', name: 'Nobody here yet', tenant: 'business', attributes: {} },
      { id: 'mapped', name: 'Also mapped', tenant: 'business', attributes: {} },
    ]),
  },
  redisState: { getOrgServiceMap: vi.fn(async () => ({ mapped: ['time'] })) },
  kratosState: { getAllIdentitiesWithBindings: vi.fn(async () => new Map()) },
}))

const envState = { ORGANISATION_SOURCE: 'directory', DEV_BYPASS_AUTH: false, NODE_ENV: 'test' }

vi.mock('../../../config/env.js', () => ({ env: envState }))
vi.mock('../../../config/index.js', () => ({ env: envState }))
vi.mock('../../../services/organisation-store.js', () => storeState)
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { isSuperAdmin: vi.fn(async () => true) },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: redisState }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: kratosState }))
vi.mock('../../../services/caller-organisations.js', () => ({
  callerOrganisations: vi.fn(async () => []),
  callerOrganisationsScope: vi.fn(() => 'delegated'),
}))

const { meRoutes } = await import('../../../routes/me.routes.js')

async function catalogue() {
  let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | null = null
  await meRoutes({
    get: (path: string, _opts: unknown, fn: typeof handler) => {
      if (path === '/organizations') handler = fn
    },
  } as never)

  const body: Record<string, unknown> = {}
  const reply = {
    status: () => reply,
    send: (payload: Record<string, unknown>) => Object.assign(body, payload),
  }
  await handler!({ validatedSession: { email: 'admin@strada.eu' }, userContext: { id: 's' } }, reply)
  return body as { organizations: string[]; scope: string }
}

describe('the organisations a global administrator may assign', () => {
  beforeEach(() => {
    storeState.allOrganisations.mockClear()
    storeState.allOrganisations.mockResolvedValue([
      { id: 'held-and-empty', name: 'Nobody here yet', tenant: 'business', attributes: {} },
      { id: 'mapped', name: 'Also mapped', tenant: 'business', attributes: {} },
    ])
  })

  it('offers an organisation that exists but has no members yet', async () => {
    const body = await catalogue()

    expect(body.scope).toBe('all')
    expect(body.organizations).toContain('held-and-empty')
    // Union, not replacement: an organisation known only to the service mapping stays offered.
    expect(body.organizations).toContain('mapped')
    // And each one once, however many sources name it.
    expect(body.organizations.filter((o) => o === 'mapped')).toHaveLength(1)
  })

  it('keeps answering when the store cannot be read', async () => {
    // A catalogue is a convenience; losing it entirely would take the screen with it.
    storeState.allOrganisations.mockRejectedValueOnce(new Error('store unavailable'))

    const body = await catalogue()

    expect(body.organizations).toEqual(['mapped'])
  })
})
