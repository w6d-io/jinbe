import { describe, it, expect, vi } from 'vitest'

// What to call an organisation is served because it is held here. Two properties matter: a label is
// never invented, and a store that cannot answer costs a label and never the list — the second
// would turn a display problem into somebody appearing to belong nowhere.

const { storeState, envState } = vi.hoisted(() => ({
  storeState: {
    organisationStoreConfigured: vi.fn(() => true),
    organisationsById: vi.fn(async () => [
      { id: 'org-1', name: 'Business', tenant: 'business', attributes: {} },
    ]),
  },
  envState: { env: { ORGANISATION_SOURCE: 'directory', DEV_BYPASS_AUTH: false, NODE_ENV: 'test' } },
}))

vi.mock('../../../config/env.js', () => ({ env: envState.env }))
vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('../../../services/organisation-store.js', () => storeState)
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { isSuperAdmin: vi.fn(async () => false) },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getOrgServiceMap: vi.fn(async () => ({})), getServices: vi.fn(async () => []) },
}))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: {} }))
vi.mock('../../../services/caller-organisations.js', () => ({
  callerOrganisations: vi.fn(async () => ['org-1', 'org-2']),
  callerOrganisationsScope: vi.fn(() => 'delegated'),
}))

const { meRoutes } = await import('../../../routes/me.routes.js')

/** The one route under test, invoked the way Fastify would. */
async function callOrganizations() {
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
  await handler!({ validatedSession: { email: 'someone@strada.eu' }, userContext: { id: 's' } }, reply)
  return body
}

describe('GET /me/organizations — the labels', () => {
  it('answers a label for what it holds, and nothing for what it does not', async () => {
    const body = await callOrganizations()

    // org-2 has no record, so it gets no invented label — the caller shows the identifier.
    expect(body.names).toEqual({ 'org-1': 'Business' })
    expect(body.organizations).toEqual(['org-1', 'org-2'])
  })

  it('still answers the list when the store cannot be read', async () => {
    storeState.organisationsById.mockRejectedValueOnce(new Error('store down'))

    const body = await callOrganizations()

    expect(body.names).toEqual({})
    expect(body.organizations).toEqual(['org-1', 'org-2'])
  })

  it('asks for no labels when the deployment holds no records', async () => {
    storeState.organisationStoreConfigured.mockReturnValueOnce(false)
    storeState.organisationsById.mockClear()

    const body = await callOrganizations()

    expect(body.names).toEqual({})
    expect(storeState.organisationsById).not.toHaveBeenCalled()
  })
})
