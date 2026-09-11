import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

// This is the one route that answers about somebody who is not the caller. Its credential is
// therefore the thing worth testing: a session cookie or a user's own bearer token must not open it,
// because whoever held one could enumerate the directory.

const { tokens, store } = vi.hoisted(() => ({
  tokens: { verify: vi.fn(async () => null as { tokenId: string; label: string } | null) },
  store: {
    organisationStoreConfigured: vi.fn(() => true),
    organisationsForSubject: vi.fn(async () => ['org-a', 'org-unknown']),
    organisationsById: vi.fn(async () => [
      { id: 'org-a', name: 'Business', tenant: 'business', attributes: {} },
    ]),
  },
}))

vi.mock('../../../services/scim-token.service.js', () => ({ scimTokenService: tokens }))
vi.mock('../../../services/organisation-store.js', () => store)
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async () => {}) },
}))

const { directoryRoutes } = await import('../../../routes/directory.routes.js')

/** Collects the hook and the handler the plugin registers, and drives them like Fastify would. */
async function mount() {
  let hook: ((request: unknown, reply: unknown) => Promise<unknown>) | null = null
  let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | null = null

  await directoryRoutes({
    addHook: (_name: string, fn: typeof hook) => {
      hook = fn
    },
    get: (_path: string, _opts: unknown, fn: typeof handler) => {
      handler = fn
    },
  } as never)

  return async (headers: Record<string, string>, subject = 'subject-1') => {
    const answer: { code?: number; body?: Record<string, unknown> } = {}
    const reply = {
      status: (code: number) => {
        answer.code = code
        return reply
      },
      send: (body: Record<string, unknown>) => {
        answer.body = body
        return reply
      },
    } as unknown as FastifyReply
    const request = {
      headers,
      method: 'GET',
      url: '/api/directory/organisations',
      ip: '10.0.0.1',
      query: { subject },
      log: { error: vi.fn(), warn: vi.fn() },
    } as unknown as FastifyRequest

    await hook!(request, reply)
    if (answer.code === 401) return answer
    await handler!(request, reply)
    return answer
  }
}

describe('the directory route — who may ask', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    store.organisationStoreConfigured.mockReturnValue(true)
    store.organisationsForSubject.mockResolvedValue(['org-a', 'org-unknown'])
    store.organisationsById.mockResolvedValue([
      { id: 'org-a', name: 'Business', tenant: 'business', attributes: {} },
    ])
  })

  it('refuses a caller with no credential, without saying why', async () => {
    tokens.verify.mockResolvedValue(null)
    const call = await mount()

    const answer = await call({})

    expect(answer.code).toBe(401)
    // "Absent" and "unknown" answer alike: the difference is a probing aid.
    expect(JSON.stringify(answer.body)).not.toMatch(/missing|absent|expired|unknown token/i)
    expect(store.organisationsForSubject).not.toHaveBeenCalled()
  })

  it('refuses a token this service does not recognise', async () => {
    tokens.verify.mockResolvedValue(null)
    const call = await mount()

    const answer = await call({ authorization: 'Bearer not-a-token' })

    expect(answer.code).toBe(401)
    expect(store.organisationsForSubject).not.toHaveBeenCalled()
  })

  it('answers a machine credential, about a subject that is not the caller', async () => {
    tokens.verify.mockResolvedValue({ tokenId: 't1', label: 'strada-login' })
    const call = await mount()

    const answer = await call({ authorization: 'Bearer good' }, 'somebody-else')

    expect(store.organisationsForSubject).toHaveBeenCalledWith('somebody-else')
    expect(answer.body?.subject).toBe('somebody-else')
  })

  it('keeps an organisation it has no record for, named after itself', async () => {
    // Dropping it would quietly narrow the answer, and a token minted from a narrowed answer opens
    // less than it should with nothing to say so.
    tokens.verify.mockResolvedValue({ tokenId: 't1', label: 'strada-login' })
    const call = await mount()

    const answer = await call({ authorization: 'Bearer good' })

    expect(answer.body?.organisations).toEqual([
      { id: 'org-a', name: 'Business', tenant: 'business' },
      { id: 'org-unknown', name: 'org-unknown', tenant: '' },
    ])
  })

  it('refuses rather than answering an empty set when it holds no records at all', async () => {
    tokens.verify.mockResolvedValue({ tokenId: 't1', label: 'strada-login' })
    store.organisationStoreConfigured.mockReturnValue(false)
    const call = await mount()

    const answer = await call({ authorization: 'Bearer good' })

    expect(answer.code).toBe(503)
  })

  it('refuses rather than answering an empty set when the store cannot be read', async () => {
    tokens.verify.mockResolvedValue({ tokenId: 't1', label: 'strada-login' })
    store.organisationsForSubject.mockRejectedValue(new Error('store down'))
    const call = await mount()

    const answer = await call({ authorization: 'Bearer good' })

    expect(answer.code).toBe(503)
  })
})
