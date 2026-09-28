import { describe, it, expect, beforeEach, vi } from 'vitest'

// Quick find: a pasted id is one GET, a whole address one exact match, anything else Kratos's own
// prefix match — the directory is walked (from the cached map) only when the prefix finds nobody.

const ID = '6f1c9a52-3b0e-4d0e-9a55-0f3c2b1d7e10'
const alice = {
  id: ID,
  state: 'active',
  traits: { email: 'alice@example.com', name: 'Alice' },
  organization_id: 'org-1',
  credentials: { totp: { config: { totp_url: 'otpauth://x' } } },
}
const bob = { id: 'b0b00000-0000-4000-8000-000000000000', state: 'inactive', traits: { email: 'bob@example.com' } }

const k = vi.hoisted(() => ({
  getIdentitiesByIds: vi.fn(),
  mfaByIds: vi.fn(),
  listIdentities: vi.fn(),
  listIdentitiesByIdentifierPrefix: vi.fn(),
  searchIdentities: vi.fn(),
  rights: vi.fn(),
  organisationsOf: vi.fn(),
}))

vi.mock('../../services/kratos.service.js', () => {
  class KratosApiError extends Error {
    constructor(public statusCode: number, message: string) { super(message) }
  }
  return {
    KratosApiError,
    MFA_METHODS: ['totp', 'webauthn', 'lookup_secret'],
    kratosService: {
      getIdentitiesByIds: k.getIdentitiesByIds,
      mfaByIds: k.mfaByIds,
      listIdentities: k.listIdentities,
      listIdentitiesByIdentifierPrefix: k.listIdentitiesByIdentifierPrefix,
      searchIdentities: k.searchIdentities,
      mfaFromCredentials: (c: { totp?: { config?: { totp_url?: string } } } | undefined) => !!c?.totp?.config?.totp_url,
    },
  }
})
vi.mock('../../authz/opa.js', () => ({ rights: k.rights }))
vi.mock('../../services/org-membership.service.js', () => ({ organisationsOf: k.organisationsOf }))

import { classify, lookupUsers } from '../../services/user-lookup.service.js'

// The cached, batched reads: identities without credentials, and second factors as method lists.
function known(...identities: Array<{ id: string; credentials?: unknown }>) {
  k.getIdentitiesByIds.mockImplementation(async (ids: string[]) =>
    new Map(identities.filter((i) => ids.includes(i.id)).map((i) => [i.id, i])))
  k.mfaByIds.mockImplementation(async (ids: string[]) =>
    new Map(identities.filter((i) => ids.includes(i.id)).map((i) => [i.id, i.credentials ? ['totp'] : []])))
}

beforeEach(() => {
  for (const f of Object.values(k)) f.mockReset()
  k.rights.mockResolvedValue({ groups: ['ops'], roles: [], permissions: [] })
  k.organisationsOf.mockImplementation(async (i: { organization_id?: string }) => (i.organization_id ? [i.organization_id] : []))
})

describe('classify', () => {
  it('tells an id, an address and a fragment apart', () => {
    expect(classify(ID)).toBe('id')
    expect(classify(ID.toUpperCase())).toBe('id')
    expect(classify('alice@example.com')).toBe('email')
    expect(classify('alice@')).toBe('prefix')
    expect(classify('ali')).toBe('prefix')
  })
})

describe('lookupUsers', () => {
  it('answers a pasted Kratos id from the cached identity, and describes the person', async () => {
    known(alice)
    const answer = await lookupUsers(`  ${ID.toUpperCase()} `)
    expect(k.getIdentitiesByIds).toHaveBeenCalledWith([ID])
    expect(k.mfaByIds).toHaveBeenCalledWith([ID])
    expect(k.listIdentities).not.toHaveBeenCalled()
    expect(k.searchIdentities).not.toHaveBeenCalled()
    expect(answer).toEqual({
      match: 'id',
      data: [{ id: ID, email: 'alice@example.com', name: 'Alice', active: true, groups: ['ops'], organizations: ['org-1'], mfa: true }],
    })
  })

  it('answers an unknown id as nobody, not as an error', async () => {
    known()
    expect(await lookupUsers(ID)).toEqual({ match: 'none', data: [] })
  })

  it('answers a whole address with the exact identifier match, second factors included', async () => {
    k.listIdentities.mockResolvedValue({ identities: [alice] })
    const answer = await lookupUsers('alice@example.com')
    expect(k.listIdentities).toHaveBeenCalledWith(1, undefined, 'alice@example.com', ['totp', 'webauthn', 'lookup_secret'])
    expect(k.listIdentitiesByIdentifierPrefix).not.toHaveBeenCalled()
    expect(answer.match).toBe('email')
  })

  it('answers a fragment with Kratos prefix match, never walking the directory', async () => {
    k.listIdentitiesByIdentifierPrefix.mockResolvedValue([alice, bob])
    const answer = await lookupUsers('b', 50)
    expect(k.listIdentitiesByIdentifierPrefix).toHaveBeenCalledWith('b', 10)
    expect(k.searchIdentities).not.toHaveBeenCalled()
    expect(answer.match).toBe('prefix')
    expect(answer.data.map((h) => [h.email, h.active, h.mfa])).toEqual([
      ['alice@example.com', true, true],
      ['bob@example.com', false, false],
    ])
  })

  it('falls back to the substring search when no address starts with it', async () => {
    k.listIdentitiesByIdentifierPrefix.mockResolvedValue([])
    k.searchIdentities.mockResolvedValue([{ id: ID }])
    known(alice)
    const answer = await lookupUsers('example')
    expect(k.searchIdentities).toHaveBeenCalledWith('example', 10)
    expect(answer.match).toBe('contains')
    expect(answer.data[0].id).toBe(ID)
  })

  it('falls back too when this Kratos has no prefix match (null), but not for a two-letter fragment', async () => {
    k.listIdentitiesByIdentifierPrefix.mockResolvedValue(null)
    expect(await lookupUsers('al')).toEqual({ match: 'none', data: [] })
    expect(k.searchIdentities).not.toHaveBeenCalled()
  })

  it('marks groups and organisations unknown when they cannot be read, never "none"', async () => {
    known(alice)
    k.rights.mockRejectedValue(new Error('opa down'))
    k.organisationsOf.mockRejectedValue(new Error('store down'))
    const [hit] = (await lookupUsers(ID)).data
    expect(hit.groups).toBeNull()
    expect(hit.organizations).toBeNull()
  })
})
