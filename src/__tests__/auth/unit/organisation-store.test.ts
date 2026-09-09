import { describe, it, expect, vi, beforeEach } from 'vitest'

// The store answers about a SUBJECT, which is the one thing the inferred model cannot do and the
// reason this exists. Two properties are load-bearing and neither is visible from the shape of the
// code: it never answers an empty list when it could not read, and it never keys on an address.

const { poolState, envState } = vi.hoisted(() => ({
  poolState: { query: vi.fn(), end: vi.fn(async () => {}) },
  envState: {
    env: {
      ORGANISATION_DATABASE_URL: 'postgres://somewhere/db',
      ORGANISATION_DATABASE_POOL_MAX: 5,
      ORGANISATION_DATABASE_TIMEOUT_MS: 5000,
    } as Record<string, unknown>,
  },
}))

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
const PoolMock = vi.fn(() => poolState)
vi.mock('pg', () => ({ Pool: PoolMock }))

const store = await import('../../../services/organisation-store.js')

function answers(...rows: unknown[][]) {
  // The first call is the schema; every read awaits it.
  poolState.query.mockReset()
  poolState.query.mockResolvedValueOnce({ rows: [] })
  for (const set of rows) poolState.query.mockResolvedValueOnce({ rows: set })
}

describe('organisationsForSubject', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    envState.env.ORGANISATION_DATABASE_URL = 'postgres://somewhere/db'
  })

  it('asks by subject, with the value bound and never interpolated', async () => {
    answers([{ organisation_id: 'org-a' }, { organisation_id: 'org-b' }])

    await expect(store.organisationsForSubject('9f1c-subject')).resolves.toEqual(['org-a', 'org-b'])

    const [sql, values] = poolState.query.mock.calls[1] as [string, unknown[]]
    expect(sql).toContain('subject_id = $1')
    expect(sql).not.toContain('9f1c-subject')
    expect(values).toEqual(['9f1c-subject'])
    // Keying on an address would move an entitlement when somebody changes theirs.
    expect(sql).not.toMatch(/email/i)
  })

  it('answers nothing for a caller with no subject, without asking', async () => {
    answers()
    await expect(store.organisationsForSubject('')).resolves.toEqual([])
    expect(poolState.query).not.toHaveBeenCalled()
  })

  it('REFUSES rather than answering an empty list when it cannot read', async () => {
    // The whole point. An empty list authorises nothing but reads as "belongs to nothing", which
    // sends somebody to ask for access they already have — and hides an outage as a permission.
    poolState.query.mockReset()
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockRejectedValueOnce(new Error('connection refused'))

    await expect(store.organisationsForSubject('9f1c-subject')).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
  })

  it('refuses when a schema it could not prepare is asked for', async () => {
    poolState.query.mockReset()
    poolState.query.mockRejectedValueOnce(new Error('database starting up'))

    await expect(store.organisationsForSubject('s')).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
  })

  it('tries the schema again after a failure, rather than giving up for the process life', async () => {
    poolState.query.mockReset()
    poolState.query.mockRejectedValueOnce(new Error('database starting up'))
    await expect(store.organisationsForSubject('s')).rejects.toThrow()

    // A database that was merely starting up must not leave this convinced for ever.
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockResolvedValueOnce({ rows: [{ organisation_id: 'org-a' }] })
    await expect(store.organisationsForSubject('s')).resolves.toEqual(['org-a'])
  })

  it('refuses when the deployment named no store at all', async () => {
    envState.env.ORGANISATION_DATABASE_URL = undefined
    await store.closeOrganisationStore()

    await expect(store.organisationsForSubject('s')).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
    expect(store.organisationStoreConfigured()).toBe(false)
  })
})

describe('how it connects', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    PoolMock.mockClear()
    envState.env.ORGANISATION_DATABASE_URL = 'postgres://somewhere/db'
    delete envState.env.ORGANISATION_DATABASE_CA
  })

  it('verifies the certificate against the authority the deployment names', async () => {
    envState.env.ORGANISATION_DATABASE_CA = '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----'
    answers([])
    await store.allOrganisations()

    const config = PoolMock.mock.calls[0][0] as { ssl?: { ca?: string; rejectUnauthorized?: boolean } }
    // Not disabled — checked against a named authority. Disabling instead would encrypt the
    // connection to whatever answered, which reads as protection and is not.
    expect(config.ssl?.rejectUnauthorized).toBe(true)
    expect(config.ssl?.ca).toContain('BEGIN CERTIFICATE')
  })

  it('says nothing about TLS when no authority is named, leaving the address to decide', async () => {
    answers([])
    await store.allOrganisations()

    const config = PoolMock.mock.calls[0][0] as { ssl?: unknown }
    expect(config.ssl).toBeUndefined()
  })
})

describe('reading organisations', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    envState.env.ORGANISATION_DATABASE_URL = 'postgres://somewhere/db'
  })

  it('keeps the order asked for, and drops what it does not hold', async () => {
    answers([
      { id: 'org-b', name: 'Essential', tenant: 'essential', attributes: { tier: 2 } },
      { id: 'org-a', name: 'Business', tenant: 'business', attributes: null },
    ])

    const held = await store.organisationsById(['org-a', 'org-missing', 'org-b'])

    expect(held.map((x) => x.id)).toEqual(['org-a', 'org-b'])
    // A null column must not become a null object somebody then reads a property off.
    expect(held[0].attributes).toEqual({})
    expect(held[1].attributes).toEqual({ tier: 2 })
  })

  it('asks nothing when nothing was asked for', async () => {
    answers()
    await expect(store.organisationsById([])).resolves.toEqual([])
    expect(poolState.query).not.toHaveBeenCalled()
  })
})
