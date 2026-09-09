import { describe, it, expect, vi, beforeEach } from 'vitest'

// An import is judged on what it refuses. Applying a good file is the easy half; the properties
// worth locking are the ones that stop a bad file from becoming a permission decision.

const { poolState, clientState, envState } = vi.hoisted(() => {
  const client = { query: vi.fn(async () => ({ rows: [] })), release: vi.fn() }
  return {
    clientState: client,
    poolState: { query: vi.fn(async () => ({ rows: [] })), connect: vi.fn(async () => client), end: vi.fn(async () => {}) },
    envState: {
      env: {
        ORGANISATION_DATABASE_URL: 'postgres://somewhere/db',
        ORGANISATION_DATABASE_POOL_MAX: 5,
        ORGANISATION_DATABASE_TIMEOUT_MS: 5000,
      } as Record<string, unknown>,
    },
  }
})

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('pg', () => ({ Pool: vi.fn(() => poolState) }))

const store = await import('../../../services/organisation-store.js')

const business = {
  id: '9db7e724-a81d-4fdf-87a5-e37d7213a100',
  name: 'Business',
  tenant: 'business',
  attributes: { tier: 'business' },
  deployments: [{ application: 'efact-backend', enabled: true }],
  members: [{ subjectId: '6a5c8def-38da-4267-b900-7298ed38de91', role: 'org_admin' }],
}

describe('applyOrganisations', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    clientState.query.mockReset()
    clientState.query.mockResolvedValue({ rows: [] })
    clientState.release.mockReset()
    poolState.query.mockResolvedValue({ rows: [] })
  })

  it('writes everything inside one transaction', async () => {
    // A half-applied import is worse than a refused one: the rows that landed grant access, and
    // nothing on screen distinguishes the result from a deliberate state.
    const outcome = await store.applyOrganisations([business])

    const statements = clientState.query.mock.calls.map((c) => String(c[0]))
    expect(statements[0]).toBe('BEGIN')
    expect(statements[statements.length - 1]).toBe('COMMIT')
    expect(outcome).toEqual({ organisations: 1, deployments: 1, members: 1 })
  })

  it('upserts on the identifier the source already had, so a replay changes nothing', async () => {
    await store.applyOrganisations([business])

    const upsert = clientState.query.mock.calls.map((c) => String(c[0])).find((s) => s.includes('INSERT INTO organisations'))
    expect(upsert).toContain('ON CONFLICT (id) DO UPDATE')
  })

  it('REPLACES the deployments and memberships of an organisation it writes', async () => {
    // They describe a whole set. Merging would leave yesterday's removals in place for ever, which
    // is a revoked access that still works.
    await store.applyOrganisations([business])

    const statements = clientState.query.mock.calls.map((c) => String(c[0]))
    expect(statements.some((s) => s.startsWith('DELETE FROM organisation_deployments'))).toBe(true)
    expect(statements.some((s) => s.startsWith('DELETE FROM organisation_members'))).toBe(true)
  })

  it('leaves alone anything not in the input', async () => {
    await store.applyOrganisations([business])

    // No statement may delete an organisation: an input can be incomplete for reasons that have
    // nothing to do with intent, and absence must not read as revoke.
    const statements = clientState.query.mock.calls.map((c) => String(c[0]))
    expect(statements.some((s) => /DELETE FROM organisations\b/.test(s))).toBe(false)
  })

  it('rolls back and writes nothing when one row fails', async () => {
    clientState.query.mockImplementation(async (sql: unknown) => {
      if (String(sql).includes('INSERT INTO organisation_members')) throw new Error('constraint violated')
      return { rows: [] }
    })

    await expect(store.applyOrganisations([business])).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
    expect(clientState.query.mock.calls.map((c) => String(c[0]))).toContain('ROLLBACK')
  })

  it('gives the connection back even when it failed', async () => {
    clientState.query.mockRejectedValue(new Error('gone'))
    await expect(store.applyOrganisations([business])).rejects.toThrow()
    // A leaked connection per failed import exhausts the pool and takes the service with it.
    expect(clientState.release).toHaveBeenCalled()
  })

  it('omits the deployments and memberships it was not given, rather than emptying them', async () => {
    // A file describing only names must not silently revoke every membership it does not mention.
    await store.applyOrganisations([{ id: business.id, name: 'Business', tenant: 'business' }])

    const statements = clientState.query.mock.calls.map((c) => String(c[0]))
    expect(statements.some((s) => s.startsWith('DELETE FROM organisation_members'))).toBe(false)
    expect(statements.some((s) => s.startsWith('DELETE FROM organisation_deployments'))).toBe(false)
  })
})
