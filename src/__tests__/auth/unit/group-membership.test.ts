import { describe, it, expect, vi, beforeEach } from 'vitest'

// The one fact that grows with the company: which groups a person is in. What a group GIVES lives in
// the repository, so this table stays one row per person per group whatever the number of
// organisations — that is the whole point of it existing.

const { poolState, envState } = vi.hoisted(() => ({
  poolState: { query: vi.fn(async () => ({ rows: [] })), end: vi.fn(async () => {}) },
  envState: {
    env: {
      ORGANISATION_DATABASE_URL: 'postgres://somewhere/db',
      ORGANISATION_DATABASE_POOL_MAX: 5,
      ORGANISATION_DATABASE_TIMEOUT_MS: 5000,
    } as Record<string, unknown>,
  },
}))

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('pg', () => ({ Pool: vi.fn(() => poolState) }))

const store = await import('../../../services/organisation-store.js')

/** The punctuation that ends a statement, if a value were ever written into one. */
const HOSTILE_GROUP = "ops'; --"

function callFor(fragment: string) {
  return poolState.query.mock.calls.find((c) => String(c[0]).includes(fragment))!
}

describe('group membership', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    // Reset, not clear: a later test removes the implementation, and clearing alone would leave the
    // mock answering undefined.
    poolState.query.mockReset()
    poolState.query.mockResolvedValue({ rows: [] })
  })

  it('assigns idempotently, so a repair can be re-run and a double click cannot fail', async () => {
    await store.addToGroup('subject-1', 'ops', 'admin@strada.eu')

    const insert = callFor('INSERT INTO group_members')
    expect(String(insert[0])).toContain('ON CONFLICT (subject_id, group_name) DO NOTHING')
    expect(insert[1]).toEqual(['subject-1', 'ops', 'admin@strada.eu'])
  })

  it('binds every value instead of writing it into the statement', async () => {
    await store.addToGroup('subject-1', HOSTILE_GROUP)

    const insert = callFor('INSERT INTO group_members')
    expect(String(insert[0])).not.toContain(HOSTILE_GROUP)
    expect(insert[1]).toEqual(['subject-1', HOSTILE_GROUP, null])
  })

  it('answers the whole page in one query', async () => {
    poolState.query.mockReset()
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockResolvedValueOnce({
      rows: [
        { subject_id: 's1', group_name: 'ops' },
        { subject_id: 's1', group_name: 'support' },
        { subject_id: 's2', group_name: 'ops' },
      ],
    })

    const held = await store.groupsForSubjects(['s1', 's2', 's3'])

    expect(poolState.query.mock.calls.filter((c) => String(c[0]).includes('FROM group_members')))
      .toHaveLength(1)
    expect(held.get('s1')).toEqual(['ops', 'support'])
    expect(held.get('s2')).toEqual(['ops'])
    // Absent rather than empty: "belongs to no group" and "was not asked about" must not read the
    // same to the caller.
    expect(held.has('s3')).toBe(false)
  })

  it('asks nothing for an empty page', async () => {
    poolState.query.mockClear()
    await expect(store.groupsForSubjects([])).resolves.toEqual(new Map())
    expect(poolState.query).not.toHaveBeenCalled()
  })

  it('reads everybody whole, because a partial answer here removes access silently', async () => {
    poolState.query.mockReset()
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockResolvedValueOnce({
      rows: [
        { subject_id: 's1', group_name: 'ops' },
        { subject_id: 's2', group_name: 'support' },
      ],
    })

    const all = await store.allGroupMemberships()

    // No paging: this feeds the artefact the engine decides against, and a page of it would be a set
    // of rights nobody meant to take away.
    expect(String(callFor('FROM group_members')[0])).not.toMatch(/LIMIT|OFFSET/i)
    expect(all.get('s1')).toEqual(['ops'])
    expect(all.get('s2')).toEqual(['support'])
  })

  it('clears every group of a subject that no longer exists', async () => {
    // A row left behind names a subject nobody can look up, and would grant to whoever is issued
    // that identifier next.
    await store.forgetGroupsOf('subject-1')

    expect(callFor('DELETE FROM group_members WHERE subject_id = $1')[1]).toEqual(['subject-1'])
  })

  it('refuses rather than reporting success when the store cannot be written', async () => {
    poolState.query.mockReset()
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockRejectedValueOnce(new Error('read only'))

    await expect(store.addToGroup('subject-1', 'ops')).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
  })
})
