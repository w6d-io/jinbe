import { describe, it, expect, vi, beforeEach } from 'vitest'

// Assigning somebody is now a record, so the properties worth locking are the ones a reader cannot
// see from the SQL: assigning twice is not an error, a subject that no longer exists keeps no rows
// anywhere, and a value never reaches the statement itself.

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

/** A subject carrying the punctuation that ends a statement, if it were ever written into one. */
const HOSTILE_SUBJECT = "subject'; --"

function written() {
  return poolState.query.mock.calls.map((c) => String(c[0]))
}

function callFor(fragment: string) {
  return poolState.query.mock.calls.find((c) => String(c[0]).includes(fragment))!
}

describe('addMember', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    // Reset, not clear: an earlier test removes the implementation, and clearing alone would leave
    // the mock answering undefined.
    poolState.query.mockReset()
    poolState.query.mockResolvedValue({ rows: [] })
  })

  it('assigns idempotently, so a repair can be re-run', async () => {
    await store.addMember('org-a', 'subject-1', 'member')

    const insert = written().find((s) => s.includes('INSERT INTO organisation_members'))
    expect(insert).toContain('ON CONFLICT (organisation_id, subject_id, role) DO NOTHING')
  })

  it('binds every value instead of writing it into the statement', async () => {
    await store.addMember('org-a', HOSTILE_SUBJECT, 'member')

    const call = callFor('INSERT INTO organisation_members')
    expect(String(call[0])).not.toContain(HOSTILE_SUBJECT)
    expect(call[1]).toEqual(['org-a', HOSTILE_SUBJECT, 'member'])
  })

  it('refuses rather than reporting success when the store cannot be written', async () => {
    poolState.query.mockReset()
    poolState.query.mockResolvedValueOnce({ rows: [] })
    poolState.query.mockRejectedValueOnce(new Error('read only'))

    await expect(store.addMember('org-a', 'subject-1', 'member')).rejects.toThrow(
      store.OrganisationStoreUnavailableError,
    )
  })
})

describe('removing somebody', () => {
  beforeEach(async () => {
    await store.closeOrganisationStore()
    // Reset, not clear: an earlier test removes the implementation, and clearing alone would leave
    // the mock answering undefined.
    poolState.query.mockReset()
    poolState.query.mockResolvedValue({ rows: [] })
  })

  it('takes one role away without taking the membership', async () => {
    await store.removeMember('org-a', 'subject-1', 'org_admin')

    const call = callFor('organisation_members WHERE organisation_id')
    expect(String(call[0])).toContain('role = $3')
    expect(call[1]).toEqual(['org-a', 'subject-1', 'org_admin'])
  })

  it('takes the whole membership when no role is named', async () => {
    await store.removeMember('org-a', 'subject-1')

    const call = callFor('organisation_members WHERE organisation_id')
    expect(String(call[0])).not.toContain('role =')
    expect(call[1]).toEqual(['org-a', 'subject-1'])
  })

  it('clears every organisation for a subject that no longer exists', async () => {
    // A row left behind names a subject nobody can look up, and would grant to whoever is issued
    // that identifier next.
    await store.removeMemberEverywhere('subject-1')

    const call = callFor('organisation_members WHERE subject_id')
    expect(call[1]).toEqual(['subject-1'])
  })
})
