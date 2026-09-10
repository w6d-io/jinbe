import { describe, it, expect } from 'vitest'
import { contradictions } from '../../../cli/import-organisations.js'
import type { OrganisationRecord } from '../../../services/organisation-store.js'

// An import is judged on what it refuses. Each of these was a real defect before it was a rule.

function record(over: Partial<OrganisationRecord> = {}): OrganisationRecord {
  return {
    id: 'd5c9806e-e4ec-4f4b-8b0b-03cff1086c27',
    name: 'Premium',
    tenant: 'premium',
    attributes: {},
    ...over,
  } as OrganisationRecord
}

describe('what an organisation import refuses', () => {
  it('accepts a record that knows its own name', () => {
    expect(contradictions([record()])).toEqual([])
  })

  it('refuses a record named after its own identifier', () => {
    // Not a name: the absence of one, disguised as one. Stored, it reaches every screen that lists
    // organisations as a raw identifier — five of eight rows in dev arrived this way, and the list
    // read as duplicates of the three real ones.
    const id = 'ff3c75eb-15fc-4c7b-9e6a-144f8ac5b772'
    const problems = contradictions([record({ id, name: id, tenant: 'essential' })])

    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain('named after its own identifier')
  })

  it('refuses it even when the source padded the field', () => {
    const id = 'ff3c75eb-15fc-4c7b-9e6a-144f8ac5b772'
    expect(contradictions([record({ id, name: `  ${id} `, tenant: 'essential' })])).toHaveLength(1)
  })

  it('accepts a name that merely CONTAINS the identifier', () => {
    // A deployment legitimately named after its tenant plus a suffix is still a name. The rule is
    // equality, not resemblance — a looser one would refuse real inputs.
    const id = 'ff3c75eb-15fc-4c7b-9e6a-144f8ac5b772'
    expect(contradictions([record({ id, name: `Essential (${id})`, tenant: 'essential' })])).toEqual([])
  })

  it('refuses one identifier described twice, rather than guessing which was meant', () => {
    const problems = contradictions([record({ name: 'Premium' }), record({ name: 'Premium EU' })])

    expect(problems).toHaveLength(1)
    expect(problems[0]).toContain('appears twice')
  })

  it('refuses a membership keyed on an address', () => {
    // An address is a trait its owner can change: keyed on one, an entitlement moves with it and a
    // reused address inherits the last holder's.
    const problems = contradictions([
      record({ members: [{ subjectId: 'romain.labat@strada.eu', role: 'member' }] } as Partial<OrganisationRecord>),
    ])

    expect(problems.length).toBeGreaterThanOrEqual(1)
  })
})
