import { describe, it, expect } from 'vitest'
import type { JWTPayload } from 'jose'
import { organisationsFromClaims } from '../../../services/oidc-bearer.service.js'

// Reading organisations off a token is an authorization input, so what it does with a shape it does
// not recognise matters as much as what it does with one it does: nothing, rather than a guess.
// Granting nothing is recoverable; granting the wrong organisation is not.

function claims(orgs: unknown): JWTPayload {
  return { sub: 'a-subject', orgs } as JWTPayload
}

describe('organisationsFromClaims', () => {
  it('reads a list of identifiers', () => {
    expect(organisationsFromClaims(claims(['org-a', 'org-b']), 'orgs')).toEqual(['org-a', 'org-b'])
  })

  it('reads a list of objects carrying an identifier', () => {
    const payload = claims([{ id: 'org-a', tns: 'premium' }, { id: 'org-b', tns: 'business' }])

    expect(organisationsFromClaims(payload, 'orgs')).toEqual(['org-a', 'org-b'])
  })

  it('accepts the other spellings an issuer might use for that identifier', () => {
    const payload = claims([{ organisationId: 'org-a' }, { organization_id: 'org-b' }])

    expect(organisationsFromClaims(payload, 'orgs')).toEqual(['org-a', 'org-b'])
  })

  it('reads a single value as a list of one', () => {
    expect(organisationsFromClaims(claims('org-a'), 'orgs')).toEqual(['org-a'])
  })

  it('reads the claim the deployment names, and not another', () => {
    const payload = { sub: 'a-subject', tenants: ['org-a'], orgs: ['org-b'] } as JWTPayload

    expect(organisationsFromClaims(payload, 'tenants')).toEqual(['org-a'])
  })

  it('yields nothing for an absent claim', () => {
    expect(organisationsFromClaims({ sub: 'a-subject' } as JWTPayload, 'orgs')).toEqual([])
  })

  it('yields nothing for a shape it cannot read, rather than guessing', () => {
    // A number, an object, a boolean: all mean the issuer and this reader disagree, and the safe
    // reading of a disagreement about permissions is none.
    expect(organisationsFromClaims(claims(42), 'orgs')).toEqual([])
    expect(organisationsFromClaims(claims({ premium: true }), 'orgs')).toEqual([])
    expect(organisationsFromClaims(claims(true), 'orgs')).toEqual([])
    expect(organisationsFromClaims(claims(null), 'orgs')).toEqual([])
  })

  it('drops the entries it cannot read from a list it otherwise can', () => {
    const payload = claims(['org-a', 42, { nothing: 'useful' }, { id: 'org-b' }, ''])

    expect(organisationsFromClaims(payload, 'orgs')).toEqual(['org-a', 'org-b'])
  })
})
