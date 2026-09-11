import { describe, it, expect } from 'vitest'
import { STEP_UP_MAX_AGE_MS, secondFactorIsFresh, stepUpFailure } from '../../services/step-up.js'
import { secondFactorProvenAt } from '../../services/kratos-session.service.js'
import type { KratosSession } from '../../services/kratos-session.service.js'

const NOW = Date.parse('2026-09-11T09:00:00Z')
const ago = (ms: number) => new Date(NOW - ms).toISOString()

const session = (methods: Array<{ method: string; aal: string; completed_at?: string }>): KratosSession => ({
  id: 's',
  active: true,
  expires_at: new Date(NOW + 3_600_000).toISOString(),
  authenticated_at: ago(8 * 3_600_000),
  authenticator_assurance_level: 'aal2',
  authentication_methods: methods,
  identity: { id: 'i', schema_id: 'default', traits: { email: 'a@b.c' }, state: 'active', created_at: '', updated_at: '' },
})

describe('secondFactorProvenAt', () => {
  it('reads the aal2 method rather than the session-wide authentication time', () => {
    // The live case that produced the bug: the session was stamped by the password, and the
    // step-up 39 seconds later never moved it.
    const s = session([
      { method: 'password', aal: 'aal1', completed_at: '2026-09-11T08:17:06Z' },
      { method: 'totp', aal: 'aal2', completed_at: '2026-09-11T08:17:45Z' },
    ])
    expect(secondFactorProvenAt(s)?.toISOString()).toBe('2026-09-11T08:17:45.000Z')
    expect(secondFactorProvenAt(s)?.toISOString()).not.toBe(new Date(s.authenticated_at).toISOString())
  })

  it('takes the most recent proof when a factor was renewed', () => {
    const s = session([
      { method: 'totp', aal: 'aal2', completed_at: '2026-09-11T08:00:00Z' },
      { method: 'totp', aal: 'aal2', completed_at: '2026-09-11T08:55:00Z' },
    ])
    expect(secondFactorProvenAt(s)?.toISOString()).toBe('2026-09-11T08:55:00.000Z')
  })

  it('answers null rather than guessing when no second factor was proven', () => {
    expect(secondFactorProvenAt(session([{ method: 'password', aal: 'aal1', completed_at: ago(60_000) }]))).toBeNull()
    expect(secondFactorProvenAt(session([{ method: 'totp', aal: 'aal2' }]))).toBeNull()
    expect(secondFactorProvenAt({ ...session([]), authentication_methods: undefined })).toBeNull()
  })
})

describe('secondFactorIsFresh', () => {
  it('accepts a factor proven inside the window', () => {
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: ago(60_000) }, NOW)).toBe(true)
  })

  it('refuses a factor older than the window', () => {
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: ago(STEP_UP_MAX_AGE_MS + 1_000) }, NOW)).toBe(false)
  })

  it('refuses an aal1 session however recent', () => {
    expect(secondFactorIsFresh({ aal: 'aal1', secondFactorAt: ago(0) }, NOW)).toBe(false)
  })

  it('fails closed on an unknown level or an unknown proof time', () => {
    expect(secondFactorIsFresh({ secondFactorAt: ago(0) }, NOW)).toBe(false)
    expect(secondFactorIsFresh({ aal: 'aal2' }, NOW)).toBe(false)
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: null }, NOW)).toBe(false)
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: 'not a date' }, NOW)).toBe(false)
  })

  it('does not accept a first-factor time standing in for the second', () => {
    // An 8-hour-old password login with a fresh TOTP must pass; the reverse must not.
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: ago(8 * 3_600_000) }, NOW)).toBe(false)
  })
})

describe('stepUpFailure', () => {
  it('tells an absent factor from a stale one so each can be said differently', () => {
    expect(stepUpFailure({ aal: 'aal2', secondFactorAt: ago(60_000) }, NOW)).toBeNull()
    expect(stepUpFailure({ aal: 'aal2', secondFactorAt: ago(STEP_UP_MAX_AGE_MS + 1) }, NOW)).toBe('stale')
    expect(stepUpFailure({ aal: 'aal1' }, NOW)).toBe('absent')
    expect(stepUpFailure({ aal: 'aal2' }, NOW)).toBe('absent')
  })
})

describe('a credential that cannot carry a second factor', () => {
  it('is refused under its own name, never as something a step-up would lift', () => {
    // A bearer-proven caller asserts no factor this service reads. Answering `absent` would send
    // an operator to prove one, and the answer would not change — a loop with no exit.
    expect(stepUpFailure({ authVia: 'bearer', aal: 'aal2', secondFactorAt: new Date() }, NOW)).toBe('unprovable')
    expect(stepUpFailure({ authVia: 'machine' }, NOW)).toBe('unprovable')
  })

  it('is never fresh, whatever the token claims', () => {
    expect(secondFactorIsFresh({ authVia: 'bearer', aal: 'aal2', secondFactorAt: new Date(NOW) }, NOW)).toBe(false)
  })

  it('leaves a session — and a context predating the field — judged on its factor', () => {
    expect(secondFactorIsFresh({ authVia: 'session', aal: 'aal2', secondFactorAt: ago(60_000) }, NOW)).toBe(true)
    expect(secondFactorIsFresh({ aal: 'aal2', secondFactorAt: ago(60_000) }, NOW)).toBe(true)
    expect(stepUpFailure({ authVia: 'session', aal: 'aal1' }, NOW)).toBe('absent')
  })
})

describe('what a stale refusal says', () => {
  it('names the real age, because "older than 15 minutes" reads as a broken gate', async () => {
    const { userGroupsService } = await import('../../services/user-groups.service.js')
    const denial = (userGroupsService as unknown as {
      stepUpDenial(a: unknown, e: string): { ok: false; body: { message: string } } | null
    }).stepUpDenial(
      { aal: 'aal2', secondFactorAt: new Date(Date.now() - 16 * 60_000), authVia: 'session' },
      'target@example.com',
    )
    expect(denial?.body.message).toContain('16 minutes ago')
    expect(denial?.body.message).toContain('the limit is 15')
  })
})
