import { describe, it, expect } from 'vitest'
import { buildSignInAuthenticators, SERVICE_NAME_PATTERN } from '../../services/rbac.service.js'

// Regression: the route JSON schema and the controller's zod once used two
// DIFFERENT hand-written regexes (route allowed hyphens, controller didn't →
// every hyphenated service name 400'd). Both now import this single constant;
// this pins its behavior.
describe('SERVICE_NAME_PATTERN', () => {
  it('accepts hyphenated, underscored and plain names', () => {
    for (const ok of ['demo-api', 'order-service', 'billing', 'a_b_c', 'svc2']) {
      expect(SERVICE_NAME_PATTERN.test(ok), ok).toBe(true)
    }
  })
  it('rejects uppercase, spaces, dots and empty', () => {
    for (const bad of ['Demo', 'a b', 'svc.name', '', 'svc/name']) {
      expect(SERVICE_NAME_PATTERN.test(bad), bad).toBe(false)
    }
  })
})

// Test env (setup.ts) does not set OATHKEEPER_ENABLED_AUTHENTICATORS, so the
// default enabled set applies: cookie_session,noop. bearer/introspection must
// therefore FAIL CLOSED here — proving a sign-in method can never produce a
// rule the deployed gateway would reject at load.
describe('buildSignInAuthenticators', () => {
  it('maps cookie to cookie_session', () => {
    expect(buildSignInAuthenticators(['cookie'])).toEqual([{ handler: 'cookie_session' }])
  })

  it('maps empty (public) to noop without consulting the enabled set', () => {
    expect(buildSignInAuthenticators([])).toEqual([{ handler: 'noop' }])
  })

  it('keeps the fixed fallback order cookie → bearer → introspection regardless of input order', () => {
    // Enabled-set check would throw for bearer here — assert on the thrown
    // handler name to prove ordering happened before validation.
    try {
      buildSignInAuthenticators(['introspection', 'cookie', 'bearer'])
      expect.unreachable('should have failed closed')
    } catch (err) {
      expect((err as Error).message).toContain("'bearer_token'")
      expect((err as { statusCode?: number }).statusCode).toBe(400)
    }
  })

  it('fails closed when a mapped authenticator is not in the enabled set', () => {
    expect(() => buildSignInAuthenticators(['bearer'])).toThrow(/not enabled on this gateway/)
    expect(() => buildSignInAuthenticators(['introspection'])).toThrow(/not enabled on this gateway/)
  })
})
