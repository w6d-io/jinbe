import { describe, it, expect, vi } from 'vitest'

// All handlers enabled — exercises the full mapping incl. the bearer +
// introspection combination (both read `Authorization: Bearer`; the Kratos
// bearer must switch to X-Session-Token so the chain can actually fall back).
vi.mock('../../services/oathkeeper-handlers.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/oathkeeper-handlers.js')>()),
  isHandlerEnabled: () => true,
}))

const { buildSignInAuthenticators } = await import('../../services/rbac.service.js')

describe('buildSignInAuthenticators (all handlers enabled)', () => {
  it('bearer alone uses the default Authorization header', () => {
    expect(buildSignInAuthenticators(['bearer'])).toEqual([{ handler: 'bearer_token' }])
  })

  it('bearer + introspection moves the Kratos bearer to X-Session-Token', () => {
    expect(buildSignInAuthenticators(['bearer', 'introspection'])).toEqual([
      { handler: 'bearer_token', config: { token_from: { header: 'X-Session-Token' } } },
      { handler: 'oauth2_introspection' },
    ])
  })

  it('all three produce the fixed fallback order', () => {
    expect(buildSignInAuthenticators(['introspection', 'bearer', 'cookie']).map((a) => a.handler)).toEqual([
      'cookie_session',
      'bearer_token',
      'oauth2_introspection',
    ])
  })
})
