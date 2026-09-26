import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// The session cookie name is Kratos' own setting (session.cookie.name). jinbe never needs to know
// it: it forwards every ory_kratos_session* cookie and lets Kratos pick its own.
vi.mock('../../../config/index.js', () => ({ env: { KRATOS_PUBLIC_URL: 'http://kratos-public:4433' } }))

import { KratosSessionService } from '../../../services/kratos-session.service.js'

describe('session cookie name comes from Kratos, not from jinbe', () => {
  it('picks a renamed session cookie and leaves unrelated cookies out', () => {
    const got = KratosSessionService.extractSessionCookie('_ga=GA1.2; ory_kratos_session_sandbox=abc=; theme=dark')
    expect(got).toBe('ory_kratos_session_sandbox=abc=')
  })

  it('forwards every session cookie when several are present', () => {
    const got = KratosSessionService.extractSessionCookie('ory_kratos_session=one; ory_kratos_session_sandbox=two')
    expect(got).toBe('ory_kratos_session=one; ory_kratos_session_sandbox=two')
  })

  it('finds nothing without a session cookie', () => {
    expect(KratosSessionService.extractSessionCookie('_ga=1; csrf_token_abc=x')).toBeNull()
  })

  describe('whoami call', () => {
    const fetchMock = vi.fn(async () => ({ ok: false, status: 401, statusText: 'Unauthorized', json: async () => ({}) }))
    beforeEach(() => { vi.stubGlobal('fetch', fetchMock) })
    afterEach(() => { vi.unstubAllGlobals(); fetchMock.mockClear() })

    it('sends the extracted cookies to Kratos as they were named', async () => {
      await new KratosSessionService().validateSession('ory_kratos_session_sandbox=abc')
      expect(fetchMock).toHaveBeenCalledWith('http://kratos-public:4433/sessions/whoami', expect.objectContaining({ headers: { Cookie: 'ory_kratos_session_sandbox=abc' } }))
    })

    it('still accepts a bare cookie value (default name)', async () => {
      await new KratosSessionService().validateSession('abc')
      expect(fetchMock).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ headers: { Cookie: 'ory_kratos_session=abc' } }))
    })
  })
})
