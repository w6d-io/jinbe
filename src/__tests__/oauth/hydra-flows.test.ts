import { describe, it, expect, beforeEach, vi } from 'vitest'

// The Hydra admin calls of the login/consent provider: paths, methods, encoding and the admin token.

vi.mock('../../config/index.js', async (orig) => {
  const real = (await orig()) as { env: object }
  return { ...real, env: Object.assign(Object.create(real.env), { HYDRA_ADMIN_URL: 'http://hydra-admin:4445', HYDRA_ADMIN_TOKEN: 'adm' }) }
})

import { hydraFlows } from '../../services/hydra-flows.service.js'
import { HydraApiError } from '../../services/hydra.service.js'

const calls: Array<{ url: string; method: string; body?: string; auth: string | null }> = []
let answer: () => Response = () => Response.json({ redirect_to: 'https://x' })

beforeEach(() => {
  calls.length = 0
  answer = () => Response.json({ redirect_to: 'https://x' })
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url: String(url), method: init.method ?? 'GET', body: init.body as string | undefined, auth: new Headers(init.headers).get('authorization') })
    return answer()
  }))
})

describe('hydraFlows', () => {
  it('reads and answers login and consent requests with the challenge encoded', async () => {
    await hydraFlows.getLoginRequest('a b&c')
    await hydraFlows.acceptLogin('L', { subject: 'u', remember: false })
    await hydraFlows.rejectLogin('L', { error: 'access_denied' })
    await hydraFlows.getConsentRequest('C')
    await hydraFlows.acceptConsent('C', { grant_scope: ['mcp'], grant_access_token_audience: ['https://mcp'], remember: false, session: { access_token: {}, id_token: {} } })
    await hydraFlows.rejectConsent('C', { error: 'access_denied' })
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'GET http://hydra-admin:4445/admin/oauth2/auth/requests/login?login_challenge=a%20b%26c',
      'PUT http://hydra-admin:4445/admin/oauth2/auth/requests/login/accept?login_challenge=L',
      'PUT http://hydra-admin:4445/admin/oauth2/auth/requests/login/reject?login_challenge=L',
      'GET http://hydra-admin:4445/admin/oauth2/auth/requests/consent?consent_challenge=C',
      'PUT http://hydra-admin:4445/admin/oauth2/auth/requests/consent/accept?consent_challenge=C',
      'PUT http://hydra-admin:4445/admin/oauth2/auth/requests/consent/reject?consent_challenge=C',
    ])
    expect(JSON.parse(calls[1].body!)).toEqual({ subject: 'u', remember: false })
    expect(calls.every((c) => c.auth === 'Bearer adm')).toBe(true)
  })

  it('lists and revokes consent sessions per subject and client', async () => {
    answer = () => Response.json([{ grant_scope: ['mcp'] }])
    expect(await hydraFlows.listConsentSessions('user 1')).toEqual([{ grant_scope: ['mcp'] }])
    answer = () => new Response(null, { status: 204 })
    await hydraFlows.revokeConsentSessions('user-1', 'c-1')
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'GET http://hydra-admin:4445/admin/oauth2/auth/sessions/consent?subject=user%201&page_size=500',
      'DELETE http://hydra-admin:4445/admin/oauth2/auth/sessions/consent?subject=user-1&client=c-1',
    ])
  })

  it('treats a non-list consent answer as none', async () => {
    answer = () => Response.json(null)
    expect(await hydraFlows.listConsentSessions('u')).toEqual([])
  })

  it('patches a client with a JSON Patch, and surfaces a failed test op as HydraApiError 400', async () => {
    answer = () => Response.json({ error: 'test failed' }, { status: 400 })
    await expect(hydraFlows.patchClient('c-1', [{ op: 'test', path: '/metadata/bound_subject', value: null }])).rejects.toBeInstanceOf(HydraApiError)
    expect(calls[0]).toMatchObject({ method: 'PATCH', url: 'http://hydra-admin:4445/admin/clients/c-1' })
  })
})
