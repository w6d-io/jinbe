import { describe, it, expect, beforeEach, vi } from 'vitest'

const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
    KRATOS_REQUEST_TIMEOUT_MS: 10000,
  },
}))

import { KratosApiError, KratosService } from '../../../services/kratos.service.js'

const reply = (status: number, body: unknown = []) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: String(status),
  json: () => Promise.resolve(body),
})

describe('KratosService.listIdentitiesByIdentifierPrefix', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    service = new KratosService()
  })

  it('asks Kratos for one bounded page by identifier prefix, second factors included', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, [{ id: 'a' }, { id: 'b' }, { id: 'c' }]))
    const found = await service.listIdentitiesByIdentifierPrefix('ali+x@', 2)

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const url = new URL(mockFetch.mock.calls[0][0] as string)
    expect(url.pathname).toBe('/admin/identities')
    expect(url.searchParams.get('preview_credentials_identifier_similar')).toBe('ali+x@')
    expect(url.searchParams.get('page_size')).toBe('2')
    expect(url.searchParams.getAll('include_credential')).toEqual(['totp', 'webauthn', 'lookup_secret'])
    expect(found?.map((i) => i.id)).toEqual(['a', 'b'])
  })

  it('answers null when this Kratos refuses the parameter, so the caller can fall back', async () => {
    mockFetch.mockResolvedValueOnce(reply(400, { error: { reason: 'unknown parameter' } }))
    expect(await service.listIdentitiesByIdentifierPrefix('ali', 5)).toBeNull()
  })

  it('throws on any other failure rather than answering nobody', async () => {
    mockFetch.mockResolvedValueOnce(reply(500))
    await expect(service.listIdentitiesByIdentifierPrefix('ali', 5)).rejects.toBeInstanceOf(KratosApiError)
  })
})
