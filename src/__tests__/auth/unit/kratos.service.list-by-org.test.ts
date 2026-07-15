import { describe, it, expect, beforeEach, vi } from 'vitest'

const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
    KRATOS_REQUEST_TIMEOUT_MS: 10000,
  },
}))

import { KratosService } from '../../../services/kratos.service.js'

function page(identities: unknown[], nextToken?: string) {
  const link = nextToken
    ? `</admin/identities?page_size=250&page_token=${nextToken}>; rel="next"`
    : null
  return {
    ok: true,
    status: 200,
    headers: { get: (h: string) => (h.toLowerCase() === 'link' ? link : null) },
    json: () => Promise.resolve(identities),
  }
}

const mk = (id: string, org: string | null, email = `${id}@ex.io`) => ({
  id,
  schema_id: 'default',
  state: 'active',
  traits: { email },
  organization_id: org,
})

describe('KratosService.listIdentitiesByOrganization (J9 pagination)', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    service = new KratosService()
  })

  it('follows the Link header across all pages (does not drop members past page 1)', async () => {
    mockFetch
      .mockResolvedValueOnce(page([mk('u1', 'org-a'), mk('u2', 'org-a')], 'TOK2'))
      .mockResolvedValueOnce(page([mk('u3', 'org-a')])) // last page, no next

    const { identities } = await service.listIdentitiesByOrganization('org-a')

    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(identities.map((i) => i.id)).toEqual(['u1', 'u2', 'u3'])
    // page 1 carries the org filter; page 2 carries the next page_token
    expect(String(mockFetch.mock.calls[0][0])).toContain('organization_id=org-a')
    expect(String(mockFetch.mock.calls[1][0])).toContain('page_token=TOK2')
  })

  it('defensively drops identities whose organization_id does not match (Kratos filter bypass)', async () => {
    // Simulate Kratos returning a foreign-org identity anyway.
    mockFetch.mockResolvedValueOnce(page([mk('u1', 'org-a'), mk('x', 'org-b'), mk('y', null)]))

    const { identities } = await service.listIdentitiesByOrganization('org-a')

    expect(identities.map((i) => i.id)).toEqual(['u1'])
  })

  it('passes credentials_identifier through to Kratos (server-side exact match)', async () => {
    mockFetch.mockResolvedValueOnce(page([mk('u1', 'org-a', 'target@ex.io')]))

    await service.listIdentitiesByOrganization('org-a', { credentialsIdentifier: 'target@ex.io' })

    const url = String(mockFetch.mock.calls[0][0])
    expect(url).toContain('credentials_identifier=target%40ex.io')
    expect(url).toContain('organization_id=org-a')
  })

  it('stops when a page repeats its token or returns empty (no infinite loop)', async () => {
    mockFetch
      .mockResolvedValueOnce(page([mk('u1', 'org-a')], 'SAME'))
      .mockResolvedValueOnce(page([mk('u2', 'org-a')], 'SAME')) // same token → stop after this

    const { identities } = await service.listIdentitiesByOrganization('org-a')

    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(identities.map((i) => i.id)).toEqual(['u1', 'u2'])
  })
})
