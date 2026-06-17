import { describe, it, expect, beforeEach, vi } from 'vitest'

// Must mock fetch and env before importing the service so the
// constructor reads the test URL.
const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
  },
}))

import { KratosService, KratosApiError } from '../../../services/kratos.service.js'

const ORG_A = '11111111-1111-1111-1111-111111111111'
const ORG_B = '22222222-2222-2222-2222-222222222222'

function baseIdentity(extras: {
  organization_id?: string | null
  metadata_admin?: Record<string, unknown> | null
} = {}) {
  return {
    id: 'user-123',
    schema_id: 'default',
    state: 'active',
    traits: { email: 'alice@example.org' },
    metadata_admin: extras.metadata_admin ?? null,
    metadata_public: {},
    organization_id: extras.organization_id ?? null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }
}

describe('KratosService — Path 3 hybrid organization helpers', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    service = new KratosService()
  })

  // ───────────────────────────────────────────────────────────────
  // getOrganizationMemberships
  // ───────────────────────────────────────────────────────────────

  describe('getOrganizationMemberships', () => {
    it('returns metadata_admin.organizations verbatim when present', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(baseIdentity({ metadata_admin: { organizations: [ORG_A, ORG_B] } })),
      })

      const out = await service.getOrganizationMemberships('user-123')

      expect(out).toEqual([ORG_A, ORG_B])
    })

    it('returns [] when metadata_admin is null', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(baseIdentity({ metadata_admin: null })),
      })

      expect(await service.getOrganizationMemberships('user-123')).toEqual([])
    })

    it('returns [] when metadata_admin.organizations is absent', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(baseIdentity({ metadata_admin: { groups: ['admins'] } })),
      })

      expect(await service.getOrganizationMemberships('user-123')).toEqual([])
    })

    it('de-duplicates and filters non-string entries defensively', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(
            baseIdentity({
              metadata_admin: { organizations: [ORG_A, ORG_A, null, 42, ORG_B] as unknown[] },
            }),
          ),
      })

      const out = await service.getOrganizationMemberships('user-123')

      expect(out).toEqual([ORG_A, ORG_B])
    })
  })

  // ───────────────────────────────────────────────────────────────
  // getOrganizationContext
  // ───────────────────────────────────────────────────────────────

  describe('getOrganizationContext', () => {
    it('returns both primary and organizations for a hybrid identity', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(
            baseIdentity({
              organization_id: ORG_A,
              metadata_admin: { organizations: [ORG_B] },
            }),
          ),
      })

      const ctx = await service.getOrganizationContext('user-123')

      expect(ctx).toEqual({ primary: ORG_A, organizations: [ORG_B] })
    })

    it('returns primary:null and organizations:[] for a brand-new identity', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(baseIdentity({})),
      })

      expect(await service.getOrganizationContext('user-123')).toEqual({
        primary: null,
        organizations: [],
      })
    })
  })

  // ───────────────────────────────────────────────────────────────
  // updateUserOrganizations
  // ───────────────────────────────────────────────────────────────

  describe('updateUserOrganizations', () => {
    it('preserves other metadata_admin keys while writing organizations', async () => {
      // 1st fetch: listIdentities by email
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            baseIdentity({
              metadata_admin: { groups: ['admins'], some_other_key: 'preserve-me' },
            }),
          ]),
      })
      // 2nd fetch: getIdentity called by updateIdentity to fetch current state
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(
            baseIdentity({
              metadata_admin: { groups: ['admins'], some_other_key: 'preserve-me' },
            }),
          ),
      })
      // 3rd fetch: updateIdentity PUT
      let capturedBody: unknown = null
      mockFetch.mockImplementationOnce(async (_url: string, opts: RequestInit) => {
        capturedBody = JSON.parse(opts.body as string)
        return {
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve(
              baseIdentity({
                metadata_admin: {
                  groups: ['admins'],
                  some_other_key: 'preserve-me',
                  organizations: [ORG_A, ORG_B],
                },
              }),
            ),
        }
      })

      const result = await service.updateUserOrganizations('alice@example.org', [ORG_A, ORG_B])

      expect(result.metadata_admin).toBeTruthy()
      const body = capturedBody as { metadata_admin: Record<string, unknown> }
      expect(body.metadata_admin).toEqual({
        groups: ['admins'],
        some_other_key: 'preserve-me',
        organizations: [ORG_A, ORG_B],
      })
    })

    it('de-duplicates the organizations array before persisting', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: {} })]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(baseIdentity({ metadata_admin: {} })),
      })
      let captured: unknown = null
      mockFetch.mockImplementationOnce(async (_url, opts: RequestInit) => {
        captured = JSON.parse(opts.body as string)
        return {
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve(
              baseIdentity({ metadata_admin: { organizations: [ORG_A, ORG_B] } }),
            ),
        }
      })

      await service.updateUserOrganizations('alice@example.org', [ORG_A, ORG_A, ORG_B, ORG_A])

      const body = captured as { metadata_admin: Record<string, unknown> }
      expect(body.metadata_admin.organizations).toEqual([ORG_A, ORG_B])
    })

    it('accepts an empty array (removes all memberships)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            baseIdentity({ metadata_admin: { organizations: [ORG_A] } }),
          ]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve(
            baseIdentity({ metadata_admin: { organizations: [ORG_A] } }),
          ),
      })
      let captured: unknown = null
      mockFetch.mockImplementationOnce(async (_url, opts: RequestInit) => {
        captured = JSON.parse(opts.body as string)
        return {
          ok: true,
          status: 200,
          json: () => Promise.resolve(baseIdentity({ metadata_admin: { organizations: [] } })),
        }
      })

      await service.updateUserOrganizations('alice@example.org', [])

      const body = captured as { metadata_admin: Record<string, unknown> }
      expect(body.metadata_admin.organizations).toEqual([])
    })

    it('throws KratosApiError(404) when the email has no identity', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      })

      await expect(
        service.updateUserOrganizations('ghost@example.org', [ORG_A]),
      ).rejects.toBeInstanceOf(KratosApiError)
    })

    it('invalidates the groups cache after a successful write', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: {} })]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(baseIdentity({ metadata_admin: {} })),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(baseIdentity({ metadata_admin: { organizations: [ORG_A] } })),
      })

      const spy = vi.spyOn(service, 'invalidateGroupsCache')
      await service.updateUserOrganizations('alice@example.org', [ORG_A])
      expect(spy).toHaveBeenCalled()
    })
  })

  // ───────────────────────────────────────────────────────────────
  // getAllIdentitiesMetadata
  // ───────────────────────────────────────────────────────────────

  describe('getAllIdentitiesMetadata', () => {
    it('aggregates groups, organizations, and the legacy pointer per email', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            baseIdentity({
              metadata_admin: { groups: ['admins'], organizations: [ORG_A, ORG_B] },
              organization_id: ORG_B,
            }),
            {
              ...baseIdentity({ metadata_admin: { groups: ['users'] } }),
              id: 'user-456',
              traits: { email: 'bob@example.org' },
            },
          ]),
      })

      const out = await service.getAllIdentitiesMetadata()

      expect(out.get('alice@example.org')).toEqual({
        groups: ['admins'],
        organizations: [ORG_A, ORG_B],
        organizationPrimary: ORG_B,
      })
      expect(out.get('bob@example.org')).toEqual({
        groups: ['users'],
        organizations: [],
        organizationPrimary: null,
      })
    })

    it('defaults missing groups to ["users"]', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: null })]),
      })

      const out = await service.getAllIdentitiesMetadata()
      expect(out.get('alice@example.org')?.groups).toEqual(['users'])
    })

    it('caches results across rapid calls (single Kratos hit)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: { groups: ['admins'] } })]),
      })

      await service.getAllIdentitiesMetadata()
      await service.getAllIdentitiesMetadata()

      expect(mockFetch).toHaveBeenCalledTimes(1)
    })

    it('invalidateGroupsCache forces a re-fetch on the next call', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: { groups: ['admins'] } })]),
      })

      await service.getAllIdentitiesMetadata()
      service.invalidateGroupsCache()

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([baseIdentity({ metadata_admin: { groups: ['users'] } })]),
      })

      const out = await service.getAllIdentitiesMetadata()
      expect(out.get('alice@example.org')?.groups).toEqual(['users'])
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })
  })
})
