import { describe, it, expect, beforeEach, vi } from 'vitest'

// ── Mock state (vi.hoisted so it's available inside vi.mock factories) ─────────
const mockState = vi.hoisted(() => {
  class HydraApiError extends Error {
    constructor(public statusCode: number, message: string, public details?: unknown) {
      super(message)
      this.name = 'HydraApiError'
    }
  }
  return {
    env: { API_KEY_ALLOWED_SCOPES: ['api:read', 'api:write'] as string[] },
    hydra: {
      createClient: vi.fn(),
      getClient: vi.fn(),
      deleteClient: vi.fn(),
      listClientsByOwner: vi.fn(),
    },
    HydraApiError,
  }
})

vi.mock('../../../config/index.js', () => ({ env: mockState.env }))
vi.mock('../../../services/hydra.service.js', () => ({
  hydraService: mockState.hydra,
  HydraApiError: mockState.HydraApiError,
}))

const HydraApiError = mockState.HydraApiError

// Import after mocking
import { ApiKeyService, ApiKeyError } from '../../../services/api-key.service.js'

const ORG = '11111111-1111-1111-1111-111111111111'

function client(overrides: Record<string, unknown> = {}) {
  return {
    client_id: 'client-abc',
    client_name: 'svc',
    scope: 'api:read',
    owner: ORG,
    metadata: { organization_id: ORG, created_by: 'kratos-id-1' },
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('ApiKeyService', () => {
  let svc: ApiKeyService

  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.API_KEY_ALLOWED_SCOPES = ['api:read', 'api:write']
    svc = new ApiKeyService()
  })

  describe('create', () => {
    it('rejects scopes outside the allowed catalog (400) and never calls Hydra', async () => {
      await expect(
        svc.create({ organizationId: ORG, body: { label: 'x', scopes: ['api:read', 'admin:all'] } })
      ).rejects.toMatchObject({ statusCode: 400 })
      expect(mockState.hydra.createClient).not.toHaveBeenCalled()
    })

    it('passes organizationId + createdBy + deduped scopes to Hydra and returns the secret once', async () => {
      mockState.hydra.createClient.mockResolvedValue(
        client({ client_secret: 'super-secret-once' })
      )

      const result = await svc.create({
        organizationId: ORG,
        body: { label: 'svc', scopes: ['api:read', 'api:read'] },
        createdBy: 'kratos-id-1',
      })

      expect(mockState.hydra.createClient).toHaveBeenCalledWith(
        expect.objectContaining({ organizationId: ORG, createdBy: 'kratos-id-1', scopes: ['api:read'] })
      )
      expect(result.client_secret).toBe('super-secret-once')
      expect(result.organization_id).toBe(ORG)
      // The view itself carries the secret only on the create response shape.
      expect(result.scopes).toEqual(['api:read'])
    })
  })

  describe('get', () => {
    it('404s when the client belongs to another org', async () => {
      mockState.hydra.getClient.mockResolvedValue(
        client({ owner: 'other', metadata: { organization_id: 'other' } })
      )
      await expect(svc.get(ORG, 'client-abc')).rejects.toMatchObject({ statusCode: 404 })
    })

    it('404s (ApiKeyError) when Hydra returns 404', async () => {
      mockState.hydra.getClient.mockRejectedValue(new HydraApiError(404, 'gone'))
      await expect(svc.get(ORG, 'client-abc')).rejects.toBeInstanceOf(ApiKeyError)
    })
  })

  describe('list', () => {
    it('filters to clients owned by the org', async () => {
      mockState.hydra.listClientsByOwner.mockResolvedValue([
        client(),
        client({ client_id: 'other', metadata: { organization_id: 'other' } }),
      ])
      const out = await svc.list(ORG)
      expect(out).toHaveLength(1)
      expect(out[0].client_id).toBe('client-abc')
      expect(mockState.hydra.listClientsByOwner).toHaveBeenCalledWith(ORG)
    })
  })

  describe('revoke', () => {
    it('verifies org ownership before deleting (404 on mismatch, Hydra delete untouched)', async () => {
      mockState.hydra.getClient.mockResolvedValue(
        client({ metadata: { organization_id: 'other' } })
      )
      await expect(svc.revoke(ORG, 'client-abc')).rejects.toMatchObject({ statusCode: 404 })
      expect(mockState.hydra.deleteClient).not.toHaveBeenCalled()
    })

    it('deletes the Hydra client when owned by the org', async () => {
      mockState.hydra.getClient.mockResolvedValue(client())
      mockState.hydra.deleteClient.mockResolvedValue(undefined)
      await expect(svc.revoke(ORG, 'client-abc')).resolves.toBeUndefined()
      expect(mockState.hydra.deleteClient).toHaveBeenCalledWith('client-abc')
    })
  })

  describe('resolveOrganization', () => {
    it('returns null for an unknown client (Hydra 404)', async () => {
      mockState.hydra.getClient.mockRejectedValue(new HydraApiError(404, 'gone'))
      expect(await svc.resolveOrganization('client-abc')).toBeNull()
    })

    it('returns org + scopes from metadata', async () => {
      mockState.hydra.getClient.mockResolvedValue(client({ scope: 'api:read api:write' }))
      expect(await svc.resolveOrganization('client-abc')).toEqual({
        organization_id: ORG,
        scopes: ['api:read', 'api:write'],
      })
    })
  })
})
