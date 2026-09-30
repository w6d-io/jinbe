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
    catalog: vi.fn(async () => [
      { scope: 'payroll.runs:read', sites: ['payroll'] },
      { scope: 'payroll:write', sites: ['payroll'] },
    ]),
    changed: vi.fn(),
    forget: vi.fn(),
  }
})

vi.mock('../../../config/index.js', () => ({ env: mockState.env }))
vi.mock('../../../services/api-key-scopes.js', () => ({ scopeCatalog: mockState.catalog }))
vi.mock('../../../services/api-clients.js', () => ({ apiClientsChanged: mockState.changed }))
vi.mock('../../../services/api-key-last-used.js', () => ({ forgetApiKeyUse: mockState.forget }))
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
    it("rejects scopes outside the org's catalog for the caller (400) and never calls Hydra", async () => {
      await expect(
        svc.create({ organizationId: ORG, callerEmail: 'a@x.io', body: { label: 'x', scopes: ['payroll:write', 'admin:all'] } })
      ).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['admin:all'], allowed_scopes: ['payroll.runs:read', 'payroll:write'] } })
      expect(mockState.catalog).toHaveBeenCalledWith(ORG, 'a@x.io')
      expect(mockState.hydra.createClient).not.toHaveBeenCalled()
    })

    it('refuses a wildcard even if a catalog were to list it', async () => {
      mockState.catalog.mockResolvedValueOnce([{ scope: '*', sites: ['x'] }, { scope: 'payroll:*', sites: ['x'] }])
      await expect(
        svc.create({ organizationId: ORG, callerEmail: 'a@x.io', body: { label: 'x', scopes: ['*'] } })
      ).rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['*'] } })
      await expect(
        svc.create({ organizationId: ORG, callerEmail: 'a@x.io', body: { label: 'x', scopes: ['payroll:*'] } })
      ).rejects.toMatchObject({ statusCode: 400 })
      expect(mockState.hydra.createClient).not.toHaveBeenCalled()
    })

    it('records an expiry when asked for one, and tells the policy data a key changed', async () => {
      mockState.hydra.createClient.mockResolvedValue(client({ client_secret: 's', metadata: { organization_id: ORG, expires_at: '2026-10-28T00:00:00.000Z' } }))
      const out = await svc.create({ organizationId: ORG, callerEmail: 'a@x.io', body: { label: 'svc', scopes: ['payroll:write'], expires_in_days: 30 } })
      const arg = mockState.hydra.createClient.mock.calls[0][0]
      expect(Date.parse(arg.expiresAt) - Date.now()).toBeGreaterThan(29 * 86_400_000)
      expect(Date.parse(arg.expiresAt) - Date.now()).toBeLessThanOrEqual(30 * 86_400_000)
      expect(out.expires_at).toBe('2026-10-28T00:00:00.000Z')
      expect(mockState.changed).toHaveBeenCalledWith('api_key.created')
    })

    it('passes organizationId + createdBy + deduped scopes to Hydra and returns the secret once', async () => {
      mockState.hydra.createClient.mockResolvedValue(
        client({ client_secret: 'super-secret-once' })
      )

      const result = await svc.create({
        organizationId: ORG,
        body: { label: 'svc', scopes: ['payroll:write', 'payroll:write'] },
        createdBy: 'kratos-id-1',
        callerEmail: 'a@x.io',
      })

      expect(mockState.hydra.createClient).toHaveBeenCalledWith(
        expect.objectContaining({ organizationId: ORG, createdBy: 'kratos-id-1', scopes: ['payroll:write'] })
      )
      expect(result.client_secret).toBe('super-secret-once')
      expect(result.organization_id).toBe(ORG)
      // The creator is the caller: their address is theirs to see; a new key was never used.
      expect(result).toMatchObject({ created_by_email: 'a@x.io', last_used_at: null })
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
      expect(out[0].expires_at).toBeNull()
      expect(mockState.hydra.listClientsByOwner).toHaveBeenCalledWith(ORG)
    })
  })

  describe('personal keys are never org keys', () => {
    it('are left out of the org list and 404 on get/revoke through the org', async () => {
      const personal = client({ client_id: 'mine', metadata: { organization_id: ORG, kind: 'personal', subject: 'u1' } })
      mockState.hydra.listClientsByOwner.mockResolvedValue([personal])
      expect(await svc.list(ORG)).toEqual([])
      mockState.hydra.getClient.mockResolvedValue(personal)
      await expect(svc.revoke(ORG, 'mine')).rejects.toMatchObject({ statusCode: 404 })
      expect(mockState.hydra.deleteClient).not.toHaveBeenCalled()
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
      expect(mockState.forget).toHaveBeenCalledWith('client-abc')
    })
  })
})
