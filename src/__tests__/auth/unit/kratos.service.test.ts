import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createKratosIdentity, testIdentities, createIdentityRequest } from '../fixtures/kratos.fixture.js'

// Mock state using vi.hoisted
const mockState = vi.hoisted(() => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
  },
}))

// Mock env configuration
vi.mock('../../../config/index.js', () => ({
  env: mockState.env,
}))

// Helper to create mock fetch response
function createMockResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : status === 404 ? 'Not Found' : 'Error',
    json: async () => body,
    text: async () => JSON.stringify(body),
  }
}

// Import after mocking
import { KratosService, KratosApiError } from '../../../services/kratos.service.js'

describe('KratosService', () => {
  let service: KratosService
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()

    // Reset mock state
    mockState.env.KRATOS_ADMIN_URL = 'http://kratos-admin:4434'

    // Create mock fetch
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)

    // Create fresh service instance
    service = new KratosService()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('listIdentities', () => {
    it('should return list of identities', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200, testIdentities))

      const result = await service.listIdentities()

      expect(result.identities).toHaveLength(3)
      expect(result.identities[0].traits.email).toBe('admin@example.com')
    })

    it('should pass pagination parameters', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200, []))

      await service.listIdentities(10, 'token123')

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('page_size=10'),
        expect.any(Object)
      )
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('page_token=token123'),
        expect.any(Object)
      )
    })

    it('should pass credentials_identifier filter', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200, []))

      await service.listIdentities(undefined, undefined, 'admin@example.com')

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('credentials_identifier=admin%40example.com'),
        expect.any(Object)
      )
    })

    it('should throw KratosApiError on failure', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(500, { error: 'Internal error' }))

      await expect(service.listIdentities()).rejects.toThrow(KratosApiError)
    })
  })

  describe('getIdentity', () => {
    it('should return identity by ID', async () => {
      const identity = testIdentities[0]
      mockFetch.mockResolvedValueOnce(createMockResponse(200, identity))

      const result = await service.getIdentity(identity.id)

      expect(result.id).toBe(identity.id)
      expect(result.traits.email).toBe('admin@example.com')
    })

    it('should throw KratosApiError when identity not found', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(404, { error: 'Identity not found' }))

      await expect(service.getIdentity('non-existent-id')).rejects.toThrow(KratosApiError)
    })

    it('should call correct endpoint', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(200, testIdentities[0]))

      await service.getIdentity('550e8400-e29b-41d4-a716-446655440001')

      expect(mockFetch).toHaveBeenCalledWith(
        'http://kratos-admin:4434/admin/identities/550e8400-e29b-41d4-a716-446655440001',
        expect.any(Object)
      )
    })
  })

  describe('createIdentity', () => {
    it('should create new identity', async () => {
      const createRequest = createIdentityRequest('newuser@example.com', {
        firstName: 'New',
        lastName: 'User',
        password: 'securepassword123',
      })

      const createdIdentity = createKratosIdentity({
        id: '550e8400-e29b-41d4-a716-446655440004',
        traits: { email: 'newuser@example.com', name: 'New User' },
      })

      mockFetch.mockResolvedValueOnce(createMockResponse(200, createdIdentity))

      const result = await service.createIdentity(createRequest)

      expect(result.id).toBe('550e8400-e29b-41d4-a716-446655440004')
      expect(result.traits.email).toBe('newuser@example.com')
    })

    it('should send POST request with correct body', async () => {
      const createRequest = createIdentityRequest('test@example.com')
      mockFetch.mockResolvedValueOnce(createMockResponse(200, testIdentities[0]))

      await service.createIdentity(createRequest)

      expect(mockFetch).toHaveBeenCalledWith(
        'http://kratos-admin:4434/admin/identities',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(createRequest),
        })
      )
    })

    it('should throw KratosApiError on validation failure', async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(400, { error: { message: 'Invalid email format' } })
      )

      await expect(
        service.createIdentity(createIdentityRequest('invalid-email'))
      ).rejects.toThrow(KratosApiError)
    })
  })

  describe('updateIdentity', () => {
    it('should update existing identity', async () => {
      const existingIdentity = testIdentities[0]
      mockFetch.mockResolvedValueOnce(createMockResponse(200, existingIdentity))

      const updatedIdentity = {
        ...existingIdentity,
        traits: { ...existingIdentity.traits, name: 'Updated Name' },
      }
      mockFetch.mockResolvedValueOnce(createMockResponse(200, updatedIdentity))

      const result = await service.updateIdentity(existingIdentity.id, {
        traits: { name: 'Updated Name' },
      })

      expect(result.traits.name).toBe('Updated Name')
    })

    it('should merge traits with existing identity', async () => {
      const existingIdentity = testIdentities[0]
      mockFetch.mockResolvedValueOnce(createMockResponse(200, existingIdentity))
      mockFetch.mockResolvedValueOnce(createMockResponse(200, existingIdentity))

      await service.updateIdentity(existingIdentity.id, {
        traits: { name: { first: 'NewFirst' } },
      })

      // Verify the PUT request body contains merged data
      const putCall = mockFetch.mock.calls[1]
      const putBody = JSON.parse(putCall[1].body)
      expect(putBody.traits.email).toBe('admin@example.com') // Original email preserved
      expect(putBody.traits.name.first).toBe('NewFirst') // New first name
    })

    it('should update state', async () => {
      const existingIdentity = testIdentities[0]
      mockFetch.mockResolvedValueOnce(createMockResponse(200, existingIdentity))
      mockFetch.mockResolvedValueOnce(createMockResponse(200, { ...existingIdentity, state: 'inactive' }))

      const result = await service.updateIdentity(existingIdentity.id, {
        state: 'inactive',
      })

      expect(result.state).toBe('inactive')
    })

    it('should throw KratosApiError when identity not found', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(404, { error: 'Not found' }))

      await expect(
        service.updateIdentity('non-existent', { traits: {} })
      ).rejects.toThrow(KratosApiError)
    })
  })

  describe('deleteIdentity', () => {
    it('should delete identity', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(204, undefined))

      await expect(service.deleteIdentity('550e8400-e29b-41d4-a716-446655440001')).resolves.not.toThrow()
    })

    it('should send DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(204, undefined))

      await service.deleteIdentity('550e8400-e29b-41d4-a716-446655440001')

      expect(mockFetch).toHaveBeenCalledWith(
        'http://kratos-admin:4434/admin/identities/550e8400-e29b-41d4-a716-446655440001',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
    })

    it('should throw KratosApiError when identity not found', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(404, { error: 'Not found' }))

      await expect(service.deleteIdentity('non-existent')).rejects.toThrow(KratosApiError)
    })
  })

  describe('error handling', () => {
    it('should include error details from Kratos response', async () => {
      const errorDetails = { error: { message: 'Detailed error', code: 'ERR001' } }
      mockFetch.mockResolvedValueOnce(createMockResponse(400, errorDetails))

      try {
        await service.listIdentities()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(KratosApiError)
        expect((e as KratosApiError).statusCode).toBe(400)
        expect((e as KratosApiError).details).toEqual(errorDetails)
      }
    })

    it('should handle text error response when JSON parsing fails', async () => {
      const failingJsonResponse = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => {
          throw new Error('JSON parse error')
        },
        text: async () => 'Plain text error message',
      }
      mockFetch.mockResolvedValueOnce(failingJsonResponse)

      try {
        await service.listIdentities()
        expect.fail('Should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(KratosApiError)
        expect((e as KratosApiError).details).toBe('Plain text error message')
      }
    })
  })
})
