import { describe, it, expect, beforeEach, vi } from 'vitest'

// Must mock fetch and env before importing service
const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
  },
}))

import { KratosService, KratosApiError } from '../../../services/kratos.service.js'

describe('KratosService - User Groups Management', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    service = new KratosService()
  })

  const mockIdentity = {
    id: 'user-123',
    schema_id: 'default',
    state: 'active',
    traits: { email: 'user@example.com' },
    metadata_admin: { groups: ['devs', 'users'] },
    metadata_public: {},
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  }

  // ===========================================================================
  // getUserGroups
  // ===========================================================================
  describe('getUserGroups', () => {
    it('should return user groups by email', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([mockIdentity]),
      })

      const result = await service.getUserGroups('user@example.com')

      expect(result).toEqual(['devs', 'users'])
      expect(mockFetch).toHaveBeenCalledWith(
        'http://kratos-admin:4434/admin/identities?page_size=1&credentials_identifier=user%40example.com',
        expect.any(Object)
      )
    })

    it('should return ["users"] when metadata_admin is null', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            { ...mockIdentity, metadata_admin: null },
          ]),
      })

      const result = await service.getUserGroups('user@example.com')

      expect(result).toEqual(['users'])
    })

    it('should return ["users"] when groups is missing', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            { ...mockIdentity, metadata_admin: {} },
          ]),
      })

      const result = await service.getUserGroups('user@example.com')

      expect(result).toEqual(['users'])
    })

    it('should throw 404 when user not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      })

      try {
        await service.getUserGroups('nonexistent@example.com')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(KratosApiError)
        expect((error as KratosApiError).statusCode).toBe(404)
        expect((error as Error).message).toContain('User not found')
      }
    })
  })

  // ===========================================================================
  // updateUserGroups
  // ===========================================================================
  describe('updateUserGroups', () => {
    it('should update user groups in metadata_admin', async () => {
      // First call: find user by email
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([mockIdentity]),
      })

      // Second call: get full identity for update
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockIdentity),
      })

      // Third call: PUT update
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            ...mockIdentity,
            metadata_admin: { groups: ['admins'] },
          }),
      })

      const result = await service.updateUserGroups('user@example.com', ['admins'])

      expect(result.metadata_admin).toEqual({ groups: ['admins'] })
      expect(mockFetch).toHaveBeenCalledTimes(3)

      // Verify PUT was called with correct body
      const putCall = mockFetch.mock.calls[2]
      expect(putCall[0]).toBe('http://kratos-admin:4434/admin/identities/user-123')
      expect(putCall[1].method).toBe('PUT')

      const body = JSON.parse(putCall[1].body)
      expect(body.metadata_admin.groups).toEqual(['admins'])
    })

    it('should preserve other metadata_admin fields', async () => {
      const identityWithOtherMetadata = {
        ...mockIdentity,
        metadata_admin: { groups: ['users'], custom_field: 'value' },
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([identityWithOtherMetadata]),
      })

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identityWithOtherMetadata),
      })

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            ...identityWithOtherMetadata,
            metadata_admin: { groups: ['admins'], custom_field: 'value' },
          }),
      })

      await service.updateUserGroups('user@example.com', ['admins'])

      const putCall = mockFetch.mock.calls[2]
      const body = JSON.parse(putCall[1].body)
      expect(body.metadata_admin.custom_field).toBe('value')
      expect(body.metadata_admin.groups).toEqual(['admins'])
    })

    it('should throw 404 when user not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      })

      await expect(
        service.updateUserGroups('nonexistent@example.com', ['admins'])
      ).rejects.toThrow(KratosApiError)
    })
  })

  // ===========================================================================
  // removeGroupFromAllUsers
  // ===========================================================================
  describe('removeGroupFromAllUsers', () => {
    it('should remove group from all users who have it', async () => {
      const identities = [
        {
          id: 'user-1',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user1@example.com' },
          metadata_admin: { groups: ['devs', 'users'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        {
          id: 'user-2',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user2@example.com' },
          metadata_admin: { groups: ['devs'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        {
          id: 'user-3',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user3@example.com' },
          metadata_admin: { groups: ['admins'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ]

      // getAllIdentitiesWithGroups call
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities),
      })

      // updateUserGroups for user1 (find + get + update)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([identities[0]]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities[0]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ ...identities[0], metadata_admin: { groups: ['users'] } }),
      })

      // updateUserGroups for user2 (find + get + update)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([identities[1]]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities[1]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ ...identities[1], metadata_admin: { groups: ['users'] } }),
      })

      const result = await service.removeGroupFromAllUsers('devs')

      expect(result).toBe(2) // Two users had 'devs' group
    })

    it('should default to ["users"] when removing last group', async () => {
      const identities = [
        {
          id: 'user-1',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user1@example.com' },
          metadata_admin: { groups: ['devs'] }, // Only has devs
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities),
      })

      // updateUserGroups calls
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([identities[0]]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities[0]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ ...identities[0], metadata_admin: { groups: ['users'] } }),
      })

      await service.removeGroupFromAllUsers('devs')

      // Verify update was called with ['users'] as default
      const putCall = mockFetch.mock.calls[3]
      const body = JSON.parse(putCall[1].body)
      expect(body.metadata_admin.groups).toEqual(['users'])
    })

    it('should return 0 when no users have the group', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve([
            {
              id: 'user-1',
              schema_id: 'default',
              state: 'active',
              traits: { email: 'user1@example.com' },
              metadata_admin: { groups: ['admins'] },
              metadata_public: {},
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ]),
      })

      const result = await service.removeGroupFromAllUsers('nonexistent-group')

      expect(result).toBe(0)
      expect(mockFetch).toHaveBeenCalledTimes(1) // Only getAllIdentitiesWithGroups
    })
  })

  // ===========================================================================
  // invalidateGroupsCache
  // ===========================================================================
  describe('invalidateGroupsCache', () => {
    it('should force refresh on next getAllIdentitiesWithGroups call', async () => {
      const identities = [
        {
          id: 'user-1',
          schema_id: 'default',
          state: 'active',
          traits: { email: 'user@example.com' },
          metadata_admin: { groups: ['users'] },
          metadata_public: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ]

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve(identities),
      })

      // First call populates cache
      await service.getAllIdentitiesWithGroups()
      expect(mockFetch).toHaveBeenCalledTimes(1)

      // Second call uses cache
      await service.getAllIdentitiesWithGroups()
      expect(mockFetch).toHaveBeenCalledTimes(1)

      // Invalidate cache
      service.invalidateGroupsCache()

      // Third call should fetch again
      await service.getAllIdentitiesWithGroups()
      expect(mockFetch).toHaveBeenCalledTimes(2)
    })
  })
})
