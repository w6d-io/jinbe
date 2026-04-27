import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'

// Must mock fetch and env before importing service
const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
  },
}))

import { KratosService } from '../../../services/kratos.service.js'

describe('KratosService - getAllIdentitiesWithGroups', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    // Create new instance to reset cache
    service = new KratosService()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const mockIdentities = [
    {
      id: 'user-1',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'admin@example.com' },
      metadata_admin: { groups: ['admins', 'users'] },
      metadata_public: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    {
      id: 'user-2',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'dev@example.com' },
      metadata_admin: { groups: ['devs'] },
      metadata_public: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    {
      id: 'user-3',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'newuser@example.com' },
      metadata_admin: null, // No groups set
      metadata_public: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  ]

  it('should fetch all identities and extract groups', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockIdentities),
    })

    const result = await service.getAllIdentitiesWithGroups()

    expect(result.get('admin@example.com')).toEqual(['admins', 'users'])
    expect(result.get('dev@example.com')).toEqual(['devs'])
    expect(result.get('newuser@example.com')).toEqual(['users']) // Default
  })

  it('should cache results for 30 seconds', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockIdentities),
    })

    // First call
    await service.getAllIdentitiesWithGroups()
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Second call (within TTL) - should use cache
    await service.getAllIdentitiesWithGroups()
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Third call still within TTL
    vi.advanceTimersByTime(15_000) // 15 seconds
    await service.getAllIdentitiesWithGroups()
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('should refresh cache after TTL expires', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockIdentities),
    })

    // First call
    await service.getAllIdentitiesWithGroups()
    expect(mockFetch).toHaveBeenCalledTimes(1)

    // Advance time past TTL (30 seconds)
    vi.advanceTimersByTime(31_000)

    // Fourth call (after TTL) - should fetch again
    await service.getAllIdentitiesWithGroups()
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('should default to ["users"] when metadata_admin.groups is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve([
          {
            id: 'user-1',
            schema_id: 'default',
            state: 'active',
            traits: { email: 'nogroups@example.com' },
            metadata_admin: {}, // Empty object
            metadata_public: {},
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
          {
            id: 'user-2',
            schema_id: 'default',
            state: 'active',
            traits: { email: 'nulladmin@example.com' },
            metadata_admin: null, // Null
            metadata_public: {},
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        ]),
    })

    const result = await service.getAllIdentitiesWithGroups()

    expect(result.get('nogroups@example.com')).toEqual(['users'])
    expect(result.get('nulladmin@example.com')).toEqual(['users'])
  })

  it('should skip identities without email', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve([
          {
            id: 'user-1',
            schema_id: 'default',
            state: 'active',
            traits: {}, // No email
            metadata_admin: { groups: ['orphans'] },
            metadata_public: {},
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
          {
            id: 'user-2',
            schema_id: 'default',
            state: 'active',
            traits: { email: 'valid@example.com' },
            metadata_admin: { groups: ['users'] },
            metadata_public: {},
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        ]),
    })

    const result = await service.getAllIdentitiesWithGroups()

    expect(result.size).toBe(1)
    expect(result.has('valid@example.com')).toBe(true)
  })

  it('should return empty map when no identities', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve([]),
    })

    const result = await service.getAllIdentitiesWithGroups()

    expect(result.size).toBe(0)
  })

  it('should propagate fetch errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: () => Promise.resolve({ error: 'Database error' }),
    })

    await expect(service.getAllIdentitiesWithGroups()).rejects.toThrow('Kratos API error')
  })

  it('should use page_size of 250 for efficiency', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve([]),
    })

    await service.getAllIdentitiesWithGroups()

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('page_size=250'),
      expect.any(Object)
    )
  })

  it('should call correct Kratos Admin API endpoint', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve([]),
    })

    await service.getAllIdentitiesWithGroups()

    expect(mockFetch).toHaveBeenCalledWith(
      'http://kratos-admin:4434/admin/identities?page_size=250',
      expect.any(Object)
    )
  })
})
