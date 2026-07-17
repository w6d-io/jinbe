import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// Mock fetch + env before importing the service (mirrors kratos.service.cache.test.ts)
const mockFetch = vi.fn()
global.fetch = mockFetch

vi.mock('../../../config/index.js', () => ({
  env: {
    KRATOS_ADMIN_URL: 'http://kratos-admin:4434',
    KRATOS_REQUEST_TIMEOUT_MS: 10000,
  },
}))

import { KratosService } from '../../../services/kratos.service.js'

describe('KratosService - getAllIdentitiesWithBindings', () => {
  let service: KratosService

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    service = new KratosService()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const identities = [
    {
      id: 'user-1',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'multi@example.com' },
      metadata_admin: { groups: ['admins', 'users'], organizations: ['org-a', 'org-b'] },
      organization_id: 'org-a',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    {
      id: 'user-2',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'legacy@example.com' },
      // No metadata_admin.organizations — only the native Kratos organization_id
      metadata_admin: { groups: ['devs'] },
      organization_id: 'org-c',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    {
      id: 'user-3',
      schema_id: 'default',
      state: 'active',
      traits: { email: 'orgless@example.com' },
      metadata_admin: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  ]

  it('extracts groups, organizations, and the primary organization per identity', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve(identities),
    })

    const result = await service.getAllIdentitiesWithBindings()

    expect(result.get('multi@example.com')).toMatchObject({
      groups: ['admins', 'users'],
      organizations: ['org-a', 'org-b'],
      primaryOrganization: 'org-a',
    })
  })

  it('defaults groups to ["users"] and organizations to [] when metadata_admin is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve(identities),
    })

    const result = await service.getAllIdentitiesWithBindings()

    expect(result.get('orgless@example.com')).toMatchObject({
      groups: ['users'],
      organizations: [],
      primaryOrganization: null,
    })
  })

  it('reads the primary organization from the native Kratos organization_id field', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve(identities),
    })

    const result = await service.getAllIdentitiesWithBindings()

    const legacy = result.get('legacy@example.com')
    expect(legacy?.organizations).toEqual([])
    expect(legacy?.primaryOrganization).toBe('org-c')
  })

  it('falls back to traits.organization_id when the root field is absent', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve([
          {
            id: 'user-x',
            schema_id: 'default',
            state: 'active',
            traits: { email: 'trait@example.com', organization_id: 'org-trait' },
            metadata_admin: { groups: ['users'] },
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        ]),
    })

    const result = await service.getAllIdentitiesWithBindings()
    expect(result.get('trait@example.com')?.primaryOrganization).toBe('org-trait')
  })

  it('caches the scan (single fetch within TTL) and is cleared by invalidateGroupsCache', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(identities),
    })

    await service.getAllIdentitiesWithBindings()
    await service.getAllIdentitiesWithBindings()
    expect(mockFetch).toHaveBeenCalledTimes(1)

    service.invalidateGroupsCache()
    await service.getAllIdentitiesWithBindings()
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('skips identities without an email', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve([
          {
            id: 'no-email',
            schema_id: 'default',
            state: 'active',
            traits: {},
            metadata_admin: { groups: ['orphans'], organizations: ['org-z'] },
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        ]),
    })

    const result = await service.getAllIdentitiesWithBindings()
    expect(result.size).toBe(0)
  })

  it('propagates Kratos fetch errors (fail closed)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: () => Promise.resolve({ error: 'boom' }),
    })

    await expect(service.getAllIdentitiesWithBindings()).rejects.toThrow('Kratos API error')
  })

  it('aborts and rejects when Kratos hangs past the request timeout', async () => {
    // Simulate a hung upstream: the promise only settles if its abort signal
    // fires. The bounded timeout must abort it so the scan rejects (fail closed)
    // instead of hanging forever.
    mockFetch.mockImplementation(
      (_url: string, opts: RequestInit) =>
        new Promise((_resolve, reject) => {
          opts.signal?.addEventListener('abort', () =>
            reject(new Error('The operation was aborted'))
          )
        })
    )

    const pending = service.getAllIdentitiesWithBindings()
    const assertion = expect(pending).rejects.toThrow(/aborted/i)
    // Advance past the 10s timeout so the AbortController fires.
    await vi.advanceTimersByTimeAsync(10_001)
    await assertion
  })
})
