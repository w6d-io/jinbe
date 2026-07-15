import { vi } from 'vitest'

export interface MockKratosIdentity {
  id: string
  traits: {
    email: string
    name?: string
  }
  state: string
  metadata_admin?: {
    groups?: string[]
    // Path 3 hybrid: multi-org array sourced from
    // metadata_admin.organizations. Mirrors the live schema.
    organizations?: string[]
  }
  // Legacy single-org pointer at the identity root.
  organization_id?: string | null
}

/**
 * Creates a mock kratosService for user name enrichment
 */
export function createKratosMock(users: MockKratosIdentity[] = []) {
  return {
    listIdentities: vi.fn().mockResolvedValue({
      identities: users,
      nextPageToken: undefined,
    }),

    getIdentity: vi.fn().mockImplementation(async (id: string) => {
      const user = users.find(u => u.id === id)
      if (!user) {
        const error = new Error('Identity not found') as Error & { statusCode: number }
        error.statusCode = 404
        throw error
      }
      return user
    }),

    getAllIdentitiesWithGroups: vi.fn().mockImplementation(async () => {
      const result = new Map<string, string[]>()
      for (const user of users) {
        const groups = user.metadata_admin?.groups || ['users']
        result.set(user.traits.email, groups)
      }
      return result
    }),

    // Path 3 hybrid: identical source data, richer return shape.
    getAllIdentitiesMetadata: vi.fn().mockImplementation(async () => {
      const result = new Map<
        string,
        { groups: string[]; organizations: string[]; organizationPrimary: string | null }
      >()
      for (const user of users) {
        const groups = user.metadata_admin?.groups || ['users']
        const organizations = user.metadata_admin?.organizations ?? []
        const organizationPrimary = user.organization_id ?? null
        result.set(user.traits.email, { groups, organizations, organizationPrimary })
      }
      return result
    }),
  }
}

/**
 * Default mock users for testing
 */
export const defaultMockUsers: MockKratosIdentity[] = [
  {
    id: 'user-1',
    traits: {
      email: 'admin@example.com',
      name: 'Admin User',
    },
    state: 'active',
    metadata_admin: { groups: ['admins', 'users'] },
  },
  {
    id: 'user-2',
    traits: {
      email: 'dev@example.com',
      name: 'Developer User',
    },
    state: 'active',
    metadata_admin: { groups: ['devs', 'users'] },
  },
  {
    id: 'user-3',
    traits: {
      email: 'viewer@example.com',
    },
    state: 'active',
    metadata_admin: { groups: ['viewers'] },
  },
  {
    id: 'user-4',
    traits: {
      email: 'test@example.com',
      name: 'Test User',
    },
    state: 'active',
    // No metadata_admin - should default to ['users']
  },
]
