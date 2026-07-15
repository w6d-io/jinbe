import { vi } from 'vitest'

export interface MockKratosIdentity {
  id: string
  traits: {
    email: string
    name?: string
    organization_id?: string
  }
  state: string
  organization_id?: string
  metadata_admin?: {
    groups?: string[]
    organizations?: string[]
  }
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

    getAllIdentitiesWithBindings: vi.fn().mockImplementation(async () => {
      const result = new Map<
        string,
        { groups: string[]; organizations: string[]; primaryOrganization: string | null }
      >()
      for (const user of users) {
        result.set(user.traits.email, {
          groups: user.metadata_admin?.groups || ['users'],
          organizations: user.metadata_admin?.organizations || [],
          primaryOrganization: user.organization_id || user.traits.organization_id || null,
        })
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
