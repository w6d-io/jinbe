/**
 * Kratos API response fixtures for auth tests
 */

import type { KratosIdentity } from '../../../schemas/admin.schema.js'

/**
 * Create a Kratos identity fixture
 */
export function createKratosIdentity(
  overrides: Partial<KratosIdentity> & { id: string; traits: { email: string } }
): KratosIdentity {
  const { id, traits, schema_id, state, created_at, updated_at, ...rest } = overrides
  return {
    id,
    schema_id: schema_id || 'default',
    state: state || 'active',
    traits: {
      email: traits.email,
      name: traits?.name,
    },
    created_at: created_at || new Date().toISOString(),
    updated_at: updated_at || new Date().toISOString(),
    ...rest,
  }
}

/**
 * Default test identities
 */
export const testIdentities: KratosIdentity[] = [
  createKratosIdentity({
    id: '550e8400-e29b-41d4-a716-446655440001',
    traits: {
      email: 'admin@example.com',
      name: 'Admin User',
    },
    state: 'active',
  }),
  createKratosIdentity({
    id: '550e8400-e29b-41d4-a716-446655440002',
    traits: {
      email: 'developer@example.com',
      name: 'Developer User',
    },
    state: 'active',
  }),
  createKratosIdentity({
    id: '550e8400-e29b-41d4-a716-446655440003',
    traits: {
      email: 'inactive@example.com',
    },
    state: 'inactive',
  }),
]

/**
 * Create a Kratos session response fixture
 */
export function createKratosSession(email: string, options: {
  sessionId?: string
  identityId?: string
  name?: string
  picture?: string
  active?: boolean
  expiresAt?: Date
} = {}) {
  const expiresAt = options.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000) // 24h from now
  return {
    id: options.sessionId || 'session-123',
    active: options.active ?? true,
    expires_at: expiresAt.toISOString(),
    authenticated_at: new Date().toISOString(),
    authenticator_assurance_level: 'aal1',
    identity: {
      id: options.identityId || '550e8400-e29b-41d4-a716-446655440001',
      schema_id: 'default',
      traits: {
        email,
        name: options.name,
        picture: options.picture,
      },
      state: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  }
}

/**
 * Create identity create request fixture
 */
export function createIdentityRequest(email: string, options: {
  firstName?: string
  lastName?: string
  password?: string
  state?: 'active' | 'inactive'
} = {}) {
  const request: {
    schema_id: string
    traits: { email: string; name?: string }
    state: 'active' | 'inactive'
    credentials?: { password: { config: { password: string } } }
  } = {
    schema_id: 'default',
    traits: {
      email,
    },
    state: options.state || 'active',
  }

  if (options.firstName || options.lastName) {
    request.traits.name = `${options.firstName || ''} ${options.lastName || ''}`.trim()
  }

  if (options.password) {
    request.credentials = {
      password: {
        config: {
          password: options.password,
        },
      },
    }
  }

  return request
}
