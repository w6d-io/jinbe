import type { BindingsFile } from '../../../schemas/rbac/bindings.schema.js'

/**
 * Creates a sample bindings file fixture
 */
export function createBindingsFixture(overrides: Partial<BindingsFile> = {}): BindingsFile {
  return {
    emails: {},
    group_membership: {
      'admin@example.com': {
        groups: ['admins', 'devs'],
        addedAt: '2024-01-01T00:00:00.000Z',
        addedBy: 'system@example.com',
      },
      'dev@example.com': {
        groups: ['devs'],
        addedAt: '2024-01-02T00:00:00.000Z',
        addedBy: 'admin@example.com',
      },
      'viewer@example.com': ['viewers'], // Simple format
    },
    ...overrides,
  }
}

/**
 * Creates an empty bindings file
 */
export function createEmptyBindingsFixture(): BindingsFile {
  return {
    emails: {},
    group_membership: {},
  }
}

/**
 * Creates a bindings file with multiple users in various groups
 */
export function createMultiUserBindingsFixture(): BindingsFile {
  return {
    emails: {},
    group_membership: {
      'superadmin@example.com': {
        groups: ['super_admins', 'admins'],
        addedAt: '2024-01-01T00:00:00.000Z',
        addedBy: 'system@example.com',
      },
      'admin@example.com': {
        groups: ['admins', 'devs'],
        addedAt: '2024-01-01T00:00:00.000Z',
        addedBy: 'system@example.com',
      },
      'infra@example.com': {
        groups: ['infra'],
        addedAt: '2024-01-02T00:00:00.000Z',
        addedBy: 'admin@example.com',
      },
      'dev1@example.com': {
        groups: ['devs'],
        addedAt: '2024-01-03T00:00:00.000Z',
        addedBy: 'admin@example.com',
      },
      'dev2@example.com': ['devs'], // Simple format
      'viewer@example.com': ['viewers'],
    },
  }
}
