import type { RolesFile } from '../../../schemas/rbac/roles.schema.js'

/**
 * Creates a standard roles file for a service
 */
export function createRolesFixture(
  serviceName: string,
  overrides: Partial<RolesFile> = {}
): RolesFile {
  return {
    version: '1.0',
    service: serviceName,
    roles: [
      {
        name: 'admin',
        description: 'Full access',
        permissions: ['*'],
      },
      {
        name: 'operator',
        description: 'Operations access (read, write, execute)',
        permissions: ['read', 'write', 'execute'],
      },
      {
        name: 'editor',
        description: 'Read and write access',
        permissions: ['read', 'write'],
      },
      {
        name: 'viewer',
        description: 'Read-only access',
        permissions: ['read'],
      },
    ],
    ...overrides,
  }
}

/**
 * Creates a minimal roles file
 */
export function createMinimalRolesFixture(serviceName: string): RolesFile {
  return {
    version: '1.0',
    service: serviceName,
    roles: [
      {
        name: 'admin',
        permissions: ['*'],
      },
    ],
  }
}

/**
 * Creates a roles file with role inheritance
 */
export function createRolesWithInheritanceFixture(serviceName: string): RolesFile {
  return {
    version: '1.0',
    service: serviceName,
    roles: [
      {
        name: 'admin',
        description: 'Full access',
        permissions: ['*'],
      },
      {
        name: 'manager',
        description: 'Manager role',
        permissions: ['manage'],
        inherits: ['editor'],
      },
      {
        name: 'editor',
        description: 'Editor role',
        permissions: ['read', 'write'],
        inherits: ['viewer'],
      },
      {
        name: 'viewer',
        description: 'Viewer role',
        permissions: ['read'],
      },
    ],
  }
}
