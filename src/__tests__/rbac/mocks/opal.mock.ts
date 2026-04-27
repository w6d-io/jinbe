import { vi } from 'vitest'

export interface UserRbacInfo {
  email: string
  groups: string[]
  roles: string[]
  permissions: string[]
}

export interface MockOpalUser {
  email: string
  groups: string[]
  roles: string[]
  permissions: string[]
}

/**
 * Creates a mock opalService for admin middleware testing
 */
export function createOpalMock(users: Map<string, MockOpalUser> = new Map()) {
  return {
    getUserInfo: vi.fn().mockImplementation(async (email: string, _app: string): Promise<UserRbacInfo | null> => {
      const user = users.get(email)
      if (!user) return null
      return {
        email: user.email,
        groups: user.groups,
        roles: user.roles,
        permissions: user.permissions,
      }
    }),
  }
}

/**
 * Default admin user for testing
 */
export const adminOpalUser: MockOpalUser = {
  email: 'admin@example.com',
  groups: ['admin', 'devs'],
  roles: ['admin'],
  permissions: ['*'],
}

/**
 * Superadmin user for testing
 */
export const superadminOpalUser: MockOpalUser = {
  email: 'superadmin@example.com',
  groups: ['superadmin', 'admin', 'devs'],
  roles: ['superadmin'],
  permissions: ['*'],
}

/**
 * Non-admin user for testing forbidden scenarios
 */
export const nonAdminOpalUser: MockOpalUser = {
  email: 'dev@example.com',
  groups: ['devs'],
  roles: ['developer'],
  permissions: ['read', 'write'],
}

/**
 * Viewer user (read-only)
 */
export const viewerOpalUser: MockOpalUser = {
  email: 'viewer@example.com',
  groups: ['viewers'],
  roles: ['viewer'],
  permissions: ['read'],
}

/**
 * Creates a default user map with common test users
 */
export function createDefaultOpalUserMap(): Map<string, MockOpalUser> {
  const users = new Map<string, MockOpalUser>()
  users.set(adminOpalUser.email, adminOpalUser)
  users.set(superadminOpalUser.email, superadminOpalUser)
  users.set(nonAdminOpalUser.email, nonAdminOpalUser)
  users.set(viewerOpalUser.email, viewerOpalUser)
  return users
}
