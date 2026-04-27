import type supertest from 'supertest'

/**
 * Add admin authentication headers to a supertest request
 */
export function withAdminAuth(request: supertest.Test): supertest.Test {
  return request
    .set('Cookie', 'ory_kratos_session=test-admin-session')
    .set('X-User-Email', 'admin@example.com')
    .set('X-User-ID', 'admin-user-id')
}

/**
 * Add superadmin authentication headers to a supertest request
 */
export function withSuperadminAuth(request: supertest.Test): supertest.Test {
  return request
    .set('Cookie', 'ory_kratos_session=test-superadmin-session')
    .set('X-User-Email', 'superadmin@example.com')
    .set('X-User-ID', 'superadmin-user-id')
}

/**
 * Add non-admin (developer) authentication headers to a supertest request
 */
export function withNonAdminAuth(request: supertest.Test): supertest.Test {
  return request
    .set('Cookie', 'ory_kratos_session=test-user-session')
    .set('X-User-Email', 'dev@example.com')
    .set('X-User-ID', 'dev-user-id')
}

/**
 * Add viewer authentication headers to a supertest request
 */
export function withViewerAuth(request: supertest.Test): supertest.Test {
  return request
    .set('Cookie', 'ory_kratos_session=test-viewer-session')
    .set('X-User-Email', 'viewer@example.com')
    .set('X-User-ID', 'viewer-user-id')
}

/**
 * Returns a request with no authentication (anonymous)
 */
export function withNoAuth(request: supertest.Test): supertest.Test {
  return request // No auth headers
}

/**
 * Add custom user authentication headers
 */
export function withUserAuth(
  request: supertest.Test,
  email: string,
  userId?: string
): supertest.Test {
  return request
    .set('Cookie', `ory_kratos_session=test-session-${email}`)
    .set('X-User-Email', email)
    .set('X-User-ID', userId || `user-${email.split('@')[0]}`)
}

/**
 * Mock user context type
 */
export interface MockUserContext {
  email: string
  userId: string
  sessionId: string
}

/**
 * Create a mock user context object
 */
export function createMockUserContext(email: string, userId?: string): MockUserContext {
  return {
    email,
    userId: userId || `user-${email.split('@')[0]}`,
    sessionId: `test-session-${email}`,
  }
}

/**
 * Admin user context
 */
export const adminContext = createMockUserContext('admin@example.com', 'admin-user-id')

/**
 * Non-admin user context
 */
export const devContext = createMockUserContext('dev@example.com', 'dev-user-id')

/**
 * Viewer user context
 */
export const viewerContext = createMockUserContext('viewer@example.com', 'viewer-user-id')
