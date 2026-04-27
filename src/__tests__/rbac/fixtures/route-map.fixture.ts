import type { RouteMapFile } from '../../../schemas/rbac/route-map.schema.js'

/**
 * Creates a standard route map file for a service
 */
export function createRouteMapFixture(
  serviceName: string,
  overrides: Partial<RouteMapFile> = {}
): RouteMapFile {
  return {
    version: '1.0',
    service: serviceName,
    routes: [
      {
        method: 'GET',
        path: '/api/health',
        requiredPermissions: [],
        public: true,
        description: 'Health check endpoint',
      },
      {
        method: 'GET',
        path: '/api/v1/resources',
        requiredPermissions: ['read'],
        public: false,
        description: 'List resources',
      },
      {
        method: 'POST',
        path: '/api/v1/resources',
        requiredPermissions: ['write'],
        public: false,
        description: 'Create resource',
      },
      {
        method: 'PUT',
        path: '/api/v1/resources/:id',
        requiredPermissions: ['write'],
        public: false,
        description: 'Update resource',
      },
      {
        method: 'DELETE',
        path: '/api/v1/resources/:id',
        requiredPermissions: ['write'],
        public: false,
        description: 'Delete resource',
      },
    ],
    ...overrides,
  }
}

/**
 * Creates a minimal route map with only health endpoint
 */
export function createMinimalRouteMapFixture(serviceName: string): RouteMapFile {
  return {
    version: '1.0',
    service: serviceName,
    routes: [
      {
        method: 'GET',
        path: '/api/health',
        requiredPermissions: [],
        public: true,
      },
    ],
  }
}

/**
 * Creates an empty route map
 */
export function createEmptyRouteMapFixture(serviceName: string): RouteMapFile {
  return {
    version: '1.0',
    service: serviceName,
    routes: [],
  }
}
