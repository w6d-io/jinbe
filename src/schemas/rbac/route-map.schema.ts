import { z } from 'zod'

/**
 * Single route definition for RBAC
 */
export const routeSchema = z.object({
  path: z.string().min(1),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', '*']),
  requiredPermissions: z.array(z.string()),
  public: z.boolean().default(false),
  description: z.string().optional(),
})

/**
 * Route map file schema (per service)
 * File: configmaps/routes/route_map.{service}.json
 *
 * Example:
 * {
 *   "version": "1.0",
 *   "service": "jinbe",
 *   "routes": [
 *     {
 *       "path": "/api/clusters",
 *       "method": "GET",
 *       "requiredPermissions": ["clusters:read"],
 *       "public": false
 *     },
 *     {
 *       "path": "/api/clusters",
 *       "method": "POST",
 *       "requiredPermissions": ["clusters:write"],
 *       "public": false
 *     }
 *   ]
 * }
 */
export const routeMapFileSchema = z.object({
  version: z.string().default('1.0'),
  service: z.string().min(1),
  routes: z.array(routeSchema),
})

// Type exports
export type Route = z.infer<typeof routeSchema>
export type RouteMapFile = z.infer<typeof routeMapFileSchema>

// JSON Schema for OpenAPI
export const routeMapFileJsonSchema = {
  type: 'object',
  properties: {
    version: { type: 'string', default: '1.0' },
    service: { type: 'string', minLength: 1 },
    routes: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          path: { type: 'string', minLength: 1 },
          method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', '*'] },
          requiredPermissions: { type: 'array', items: { type: 'string' } },
          public: { type: 'boolean', default: false },
          description: { type: 'string' },
        },
        required: ['path', 'method', 'requiredPermissions'],
      },
    },
  },
  required: ['service', 'routes'],
}
