import { z } from 'zod'

/**
 * Single role definition
 */
export const roleSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  permissions: z.array(z.string()),
  // Role inheritance - this role includes all permissions from inherited roles
  inherits: z.array(z.string()).optional(),
})

/**
 * Roles file schema (per service)
 * File: configmaps/roles/roles.{service}.json
 *
 * Example:
 * {
 *   "version": "1.0",
 *   "service": "jinbe",
 *   "roles": [
 *     {
 *       "name": "admin",
 *       "description": "Full access to all resources",
 *       "permissions": ["*"]
 *     },
 *     {
 *       "name": "editor",
 *       "description": "Can read and write resources",
 *       "permissions": ["read", "write"],
 *       "inherits": ["viewer"]
 *     },
 *     {
 *       "name": "viewer",
 *       "description": "Read-only access",
 *       "permissions": ["read"]
 *     }
 *   ]
 * }
 */
export const rolesFileSchema = z.object({
  version: z.string().default('1.0'),
  service: z.string().min(1),
  roles: z.array(roleSchema),
})

// Type exports
export type Role = z.infer<typeof roleSchema>
export type RolesFile = z.infer<typeof rolesFileSchema>

// JSON Schema for OpenAPI
export const rolesFileJsonSchema = {
  type: 'object',
  properties: {
    version: { type: 'string', default: '1.0' },
    service: { type: 'string', minLength: 1 },
    roles: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1 },
          description: { type: 'string' },
          permissions: { type: 'array', items: { type: 'string' } },
          inherits: { type: 'array', items: { type: 'string' } },
        },
        required: ['name', 'permissions'],
      },
    },
  },
  required: ['service', 'roles'],
}
