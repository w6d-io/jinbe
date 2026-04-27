import { z } from 'zod'

/**
 * Groups file schema (groups.json)
 *
 * This is a standalone file containing group definitions.
 * Groups are no longer stored in bindings.json.
 *
 * Structure:
 * {
 *   "emails": {},
 *   "groups": {
 *     "super_admins": {
 *       "global": ["super_admin"],
 *       "jinbe": ["admin", "write"],
 *       "kuma_v2": ["admin"]
 *     },
 *     "editors": {
 *       "jinbe": ["write"],
 *       "kuma_v2": ["write"]
 *     }
 *   }
 * }
 */

/**
 * Service roles mapping: service name → roles array
 */
export const serviceRolesSchema = z.record(z.string(), z.array(z.string()))

/**
 * Group definition: { service: roles[] }
 */
export const groupDefinitionSchema = serviceRolesSchema

/**
 * Groups map: { groupName: { service: roles[] } }
 */
export const groupsMapSchema = z.record(z.string(), groupDefinitionSchema)

/**
 * Groups file schema: { emails: {}, groups: { groupName: { service: roles[] } } }
 */
export const groupsFileSchema = z.object({
  emails: z.record(z.string(), z.unknown()).optional().default({}),
  groups: groupsMapSchema,
})

/**
 * Group for API responses (flattened from file format)
 */
export const groupSchema = z.object({
  name: z.string().min(1),
  services: serviceRolesSchema, // { "jinbe": ["admin"], "kuma_v2": ["viewer"] }
})

/**
 * Request body for creating/updating a group
 */
export const createGroupBodySchema = z.object({
  name: z.string().min(1).regex(/^[a-z_]+$/, 'Group name must be lowercase with underscores only'),
  services: serviceRolesSchema,
})

/**
 * Request body for updating a group (partial)
 */
export const updateGroupBodySchema = z.object({
  services: serviceRolesSchema,
})

// Type exports
export type ServiceRoles = z.infer<typeof serviceRolesSchema>
export type GroupDefinition = z.infer<typeof groupDefinitionSchema>
export type GroupsMap = z.infer<typeof groupsMapSchema>
export type GroupsFile = z.infer<typeof groupsFileSchema>
export type Group = z.infer<typeof groupSchema>
export type CreateGroupBody = z.infer<typeof createGroupBodySchema>
export type UpdateGroupBody = z.infer<typeof updateGroupBodySchema>

// JSON Schema for OpenAPI
export const groupJsonSchema = {
  type: 'object',
  properties: {
    name: { type: 'string', pattern: '^[a-z_]+$' },
    services: {
      type: 'object',
      description: 'Service → roles mapping',
      additionalProperties: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  },
  required: ['name', 'services'],
}

export const createGroupBodyJsonSchema = {
  type: 'object',
  properties: {
    name: {
      type: 'string',
      pattern: '^[a-z_]+$',
      description: 'Group name (lowercase with underscores)',
    },
    services: {
      type: 'object',
      description: 'Service → roles mapping',
      additionalProperties: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  },
  required: ['name', 'services'],
}

export const updateGroupBodyJsonSchema = {
  type: 'object',
  properties: {
    services: {
      type: 'object',
      description: 'Service → roles mapping',
      additionalProperties: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  },
  required: ['services'],
}

// Groups file JSON schema for OpenAPI
export const groupsFileJsonSchema = {
  type: 'object',
  description: 'Groups file with emails and groups definitions',
  properties: {
    emails: {
      type: 'object',
      description: 'Email mappings (legacy)',
      additionalProperties: true,
    },
    groups: {
      type: 'object',
      description: 'Groups definitions: group name → { service → roles[] }',
      additionalProperties: {
        type: 'object',
        additionalProperties: {
          type: 'array',
          items: { type: 'string' },
        },
      },
    },
  },
  required: ['groups'],
}
