import { z } from 'zod'

/**
 * Admin schemas for Kratos user management
 */

// Kratos Identity traits schema
export const kratosTraitsSchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
})

// Kratos Identity response schema
export const kratosIdentitySchema = z.object({
  id: z.string().uuid(),
  schema_id: z.string(),
  schema_url: z.string().optional(),
  state: z.enum(['active', 'inactive']).optional(),
  state_changed_at: z.string().optional(),
  traits: kratosTraitsSchema,
  verifiable_addresses: z
    .array(
      z.object({
        id: z.string().uuid(),
        value: z.string(),
        verified: z.boolean(),
        via: z.string(),
        status: z.string(),
      })
    )
    .optional(),
  recovery_addresses: z
    .array(
      z.object({
        id: z.string().uuid(),
        value: z.string(),
        via: z.string(),
      })
    )
    .optional(),
  metadata_public: z.record(z.unknown()).nullable().optional(),
  metadata_admin: z.record(z.unknown()).nullable().optional(),
  created_at: z.string(),
  updated_at: z.string(),
})

// Create identity request schema
export const kratosIdentityCreateSchema = z.object({
  schema_id: z.string().default('default'),
  traits: kratosTraitsSchema,
  state: z.enum(['active', 'inactive']).default('active'),
  metadata_public: z.record(z.unknown()).optional(),
  metadata_admin: z.record(z.unknown()).optional(),
  credentials: z
    .object({
      password: z
        .object({
          config: z.object({
            password: z.string().min(8, 'Password must be at least 8 characters'),
          }),
        })
        .optional(),
    })
    .optional(),
})

// Update identity request schema
export const kratosIdentityUpdateSchema = z.object({
  schema_id: z.string().optional(),
  traits: kratosTraitsSchema.partial().optional(),
  state: z.enum(['active', 'inactive']).optional(),
  metadata_public: z.record(z.unknown()).optional(),
  metadata_admin: z.record(z.unknown()).optional(),
})

// User ID param schema (UUID format for Kratos)
export const userIdParamSchema = z.object({
  id: z.string().uuid('Invalid user ID format'),
})

// Users list query schema with pagination
export const usersQuerySchema = z.object({
  page_size: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .refine((val) => val === undefined || (val > 0 && val <= 1000), {
      message: 'Page size must be between 1 and 1000',
    }),
  page_token: z.string().optional(),
  credentials_identifier: z.string().optional(),
})

// User email param schema (for group management endpoints)
export const userEmailParamSchema = z.object({
  email: z.string().email('Invalid email format'),
})

// User groups update request schema
export const updateUserGroupsBodySchema = z.object({
  groups: z.array(z.string().min(1, 'Group name cannot be empty')),
})

// Type exports
export type KratosTraits = z.infer<typeof kratosTraitsSchema>
export type KratosIdentity = z.infer<typeof kratosIdentitySchema>
export type KratosIdentityCreate = z.infer<typeof kratosIdentityCreateSchema>
export type KratosIdentityUpdate = z.infer<typeof kratosIdentityUpdateSchema>
export type UserIdParam = z.infer<typeof userIdParamSchema>
export type UsersQueryParams = z.infer<typeof usersQuerySchema>
export type UserEmailParam = z.infer<typeof userEmailParamSchema>
export type UpdateUserGroupsBody = z.infer<typeof updateUserGroupsBodySchema>

// JSON Schema exports for OpenAPI
export const kratosIdentityJsonSchema = {
  type: 'object',
  properties: {
    id: { type: 'string', format: 'uuid' },
    schema_id: { type: 'string' },
    schema_url: { type: 'string' },
    state: { type: 'string', enum: ['active', 'inactive'] },
    state_changed_at: { type: 'string', format: 'date-time' },
    traits: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        name: { type: 'string', description: 'User display name' },
        picture: { type: 'string', format: 'uri', description: 'User avatar URL' },
        providers: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              issuer_url: { type: 'string' },
              provider_type: { type: 'string' },
            },
          },
        },
      },
      required: ['email'],
    },
    metadata_public: { type: 'object', nullable: true, additionalProperties: true },
    metadata_admin: { type: 'object', nullable: true, additionalProperties: true },
    organization_id: { type: 'string', nullable: true },
    created_at: { type: 'string', format: 'date-time' },
    updated_at: { type: 'string', format: 'date-time' },
    // RBAC fields from OPAL
    groups: {
      type: 'array',
      items: { type: 'string' },
      description: 'User groups from OPAL RBAC',
    },
    roles: {
      type: 'array',
      items: { type: 'string' },
      description: 'User roles from OPAL RBAC',
    },
    permissions: {
      type: 'array',
      items: { type: 'string' },
      description: 'User permissions from OPAL RBAC',
    },
  },
}

export const kratosIdentityListJsonSchema = {
  type: 'array',
  items: kratosIdentityJsonSchema,
}

export const userCreateJsonSchema = {
  type: 'object',
  required: ['traits'],
  properties: {
    schema_id: { type: 'string', default: 'default' },
    traits: {
      type: 'object',
      required: ['email'],
      properties: {
        email: { type: 'string', format: 'email' },
        name: {
          type: 'object',
          properties: {
            first: { type: 'string' },
            last: { type: 'string' },
          },
        },
      },
    },
    state: { type: 'string', enum: ['active', 'inactive'], default: 'active' },
    credentials: {
      type: 'object',
      properties: {
        password: {
          type: 'object',
          properties: {
            config: {
              type: 'object',
              required: ['password'],
              properties: {
                password: { type: 'string', minLength: 8 },
              },
            },
          },
        },
      },
    },
  },
}

export const userUpdateJsonSchema = {
  type: 'object',
  properties: {
    schema_id: { type: 'string' },
    traits: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        name: {
          type: 'object',
          properties: {
            first: { type: 'string' },
            last: { type: 'string' },
          },
        },
      },
    },
    state: { type: 'string', enum: ['active', 'inactive'] },
  },
}

// User group management JSON schemas for OpenAPI
export const updateUserGroupsBodyJsonSchema = {
  type: 'object',
  required: ['groups'],
  properties: {
    groups: {
      type: 'array',
      items: { type: 'string' },
      description: 'Array of group names to assign to the user',
    },
  },
}

export const userGroupsResponseJsonSchema = {
  type: 'object',
  properties: {
    email: { type: 'string', format: 'email' },
    groups: {
      type: 'array',
      items: { type: 'string' },
      description: "User's current group memberships",
    },
    availableGroups: {
      type: 'array',
      items: { type: 'string' },
      description: 'Available groups that can be assigned',
    },
  },
}

export const userGroupsUpdateResponseJsonSchema = {
  type: 'object',
  properties: {
    email: { type: 'string', format: 'email' },
    groups: {
      type: 'array',
      items: { type: 'string' },
      description: "User's updated group memberships",
    },
    updatedAt: {
      type: 'string',
      format: 'date-time',
      description: 'Timestamp of the update',
    },
  },
}
