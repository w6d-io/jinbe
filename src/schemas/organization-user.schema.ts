import { z } from 'zod'

// Organization ID param
export const organizationIdParamSchema = z.object({
  organizationId: z.string().uuid('organization_id must be a valid UUID'),
})

// Organization + User ID params
export const organizationUserIdParamSchema = z.object({
  organizationId: z.string().uuid('organization_id must be a valid UUID'),
  id: z.string().uuid('Invalid user ID format'),
})

// Create user in organization
export const organizationUserCreateBodySchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  sendInvite: z.boolean().optional().default(false),
})

// Update user in organization
export const organizationUserUpdateBodySchema = z.object({
  traits: z.object({
    email: z.string().email().optional(),
    name: z.string().optional(),
  }).optional(),
  state: z.enum(['active', 'inactive']).optional(),
})

// Query params for listing organization users
export const organizationUsersQuerySchema = z.object({
  page_size: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .refine((val) => val === undefined || (val > 0 && val <= 1000), {
      message: 'Page size must be between 1 and 1000',
    }),
  credentials_identifier: z.string().optional(),
})

// Type exports
export type OrganizationIdParam = z.infer<typeof organizationIdParamSchema>
export type OrganizationUserIdParam = z.infer<typeof organizationUserIdParamSchema>
export type OrganizationUserCreateBody = z.infer<typeof organizationUserCreateBodySchema>
export type OrganizationUserUpdateBody = z.infer<typeof organizationUserUpdateBodySchema>
export type OrganizationUsersQuery = z.infer<typeof organizationUsersQuerySchema>

// JSON Schema exports for OpenAPI
export const organizationIdParamJsonSchema = {
  type: 'object',
  required: ['organizationId'],
  properties: {
    organizationId: { type: 'string', format: 'uuid', description: 'Organization identifier' },
  },
}

export const organizationUserIdParamJsonSchema = {
  type: 'object',
  required: ['organizationId', 'id'],
  properties: {
    organizationId: { type: 'string', format: 'uuid', description: 'Organization identifier' },
    id: { type: 'string', format: 'uuid', description: 'User ID' },
  },
}

export const organizationUserCreateBodyJsonSchema = {
  type: 'object',
  required: ['email'],
  properties: {
    email: { type: 'string', format: 'email' },
    name: { type: 'string' },
    sendInvite: { type: 'boolean', default: false },
  },
  additionalProperties: false,
}

export const organizationUserUpdateBodyJsonSchema = {
  type: 'object',
  properties: {
    traits: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        name: { type: 'string' },
      },
    },
    state: { type: 'string', enum: ['active', 'inactive'] },
  },
}
