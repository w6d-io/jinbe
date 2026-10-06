import { grantRequestJsonSchema, grantRequestSchema } from '../services/direct-grants.service.js'
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
  // Optional initial org roles (`svc:role`), each under the holding rule (services/org-role-grants.ts).
  roles: z.array(z.string().regex(/^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$/)).max(32).optional(),
  // Optional direct grants in this organisation (scope = its id), each under the policy's verdict.
  grants: z.array(grantRequestSchema).max(32).optional(),
})

// Update user in organization
// An organization edits how a member is named, nothing global to the account: the sign-in address and
// the account state belong to the platform (users:update_email with a recent second factor,
// users:disable). Changing them here let an org admin take over any account it had just added.
export const organizationUserUpdateBodySchema = z.object({
  traits: z.object({
    name: z.string().max(200).optional(),
  }).strict().optional(),
}).strict()

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
    roles: { type: 'array', maxItems: 32, items: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$' } },
    grants: { type: 'array', maxItems: 32, items: grantRequestJsonSchema },
  },
  additionalProperties: false,
}

export const organizationUserUpdateBodyJsonSchema = {
  type: 'object',
  properties: {
    traits: {
      type: 'object',
      additionalProperties: false,
      properties: {
        name: { type: 'string', maxLength: 200 },
      },
    },
  },
  additionalProperties: false,
}
