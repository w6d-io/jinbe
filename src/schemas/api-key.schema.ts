import { z } from 'zod'

// ── Params ──────────────────────────────────────────────────────────────────
export const apiKeyClientIdParamSchema = z.object({
  organizationId: z.string().uuid('organization_id must be a valid UUID'),
  clientId: z.string().min(1, 'clientId is required'),
})
export type ApiKeyClientIdParam = z.infer<typeof apiKeyClientIdParamSchema>

/** The longest an org machine key may be given, when it is given an expiry at all. */
export const ORG_KEY_MAX_DAYS = 365
/** The longest a personal key may live (owner decision: 30 days), and its default. */
export const PERSONAL_KEY_MAX_DAYS = 30

// ── Create body ───────────────────────────────────────────────────────────────
export const apiKeyCreateBodySchema = z.object({
  label: z.string().min(1, 'label is required').max(200),
  scopes: z.array(z.string().min(1)).min(1, 'at least one scope is required'),
  audience: z.array(z.string()).optional(),
  /** Optional for an org machine key; absent = no expiry. */
  expires_in_days: z.number().int().min(1).max(ORG_KEY_MAX_DAYS).optional(),
})
export type ApiKeyCreateBody = z.infer<typeof apiKeyCreateBodySchema>

// ── Type exports ──────────────────────────────────────────────────────────────
export interface ApiKeyView {
  client_id: string
  organization_id: string
  label: string
  scopes: string[]
  created_by: string | null
  created_at: string | null
  /** RFC 3339, or null for a key that never expires. */
  expires_at: string | null
  /** RFC 3339 last use (within a minute), null when never seen or unknown. */
  last_used_at: string | null
  /** The creator's address, when the caller may see it (services/api-key-views.ts); null otherwise. */
  created_by_email: string | null
}

// ── Personal keys ─────────────────────────────────────────────────────────────
export const personalKeyCreateBodySchema = z.object({
  label: z.string().min(1, 'label is required').max(200),
  organization_id: z.string().uuid('organization_id must be a valid UUID'),
  scopes: z.array(z.string().min(1)).min(1, 'at least one scope is required'),
  /** Absent = the longest allowed now (the administrator's maximum, mcp/settings.ts). */
  expires_in_days: z.number().int().min(1).max(PERSONAL_KEY_MAX_DAYS).optional(),
})
export type PersonalKeyCreateBody = z.infer<typeof personalKeyCreateBodySchema>

export const personalScopesQuerySchema = z.object({ organization_id: z.string().uuid('organization_id must be a valid UUID') })

export const apiKeyPolicySchema = z.object({ personal_keys: z.enum(['allowed', 'forbidden']) }).strict()
export type ApiKeyPolicy = z.infer<typeof apiKeyPolicySchema>

/** Returned ONCE on creation — includes the secret. */
export interface ApiKeySecretView extends ApiKeyView {
  client_secret: string
}

// ── JSON Schema exports for OpenAPI ─────────────────────────────────────────────
export const organizationIdParamJsonSchema = {
  type: 'object',
  required: ['organizationId'],
  properties: {
    organizationId: { type: 'string', format: 'uuid', description: 'Organization identifier' },
  },
}

export const apiKeyClientIdParamJsonSchema = {
  type: 'object',
  required: ['organizationId', 'clientId'],
  properties: {
    organizationId: { type: 'string', format: 'uuid', description: 'Organization identifier' },
    clientId: { type: 'string', description: 'Hydra OAuth2 client_id' },
  },
}

export const apiKeyCreateBodyJsonSchema = {
  type: 'object',
  required: ['label', 'scopes'],
  properties: {
    label: { type: 'string', minLength: 1, maxLength: 200, description: 'Human label for the key' },
    scopes: {
      type: 'array',
      items: { type: 'string' },
      minItems: 1,
      description: 'Requested scopes (validated against the allowed catalog)',
    },
    audience: { type: 'array', items: { type: 'string' }, description: 'Optional token audience' },
    expires_in_days: { type: 'integer', minimum: 1, maximum: ORG_KEY_MAX_DAYS, description: 'Optional expiry in days; absent = never expires' },
  },
  additionalProperties: false,
}

export const personalKeyCreateBodyJsonSchema = {
  type: 'object',
  required: ['label', 'organization_id', 'scopes'],
  properties: {
    label: { type: 'string', minLength: 1, maxLength: 200 },
    organization_id: { type: 'string', format: 'uuid', description: 'The one organization the key acts in' },
    scopes: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'Permissions you hold in that organization' },
    expires_in_days: { type: 'integer', minimum: 1, maximum: PERSONAL_KEY_MAX_DAYS, description: 'At most the maximum an administrator set (30 days or less); absent = that maximum' },
  },
  additionalProperties: false,
}

export const apiKeyPolicyJsonSchema = {
  type: 'object',
  required: ['personal_keys'],
  properties: { personal_keys: { type: 'string', enum: ['allowed', 'forbidden'] } },
  additionalProperties: false,
}

export const scopeCatalogResponseJsonSchema = {
  type: 'object',
  properties: {
    scopes: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          scope: { type: 'string', description: 'A permission (resource:verb)' },
          sites: { type: 'array', items: { type: 'string' }, description: 'The sites whose routes require it' },
        },
      },
    },
  },
}

const apiKeyViewProps = {
  client_id: { type: 'string' },
  organization_id: { type: 'string', format: 'uuid' },
  label: { type: 'string' },
  scopes: { type: 'array', items: { type: 'string' } },
  created_by: { type: 'string', nullable: true },
  created_at: { type: 'string', format: 'date-time', nullable: true },
  expires_at: { type: 'string', format: 'date-time', nullable: true },
  last_used_at: { type: 'string', format: 'date-time', nullable: true, description: 'Last use, to the minute; null when never seen' },
  created_by_email: { type: 'string', nullable: true, description: 'The creator, when you are them or may see users' },
}

export const apiKeyViewJsonSchema = {
  type: 'object',
  properties: apiKeyViewProps,
}

export const apiKeySecretViewJsonSchema = {
  type: 'object',
  description: 'Returned ONCE on creation. Copy the client_secret now — it cannot be retrieved again.',
  properties: {
    ...apiKeyViewProps,
    client_secret: { type: 'string', description: 'Shown only once' },
  },
}

export const apiKeyListResponseJsonSchema = {
  type: 'object',
  properties: {
    data: { type: 'array', items: apiKeyViewJsonSchema },
    total: { type: 'number' },
  },
}
