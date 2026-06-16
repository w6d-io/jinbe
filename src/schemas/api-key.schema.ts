import { z } from 'zod'

// ── Params ──────────────────────────────────────────────────────────────────
export const apiKeyClientIdParamSchema = z.object({
  organizationId: z.string().uuid('organization_id must be a valid UUID'),
  clientId: z.string().min(1, 'clientId is required'),
})
export type ApiKeyClientIdParam = z.infer<typeof apiKeyClientIdParamSchema>

// ── Create body ───────────────────────────────────────────────────────────────
export const apiKeyCreateBodySchema = z.object({
  label: z.string().min(1, 'label is required').max(200),
  scopes: z.array(z.string().min(1)).min(1, 'at least one scope is required'),
  audience: z.array(z.string()).optional(),
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
}

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
  },
  additionalProperties: false,
}

const apiKeyViewProps = {
  client_id: { type: 'string' },
  organization_id: { type: 'string', format: 'uuid' },
  label: { type: 'string' },
  scopes: { type: 'array', items: { type: 'string' } },
  created_by: { type: 'string', nullable: true },
  created_at: { type: 'string', format: 'date-time', nullable: true },
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
