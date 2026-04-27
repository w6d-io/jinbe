import { z } from 'zod'

/**
 * Oathkeeper authenticator handlers
 */
export const authenticatorHandlerSchema = z.enum([
  'noop',
  'cookie_session',
  'jwt',
  'oauth2_introspection',
  'oauth2_client_credentials',
  'anonymous',
  'unauthorized',
])

/**
 * Oathkeeper authorizer handlers
 */
export const authorizerHandlerSchema = z.enum([
  'allow',
  'deny',
  'remote_json',
  'keto_engine_acp_ory',
])

/**
 * Oathkeeper mutator handlers
 */
export const mutatorHandlerSchema = z.enum(['noop', 'header', 'cookie', 'id_token', 'hydrator'])

/**
 * HTTP methods
 */
export const httpMethodSchema = z.enum([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'HEAD',
])

/**
 * Authenticator configuration
 */
export const authenticatorSchema = z.object({
  handler: authenticatorHandlerSchema,
  config: z.record(z.unknown()).optional(),
})

/**
 * Authorizer configuration
 */
export const authorizerSchema = z.object({
  handler: authorizerHandlerSchema,
  config: z.record(z.unknown()).optional(),
})

/**
 * Mutator configuration
 */
export const mutatorSchema = z.object({
  handler: mutatorHandlerSchema,
  config: z.record(z.unknown()).optional(),
})

/**
 * Upstream configuration
 */
export const upstreamSchema = z.object({
  url: z.string().url(),
  preserve_host: z.boolean().optional(),
  strip_path: z.string().optional(),
})

/**
 * Match configuration
 */
export const matchSchema = z.object({
  url: z.string().min(1),
  methods: z.array(httpMethodSchema),
})

/**
 * Single Oathkeeper access rule
 *
 * Example:
 * {
 *   "id": "jinbe-api",
 *   "upstream": { "url": "http://jinbe.w6d-ops:8080" },
 *   "match": {
 *     "url": "https://kuma.dev.w6d.io/api/<**>",
 *     "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
 *   },
 *   "authenticators": [{ "handler": "cookie_session" }],
 *   "authorizer": { "handler": "remote_json" },
 *   "mutators": [{ "handler": "header" }]
 * }
 */
export const oathkeeperRuleSchema = z.object({
  id: z.string().min(1),
  upstream: upstreamSchema,
  match: matchSchema,
  authenticators: z.array(authenticatorSchema),
  authorizer: authorizerSchema,
  mutators: z.array(mutatorSchema),
  // Optional: errors configuration
  errors: z
    .array(
      z.object({
        handler: z.string(),
        config: z.record(z.unknown()).optional(),
      })
    )
    .optional(),
})

/**
 * Access rules file schema (array of rules)
 * File: configmaps/access-rules.json
 */
export const accessRulesFileSchema = z.array(oathkeeperRuleSchema)

// Type exports
export type AuthenticatorHandler = z.infer<typeof authenticatorHandlerSchema>
export type AuthorizerHandler = z.infer<typeof authorizerHandlerSchema>
export type MutatorHandler = z.infer<typeof mutatorHandlerSchema>
export type HttpMethod = z.infer<typeof httpMethodSchema>
export type Authenticator = z.infer<typeof authenticatorSchema>
export type Authorizer = z.infer<typeof authorizerSchema>
export type Mutator = z.infer<typeof mutatorSchema>
export type Upstream = z.infer<typeof upstreamSchema>
export type Match = z.infer<typeof matchSchema>
export type OathkeeperRule = z.infer<typeof oathkeeperRuleSchema>
export type AccessRulesFile = z.infer<typeof accessRulesFileSchema>

// JSON Schema for OpenAPI
export const oathkeeperRuleJsonSchema = {
  type: 'object',
  properties: {
    id: { type: 'string', minLength: 1 },
    upstream: {
      type: 'object',
      properties: {
        url: { type: 'string', format: 'uri' },
        preserve_host: { type: 'boolean' },
        strip_path: { type: 'string' },
      },
      required: ['url'],
    },
    match: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        methods: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
          },
        },
      },
      required: ['url', 'methods'],
    },
    authenticators: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          handler: {
            type: 'string',
            enum: [
              'noop',
              'cookie_session',
              'jwt',
              'oauth2_introspection',
              'oauth2_client_credentials',
              'anonymous',
              'unauthorized',
            ],
          },
          config: { type: 'object' },
        },
        required: ['handler'],
      },
    },
    authorizer: {
      type: 'object',
      properties: {
        handler: {
          type: 'string',
          enum: ['allow', 'deny', 'remote_json', 'keto_engine_acp_ory'],
        },
        config: { type: 'object' },
      },
      required: ['handler'],
    },
    mutators: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          handler: { type: 'string', enum: ['noop', 'header', 'cookie', 'id_token', 'hydrator'] },
          config: { type: 'object' },
        },
        required: ['handler'],
      },
    },
  },
  required: ['id', 'upstream', 'match', 'authenticators', 'authorizer', 'mutators'],
}

export const accessRulesFileJsonSchema = {
  type: 'array',
  items: oathkeeperRuleJsonSchema,
}
