import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import {
  scimAuth,
  sendScimError,
  SCIM_CONTENT_TYPE,
} from '../middleware/scim-auth.js'
import {
  scimService,
  ScimError,
  SCIM_USER_SCHEMA,
  SCIM_LIST_RESPONSE_URN,
  SCIM_MAX_RESULTS,
  type ScimUserInput,
  type ScimPatchOperation,
} from '../services/scim.service.js'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * SCIM 2.0 endpoints (RFC 7644) — Users only (spec phase 1).
 * Mounted at /scim/v2 in server.ts, OUTSIDE the /api scope: no Kratos cookie,
 * no TokenReview — every route is gated by the scimAuth bearer check (hashed
 * tokens in rbac:scim:tokens), registered as the first hook so requests
 * fail closed 401 before body parsing/validation.
 *
 * GET  /ServiceProviderConfig | /ResourceTypes | /Schemas   (static, authenticated)
 * GET  /Users?filter=userName eq "x"&startIndex=&count=     (ListResponse)
 * POST /Users                                               (201; 409 uniqueness on existing email)
 * GET|PUT|PATCH|DELETE /Users/:id                           (DELETE = soft-deactivate, never deleteIdentity)
 */

const SCIM_SPC_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
const SCIM_RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType'

/** Loose response schema — SCIM payload shapes are built by the service. */
const anyObject = { type: 'object', additionalProperties: true } as const

/** ServiceProviderConfig — accurate to what phase 1 implements (spec §2). */
const SERVICE_PROVIDER_CONFIG = {
  schemas: [SCIM_SPC_SCHEMA],
  patch: { supported: true },
  bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults: SCIM_MAX_RESULTS },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [
    {
      type: 'oauthbearertoken',
      name: 'OAuth Bearer Token',
      description: 'Long-lived bearer token minted per IdP (hashed at rest).',
      specUri: 'https://www.rfc-editor.org/info/rfc6750',
      primary: true,
    },
  ],
  meta: {
    resourceType: 'ServiceProviderConfig',
    location: '/scim/v2/ServiceProviderConfig',
  },
}

const USER_RESOURCE_TYPE = {
  schemas: [SCIM_RESOURCE_TYPE_SCHEMA],
  id: 'User',
  name: 'User',
  endpoint: '/Users',
  description: 'User Account',
  schema: SCIM_USER_SCHEMA,
  schemaExtensions: [],
  meta: { resourceType: 'ResourceType', location: '/scim/v2/ResourceTypes/User' },
}

/** /Schemas — the User schema, limited to the attributes actually implemented. */
const USER_SCHEMA_DEFINITION = {
  id: SCIM_USER_SCHEMA,
  name: 'User',
  description: 'User Account',
  attributes: [
    {
      name: 'userName', type: 'string', multiValued: false, required: true,
      caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'server',
    },
    {
      name: 'name', type: 'complex', multiValued: false, required: false,
      mutability: 'readWrite', returned: 'default',
      subAttributes: [
        { name: 'formatted', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none' },
        { name: 'givenName', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none' },
        { name: 'familyName', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none' },
      ],
    },
    {
      name: 'displayName', type: 'string', multiValued: false, required: false,
      caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none',
    },
    {
      name: 'emails', type: 'complex', multiValued: true, required: false,
      mutability: 'readWrite', returned: 'default',
      subAttributes: [
        { name: 'value', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none' },
        { name: 'primary', type: 'boolean', multiValued: false, required: false, mutability: 'readWrite', returned: 'default' },
      ],
    },
    {
      name: 'active', type: 'boolean', multiValued: false, required: false,
      mutability: 'readWrite', returned: 'default',
    },
    {
      name: 'groups', type: 'complex', multiValued: true, required: false,
      mutability: 'readOnly', returned: 'default',
      subAttributes: [
        { name: 'value', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readOnly', returned: 'default', uniqueness: 'none' },
        { name: 'display', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readOnly', returned: 'default', uniqueness: 'none' },
      ],
    },
  ],
  meta: { resourceType: 'Schema', location: `/scim/v2/Schemas/${SCIM_USER_SCHEMA}` },
}

function listResponse(resources: unknown[], totalResults = resources.length) {
  return {
    schemas: [SCIM_LIST_RESPONSE_URN],
    totalResults,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  }
}

/** SCIM machine actor for the audit trail (spec §5: actor = scim:<label>). */
function scimActor(request: FastifyRequest) {
  return {
    email: `scim:${request.scimToken?.label ?? 'unknown'}`,
    ip: request.ip,
    ua: (request.headers['user-agent'] as string) || null,
  }
}

function emitScimAudit(
  request: FastifyRequest,
  verb: string,
  target: string,
  details?: Record<string, unknown>,
  result: 'applied' | 'failed' = 'applied'
) {
  auditEventService.emit({
    category: 'access',
    kind: 'change',
    verb,
    target,
    result,
    actor: scimActor(request),
    source: 'scim',
    targetType: 'user',
    requestId: request.id as string,
    details: { ...details, tokenId: request.scimToken?.tokenId },
  }).catch(() => {})
}

/**
 * Outbox notification (spec §5). Dynamic import avoids pulling the whole
 * server module graph into unit tests of this file; a failure is swallowed —
 * notifications are best-effort by design (outbox pattern).
 */
function emitScimNotification(
  action: 'created' | 'updated' | 'deleted',
  payload: Record<string, unknown>
) {
  import('../server.js')
    .then(({ notificationService }) =>
      notificationService.emit({ action, entity_type: 'user', payload })
    )
    .catch(() => {})
}

/** Run a handler, converting ScimError into an RFC 7644 error response. */
async function scimHandler(
  reply: FastifyReply,
  fn: () => Promise<unknown>
): Promise<unknown> {
  try {
    return await fn()
  } catch (err) {
    if (err instanceof ScimError) {
      return sendScimError(reply, err.status, err.message, err.scimType)
    }
    throw err
  }
}

export async function scimRoutes(fastify: FastifyInstance) {
  // IdPs send Content-Type: application/scim+json — Fastify only parses
  // application/json by default. Encapsulated: applies to SCIM routes only.
  fastify.addContentTypeParser(
    'application/scim+json',
    { parseAs: 'string' },
    (_request, body, done) => {
      try {
        done(null, body ? JSON.parse(body as string) : {})
      } catch (err) {
        done(err as Error, undefined)
      }
    }
  )

  // Bearer-token gate on EVERY SCIM route — onRequest so a missing/invalid
  // token fails closed 401 before body parsing and schema validation.
  fastify.addHook('onRequest', scimAuth)

  // ── Discovery (static; authenticated — spec §3) ────────────────────────────

  fastify.get(
    '/ServiceProviderConfig',
    {
      schema: {
        description: 'SCIM 2.0 service provider configuration (RFC 7643 §5).',
        tags: ['scim'],
        response: { 200: anyObject },
      },
    },
    async (_request, reply) => {
      reply.header('Content-Type', SCIM_CONTENT_TYPE)
      return SERVICE_PROVIDER_CONFIG
    }
  )

  fastify.get(
    '/ResourceTypes',
    {
      schema: {
        description: 'SCIM 2.0 resource types (RFC 7643 §6). Users only in phase 1.',
        tags: ['scim'],
        response: { 200: anyObject },
      },
    },
    async (_request, reply) => {
      reply.header('Content-Type', SCIM_CONTENT_TYPE)
      return listResponse([USER_RESOURCE_TYPE])
    }
  )

  fastify.get(
    '/Schemas',
    {
      schema: {
        description: 'SCIM 2.0 schema definitions (RFC 7643 §7).',
        tags: ['scim'],
        response: { 200: anyObject },
      },
    },
    async (_request, reply) => {
      reply.header('Content-Type', SCIM_CONTENT_TYPE)
      return listResponse([USER_SCHEMA_DEFINITION])
    }
  )

  // ── Users ──────────────────────────────────────────────────────────────────

  fastify.get(
    '/Users',
    {
      schema: {
        description:
          'List/filter SCIM users. Supports filter=userName eq "..." / externalId eq "..." and startIndex/count pagination.',
        tags: ['scim'],
        querystring: {
          type: 'object',
          properties: {
            filter: { type: 'string' },
            startIndex: { type: 'integer' },
            count: { type: 'integer' },
          },
        },
        response: { 200: anyObject },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const query = request.query as { filter?: string; startIndex?: number; count?: number }
        const result = await scimService.listUsers(query)
        reply.header('Content-Type', SCIM_CONTENT_TYPE)
        return {
          schemas: [SCIM_LIST_RESPONSE_URN],
          totalResults: result.totalResults,
          startIndex: result.startIndex,
          itemsPerPage: result.itemsPerPage,
          Resources: result.resources,
        }
      })
  )

  fastify.get(
    '/Users/:id',
    {
      schema: {
        description: 'Get a SCIM user by Kratos identity id.',
        tags: ['scim'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        response: { 200: anyObject },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const { id } = request.params as { id: string }
        const user = await scimService.getUser(id)
        reply.header('Content-Type', SCIM_CONTENT_TYPE)
        return user
      })
  )

  fastify.post(
    '/Users',
    {
      schema: {
        description:
          'Create a SCIM user (Kratos identity, default group [users], scim.managed marking). 409 uniqueness on existing email.',
        tags: ['scim'],
        body: anyObject,
        response: { 201: anyObject },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const body = request.body as ScimUserInput
        const user = await scimService.createUser(body, request.scimToken!.tokenId)
        emitScimAudit(request, 'create', `user:${user.userName}`, {
          id: user.id, externalId: body.externalId ?? null,
        })
        emitScimNotification('created', { id: user.id, email: user.userName })
        reply.header('Content-Type', SCIM_CONTENT_TYPE)
        reply.header('Location', `/scim/v2/Users/${user.id}`)
        return reply.status(201).send(user)
      })
  )

  fastify.put(
    '/Users/:id',
    {
      schema: {
        description: 'Replace a SCIM user (traits + active state; groups preserved).',
        tags: ['scim'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        body: anyObject,
        response: { 200: anyObject },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const { id } = request.params as { id: string }
        const user = await scimService.replaceUser(
          id,
          request.body as ScimUserInput,
          request.scimToken!.tokenId
        )
        emitScimAudit(request, 'update', `user:${user.userName}`, { id, op: 'replace' })
        emitScimNotification('updated', { id, email: user.userName })
        reply.header('Content-Type', SCIM_CONTENT_TYPE)
        return user
      })
  )

  fastify.patch(
    '/Users/:id',
    {
      schema: {
        description:
          'PATCH a SCIM user (RFC 7644 PatchOp): active true/false at minimum, plus userName/name/externalId. active=false revokes sessions.',
        tags: ['scim'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
        body: anyObject,
        response: { 200: anyObject },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const { id } = request.params as { id: string }
        const body = request.body as { Operations?: ScimPatchOperation[] }
        const user = await scimService.patchUser(id, body, request.scimToken!.tokenId)
        emitScimAudit(request, 'update', `user:${user.userName}`, {
          id, op: 'patch', active: user.active,
        })
        emitScimNotification('updated', { id, email: user.userName, status: user.active ? 'active' : 'inactive' })
        reply.header('Content-Type', SCIM_CONTENT_TYPE)
        return user
      })
  )

  fastify.delete(
    '/Users/:id',
    {
      schema: {
        description:
          'Soft-delete a SCIM user: state → inactive + all sessions revoked. The Kratos identity is NEVER deleted (audit/grant provenance).',
        tags: ['scim'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      },
    },
    async (request, reply) =>
      scimHandler(reply, async () => {
        const { id } = request.params as { id: string }
        await scimService.deactivateUser(id, request.scimToken!.tokenId)
        emitScimAudit(request, 'delete', `user:${id}`, { id, softDelete: true })
        emitScimNotification('deleted', { id })
        return reply.status(204).send()
      })
  )
}
