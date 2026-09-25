import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { requireSuperAdmin } from '../middleware/require-admin.js'
import { SERVICE_NAME_PATTERN } from '../services/rbac.service.js'
import { checkAccess, AccessCheckUnavailableError, OpaQueryError } from '../services/access-check.service.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * POST /api/admin/rbac/access-check — "can X do METHOD PATH, and why?" for the console.
 *
 * Platform admins only: registered inside rbacRoutes, so the admin:read gate there runs first and
 * admin:write is required on top — the answer lists what somebody else holds. Declared admin-only
 * in the jinbe route_map too, so the gateway never lets an anonymous or ordinary caller reach it.
 */

// Built when the plugin registers, not at import: modules that mock rbac.service import this one.
const accessCheckBodySchema = () => z.object({
  email: z.string().trim().email().max(320),
  method: z.string().transform((m) => m.toUpperCase()).pipe(z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])),
  path: z.string().max(2048).regex(/^\/[^\s?#]*$/, 'must be an absolute path with no query or fragment'),
  app: z.string().max(63).regex(SERVICE_NAME_PATTERN).optional(),
})

const errorSchema = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } }

const accessCheckResponseSchema = {
  type: 'object',
  properties: {
    allow: { type: 'boolean' },
    reason: { type: 'string', enum: ['ok', 'not_found', 'forbidden', 'forbidden_org'] },
    app: { type: ['string', 'null'] },
    owners: { type: 'array', items: { type: 'string' } },
    matchingRules: {
      type: 'array',
      items: {
        type: 'object',
        properties: { method: { type: 'string' }, path: { type: 'string' }, permission: { type: 'string' } },
      },
    },
    groups: { type: 'array', items: { type: 'string' } },
    roles: { type: 'array', items: { type: 'string' } },
    permissions: { type: 'array', items: { type: 'string' } },
    superAdmin: { type: 'boolean' },
  },
  required: ['allow', 'reason', 'app', 'owners', 'matchingRules', 'groups', 'roles', 'permissions', 'superAdmin'],
}

export async function accessCheckRoutes(fastify: FastifyInstance) {
  const bodySchema = accessCheckBodySchema()

  fastify.post('/access-check', {
    preHandler: requireSuperAdmin,
    schema: {
      description:
        'Ask OPA whether a user may call METHOD PATH and why: the gateway verdict (rbac.decision) plus the ' +
        'owning service, the route rules that matched, and the groups, roles and permissions that applied ' +
        '(rbac.simulate). `owners` with two or more services is a route tie, which the policy answers not_found. ' +
        'Requires admin:write. 503 when OPA_URL / OPA_TOKEN are not configured; 502 when OPA does not answer.',
      tags: ['rbac'],
      body: {
        type: 'object',
        required: ['email', 'method', 'path'],
        properties: {
          email: { type: 'string', format: 'email' },
          method: { type: 'string', description: 'GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS (any case)' },
          path: { type: 'string', description: 'Absolute request path, no query string, e.g. /api/clusters/42' },
          app: { type: 'string', description: 'Pin the service instead of letting the policy resolve the owner' },
        },
      },
      response: {
        200: accessCheckResponseSchema,
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        502: errorSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = bodySchema.safeParse(request.body)
    if (!parsed.success) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: parsed.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; '),
      })
    }

    try {
      return reply.send(await checkAccess(parsed.data))
    } catch (err) {
      if (err instanceof AccessCheckUnavailableError) {
        return reply.status(503).send({ error: 'Service Unavailable', message: err.message })
      }
      if (err instanceof OpaQueryError) {
        request.log.warn({ reason: err.message }, 'access-check: OPA did not answer')
        return reply.status(502).send({ error: 'Bad Gateway', message: err.message })
      }
      throw err
    }
  })
}
