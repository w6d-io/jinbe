import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { needs } from '../policy/route-access.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { kratosService } from '../services/kratos.service.js'
import { directGrantsRepository } from '../services/direct-grants.repository.js'
import {
  directGrantsService, grantJsonSchema, grantRequestJsonSchema, grantsBodySchema, GrantsRefusedError, view,
} from '../services/direct-grants.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { memberOf } from './org-roles.routes.js'
import { organizationUserIdParamJsonSchema } from '../schemas/organization-user.schema.js'
import {
  badRequestResponseSchema, forbiddenResponseSchema, notFoundResponseSchema, serviceUnavailableResponseSchema, unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * Per-person direct grants (authz-v2-design §2.6) — a role or a permission held without a group:
 *
 *   GET    /api/admin/users/:id/grants                    users.grants:read   one person's grants, every scope
 *   PUT    /api/admin/users/:id/grants                    users.grants:write  replace them (holding rule per change)
 *   DELETE /api/admin/users/:id/grants                    users.grants:write  take them all away
 *   DELETE /api/admin/users/:id/grants/:grantId           users.grants:write  take one away
 *   GET    /api/admin/grants                              users.grants:read   everyone holding direct grants (review)
 *   GET    /api/organizations/:org/users/:id/grants       org.members:read    that org's grants of one member
 *   PUT    /api/organizations/:org/users/:id/grants       org.members:write   replace them (scope: that org only)
 *   DELETE /api/organizations/:org/users/:id/grants/:gid  org.members:write   take one away
 *
 * Every change is decided by the policy (rbac.delegation grant_direct / revoke_direct verdicts); a
 * refusal answers 403 with each refused grant, its reasons, what is missing and who could grant it.
 */

const ORG = { org: 'organizationId' } as const

const idParams = { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } }
const grantIdParams = { type: 'object', required: ['id', 'grantId'], properties: { id: { type: 'string', format: 'uuid' }, grantId: { type: 'string', format: 'uuid' } } }
const orgGrantIdParams = {
  type: 'object',
  required: ['organizationId', 'id', 'grantId'],
  properties: { organizationId: { type: 'string', format: 'uuid' }, id: { type: 'string', format: 'uuid' }, grantId: { type: 'string', format: 'uuid' } },
}
const personGrants = { type: 'object', properties: { id: { type: 'string' }, email: { type: 'string', nullable: true }, grants: { type: 'array', items: grantJsonSchema } } }
const body = { type: 'object', required: ['grants'], additionalProperties: false, properties: { grants: { type: 'array', maxItems: 100, items: grantRequestJsonSchema } } }
const refusedSchema = {
  ...forbiddenResponseSchema,
  properties: {
    ...forbiddenResponseSchema.properties,
    refused: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          grant: { type: 'object', properties: { id: { type: 'string' }, scope: { type: 'string' }, app: { type: 'string' }, kind: { type: 'string' }, name: { type: 'string' } } },
          reasons: { type: 'array', items: { type: 'string' } },
          missing: { type: 'array', items: { type: 'string' } },
          grantedBy: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
}
const notFound = { ...notFoundResponseSchema, properties: { ...notFoundResponseSchema.properties, error: { type: 'string' } } }
const errors = { 400: badRequestResponseSchema, 401: unauthorizedResponseSchema, 403: refusedSchema, 404: notFound, 503: serviceUnavailableResponseSchema }

/** A refusal, an unreadable policy, or the error handler's turn. */
function answer(reply: FastifyReply, err: unknown) {
  if (err instanceof GrantsRefusedError) return reply.status(403).send({ error: 'Forbidden', code: 'grant_exceeds_own', message: err.message, refused: err.refused })
  if (err instanceof AuthzUnavailableError) return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `Unable to verify authorization: ${err.message}` })
  if ((err as { statusCode?: number }).statusCode === 400) return reply.status(400).send({ error: 'Bad Request', message: (err as Error).message })
  throw err
}

const actorOf = (request: FastifyRequest) => ({ ...auditActor(request), email: request.userContext?.email ?? '' })

async function person(id: string): Promise<{ email: string } | null> {
  const identity = await kratosService.getIdentity(id).catch(() => null)
  if (!identity) return null
  return { email: String((identity.traits as { email?: unknown } | undefined)?.email ?? '') }
}

const noPerson = (reply: FastifyReply, id: string) => reply.status(404).send({ error: 'Not Found', message: `No user '${id}'` })
const noMember = (reply: FastifyReply, id: string, org: string) => reply.status(404).send({ error: 'Not Found', message: `No member '${id}' in organization '${org}'` })

/** Platform side, mounted under /api/admin. */
export async function adminDirectGrantsRoutes(fastify: FastifyInstance) {
  fastify.get('/users/:id/grants', {
    ...needs('users.grants:read'),
    schema: { description: "One person's direct grants (roles and permissions held without a group), in every scope, expired ones marked.", tags: ['admin'], params: idParams, response: { 200: personGrants, ...errors } },
  }, async (request, reply) => {
    const { id } = request.params as { id: string }
    const who = await person(id)
    if (!who) return noPerson(reply, id)
    return reply.send({ id, email: who.email, grants: (await directGrantsRepository.getFor(id)).map((g) => view(g)) })
  })

  fastify.put('/users/:id/grants', {
    ...needs('users.grants:write'),
    schema: {
      description:
        "Replace one person's direct grants, platform-wide and in any organisation. Each grant: scope (\"platform\" or an org id), app, " +
        'kind (role|permission), name, optional reason and expiresAt. Every grant added or changed, and every scope losing one, is ' +
        'decided by the policy (holding rule); a refusal changes nothing and lists each refused grant.',
      tags: ['admin'], params: idParams, body, response: { 200: personGrants, ...errors },
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string }
    const { grants } = grantsBodySchema.parse(request.body)
    const who = await person(id)
    if (!who) return noPerson(reply, id)
    try {
      const after = await directGrantsService.replace({ subjectId: id, granteeEmail: who.email, wanted: grants, actor: actorOf(request) })
      return reply.send({ id, email: who.email, grants: after.map((g) => view(g)) })
    } catch (err) {
      return answer(reply, err)
    }
  })

  fastify.delete('/users/:id/grants', {
    ...needs('users.grants:write'),
    schema: { description: "Take every direct grant of one person away (each scope decided by the policy).", tags: ['admin'], params: idParams, response: { 200: personGrants, ...errors } },
  }, async (request, reply) => {
    const { id } = request.params as { id: string }
    const who = await person(id)
    if (!who) return noPerson(reply, id)
    try {
      const after = await directGrantsService.replace({ subjectId: id, granteeEmail: who.email, wanted: [], actor: actorOf(request) })
      return reply.send({ id, email: who.email, grants: after.map((g) => view(g)) })
    } catch (err) {
      return answer(reply, err)
    }
  })

  fastify.delete('/users/:id/grants/:grantId', {
    ...needs('users.grants:write'),
    schema: { description: 'Take one direct grant away.', tags: ['admin'], params: grantIdParams, response: { 200: personGrants, ...errors } },
  }, async (request, reply) => {
    const { id, grantId } = request.params as { id: string; grantId: string }
    const who = await person(id)
    if (!who) return noPerson(reply, id)
    try {
      const gone = await directGrantsService.revoke({ subjectId: id, granteeEmail: who.email, grantId, actor: actorOf(request) })
      if (!gone) return reply.status(404).send({ error: 'Not Found', message: `No grant '${grantId}' for user '${id}'` })
      return reply.send({ id, email: who.email, grants: (await directGrantsRepository.getFor(id)).map((g) => view(g)) })
    } catch (err) {
      return answer(reply, err)
    }
  })

  fastify.get('/grants', {
    ...needs('users.grants:read'),
    schema: {
      description: 'Everyone holding direct grants, with each grant (who gave it, when, why, until when): the list a review or a recertification walks.',
      tags: ['admin'],
      response: { 200: { type: 'object', properties: { people: { type: 'array', items: personGrants } } }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 503: serviceUnavailableResponseSchema },
    },
  }, async (_request, reply) => reply.send({ people: await directGrantsService.everyone() }))
}

/** Org side, mounted under /api/organizations/:organizationId (and its /admin twin). */
export async function orgDirectGrantsRoutes(fastify: FastifyInstance) {
  fastify.get('/users/:id/grants', {
    ...needs('org.members:read', ORG),
    schema: { description: "One member's direct grants in this organization.", tags: ['organization-users'], params: organizationUserIdParamJsonSchema, response: { 200: personGrants, ...errors } },
  }, async (request, reply) => {
    const { organizationId, id } = request.params as { organizationId: string; id: string }
    const member = await memberOf(id, organizationId)
    if (!member) return noMember(reply, id, organizationId)
    const grants = (await directGrantsRepository.getFor(id)).filter((g) => g.scope === organizationId)
    return reply.send({ id, email: member.email, grants: grants.map((g) => view(g)) })
  })

  fastify.put('/users/:id/grants', {
    ...needs('org.members:write', ORG),
    schema: {
      description:
        "Replace one member's direct grants in this organization (scope must be this organization's id). Decided by the policy " +
        '(holding rule in this organization); a refusal changes nothing and lists each refused grant.',
      tags: ['organization-users'], params: organizationUserIdParamJsonSchema, body, response: { 200: personGrants, ...errors },
    },
  }, async (request, reply) => {
    const { organizationId, id } = request.params as { organizationId: string; id: string }
    const { grants } = grantsBodySchema.parse(request.body)
    const member = await memberOf(id, organizationId)
    if (!member) return noMember(reply, id, organizationId)
    try {
      const after = await directGrantsService.replace({
        subjectId: id, granteeEmail: member.email, wanted: grants, actor: actorOf(request), within: (scope) => scope === organizationId,
      })
      return reply.send({ id, email: member.email, grants: after.filter((g) => g.scope === organizationId).map((g) => view(g)) })
    } catch (err) {
      return answer(reply, err)
    }
  })

  fastify.delete('/users/:id/grants/:grantId', {
    ...needs('org.members:write', ORG),
    schema: { description: "Take one of a member's direct grants in this organization away.", tags: ['organization-users'], params: orgGrantIdParams, response: { 200: personGrants, ...errors } },
  }, async (request, reply) => {
    const { organizationId, id, grantId } = request.params as { organizationId: string; id: string; grantId: string }
    const member = await memberOf(id, organizationId)
    if (!member) return noMember(reply, id, organizationId)
    try {
      const gone = await directGrantsService.revoke({ subjectId: id, granteeEmail: member.email, grantId, actor: actorOf(request), within: (scope) => scope === organizationId })
      if (!gone) return reply.status(404).send({ error: 'Not Found', message: `No grant '${grantId}' for member '${id}' here` })
      const grants = (await directGrantsRepository.getFor(id)).filter((g) => g.scope === organizationId)
      return reply.send({ id, email: member.email, grants: grants.map((g) => view(g)) })
    } catch (err) {
      return answer(reply, err)
    }
  })
}
