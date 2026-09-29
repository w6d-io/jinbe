import { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { needs } from '../policy/route-access.js'
import { auditEventService } from '../services/audit-event.service.js'
import {
  createOrganisation,
  deleteOrganisation,
  deploymentsOf,
  organisationStoreConfigured,
  organisationStoreNotConfigured,
  setDeployments,
  updateOrganisation,
} from '../services/organisation-store.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  badRequestResponseSchema,
  conflictResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/** A tenant is a namespace-shaped label: lowercase, digits and inner dashes, at most 63. */
const TENANT = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

const createBody = z.object({
  name: z.string().trim().min(1).max(200),
  tenant: z.string().regex(TENANT).optional(),
})

const APPLICATION = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

const updateBody = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    tenant: z.string().regex(TENANT).optional(),
    /** The applications this organisation has, as a whole set: absent ones are turned off. */
    applications: z.array(z.string().regex(APPLICATION)).max(200).optional(),
  })
  .strict()
  .refine((b) => b.name !== undefined || b.tenant !== undefined || b.applications !== undefined, 'nothing to change')

const idParams = z.object({ id: z.string().uuid() })

/** `organisation_not_found` with the message: the shared 404 schema names only the message. */
const organisationNotFound = { ...notFoundResponseSchema, properties: { error: { type: 'string' }, ...notFoundResponseSchema.properties } }

const organisationResponse = {
  type: 'object',
  properties: {
    id: { type: 'string', format: 'uuid' },
    name: { type: 'string' },
    tenant: { type: 'string' },
    applications: { type: 'array', items: { type: 'string' } },
  },
}

/** `Acme Corp` → `acme-corp`. Empty when the name has nothing a namespace can carry. */
function tenantFrom(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/, '')
}

/**
 * Organisation writes, mounted inside the admin plugin so they sit behind its guard as well.
 *
 * Creating an organisation takes a name and nothing else. What this replaced tied an organisation to
 * a bundle of services at birth, because membership used to decide site access through that bundle;
 * it no longer does, so there is nothing an organisation must be born with.
 */
export async function organisationAdminRoutes(fastify: FastifyInstance) {
  fastify.post(
    '/organizations',
    {
      ...needs('org:write'),
      schema: {
        description:
          'Create an organisation from a name. No service bundle is required. Needs org:write.',
        tags: ['admin'],
        body: {
          type: 'object',
          required: ['name'],
          properties: {
            name: { type: 'string', minLength: 1, maxLength: 200 },
            tenant: {
              type: 'string',
              pattern: TENANT.source,
              description: 'Namespace-shaped label; derived from the name when omitted.',
            },
          },
          additionalProperties: false,
        },
        response: {
          201: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              name: { type: 'string' },
              tenant: { type: 'string' },
              applications: { type: 'array', items: { type: 'string' } },
            },
          },
          400: badRequestResponseSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const parsed = createBody.safeParse(request.body)
      if (!parsed.success) {
        return reply.status(400).send({ error: 'Bad Request', message: parsed.error.issues[0]?.message })
      }
      const { name } = parsed.data
      const tenant = parsed.data.tenant ?? tenantFrom(name)
      if (!tenant) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'A tenant cannot be derived from this name; give one explicitly.',
        })
      }

      if (!organisationStoreConfigured()) {
        return reply.status(503).send(organisationStoreNotConfigured())
      }

      let created
      try {
        created = await createOrganisation({ name, tenant })
      } catch (err) {
        request.log.error({ err }, 'The organisation could not be created')
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'The organisation directory could not be written.',
        })
      }

      auditEventService
        .emit({
          type: 'organization.created',
          actor: auditActor(request),
          target: { type: 'organization', id: created.id },
          details: { name, tenant },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(201).send({ id: created.id, name, tenant, applications: [] })
    },
  )

  // Rename, re-tenant, or set which applications an organisation has. Only what is sent changes.
  fastify.patch(
    '/organizations/:id',
    {
      ...needs('org:write'),
      schema: {
        description:
          'Change an organisation: name, tenant, and/or the whole set of applications it has. Needs org:write.',
        tags: ['admin'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } },
        body: {
          type: 'object',
          properties: {
            name: { type: 'string', minLength: 1, maxLength: 200 },
            tenant: { type: 'string', pattern: TENANT.source },
            applications: { type: 'array', items: { type: 'string', pattern: APPLICATION.source }, maxItems: 200 },
          },
          additionalProperties: false,
        },
        response: {
          200: organisationResponse,
          400: badRequestResponseSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: organisationNotFound,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const params = idParams.safeParse(request.params)
      const parsed = updateBody.safeParse(request.body)
      if (!params.success || !parsed.success) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: (parsed.success ? params.error!.issues : parsed.error.issues).map((i) => i.message).join('; '),
        })
      }
      if (!organisationStoreConfigured()) return reply.status(503).send(organisationStoreNotConfigured())

      const { id } = params.data
      const { applications, ...change } = parsed.data
      // Not-found and outages are answered by the error handler (404 organisation_not_found, 503).
      const updated = await updateOrganisation(id, change)
      if (applications) {
        await setDeployments(id, [...new Set(applications)].map((application) => ({ application, enabled: true })))
      }
      const enabled = (await deploymentsOf(id)).filter((d) => d.enabled).map((d) => d.application)

      auditEventService
        .emit({
          type: 'organization.updated',
          actor: auditActor(request),
          target: { type: 'organization', id },
          details: { ...change, ...(applications ? { applications } : {}) },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.send({ id, name: updated.name, tenant: updated.tenant, applications: enabled })
    },
  )

  // Delete an organisation nobody belongs to. With members left it refuses (409) and says how many:
  // their memberships would otherwise point at nothing.
  fastify.delete(
    '/organizations/:id',
    {
      ...needs('org:delete'),
      schema: {
        description: 'Delete an organisation that has no members left. Needs org:delete and a recent second factor.',
        tags: ['admin'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } },
        response: {
          204: { type: 'null' },
          400: badRequestResponseSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: organisationNotFound,
          409: { ...conflictResponseSchema, properties: { ...conflictResponseSchema.properties, members: { type: 'integer' } } },
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const params = idParams.safeParse(request.params)
      if (!params.success) return reply.status(400).send({ error: 'Bad Request', message: 'id: must be a UUID' })
      if (!organisationStoreConfigured()) return reply.status(503).send(organisationStoreNotConfigured())

      await deleteOrganisation(params.data.id)

      auditEventService
        .emit({
          type: 'organization.deleted',
          actor: auditActor(request),
          target: { type: 'organization', id: params.data.id },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(204).send()
    },
  )
}
