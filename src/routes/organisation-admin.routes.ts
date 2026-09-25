import { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requirePlatformPermission } from '../middleware/require-platform-permission.js'
import { auditEventService } from '../services/audit-event.service.js'
import { createOrganisation, organisationStoreConfigured } from '../services/organisation-store.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/** A tenant is a namespace-shaped label: lowercase, digits and inner dashes, at most 63. */
const TENANT = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

const createBody = z.object({
  name: z.string().trim().min(1).max(200),
  tenant: z.string().regex(TENANT).optional(),
})

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
      preHandler: requirePlatformPermission('admin.organisation:write'),
      schema: {
        description:
          'Create an organisation from a name. No service bundle is required. Needs admin.organisation:write.',
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
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'No organisation directory is configured.',
        })
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
}
