import { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { needs } from '../policy/route-access.js'
import { auditEventService } from '../services/audit-event.service.js'
import {
  createOrganisation,
  deleteOrganisation,
  organisationStoreConfigured,
  organisationStoreNotConfigured,
  updateOrganisation,
} from '../services/organisation-store.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { directGrantsRepository } from '../services/direct-grants.repository.js'
import { joinOrganisation } from '../services/org-membership.service.js'
import { invitationLink, orgInvitations } from '../services/org-invitations.js'
import { OWNER } from '../services/org-owner-roles.js'
import { kratosService } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { signUpStore } from '../sites/signup/store.js'
import { sitesRepository } from '../sites/repository.js'
import { JINBE } from '../policy/roles.js'
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
  /** The owner's address: an account is named owner, an unknown address invited as owner. Never an id. */
  owner: z.string().trim().toLowerCase().email().max(254),
}).strict()

const updateBody = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    tenant: z.string().regex(TENANT).optional(),
  })
  .strict()
  .refine((b) => b.name !== undefined || b.tenant !== undefined, 'nothing to change')

const idParams = z.object({ id: z.string().uuid() })

/** `organisation_not_found` with the message: the shared 404 schema names only the message. */
const organisationNotFound = { ...notFoundResponseSchema, properties: { error: { type: 'string' }, ...notFoundResponseSchema.properties } }

const organisationResponse = {
  type: 'object',
  properties: {
    id: { type: 'string', format: 'uuid' },
    name: { type: 'string' },
    tenant: { type: 'string' },
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

/** Who owns a new organisation: an account named owner now, or an address invited as owner. */
async function seatOwner(organisationId: string, email: string, by: { id: string | null; email: string }) {
  const account = await kratosService.findByEmail(email)
  if (account) {
    await joinOrganisation(account, organisationId)
    await orgRolesRepository.setForMember(organisationId, account.id, [OWNER])
    return { owner: { email, id: account.id, status: 'owner' as const } }
  }
  const { invitation, token } = await orgInvitations.create({ org: organisationId, email, roles: [OWNER], invitedBy: by, byPlatform: true })
  return { owner: { email, id: null, status: 'invited' as const }, invitation: { id: invitation.id, token, link: invitationLink(token), expiresAt: invitation.expiresAt } }
}

/**
 * Organisation writes, mounted inside the admin plugin so they sit behind its guard as well.
 *
 * An organisation is made for its owner (super_admin and developer: orgs:write): a name and the
 * owner's address. An account with that address is named owner (jinbe:owner, and so each serving
 * site's owner role); an address with no account is invited as owner and owns it on accepting.
 */
export async function organisationAdminRoutes(fastify: FastifyInstance) {
  fastify.post(
    '/organizations',
    {
      ...needs('orgs:write'),
      schema: {
        description:
          "Create an organisation for its owner: a name and the owner's address (never an id). An account with that address " +
          'is named owner at once; an address with no account is invited as owner — the token (and `link` when INVITATION_URL ' +
          'is set) is returned ONCE, to send them. Needs orgs:write.',
        tags: ['admin'],
        body: {
          type: 'object',
          required: ['name', 'owner'],
          properties: {
            name: { type: 'string', minLength: 1, maxLength: 200 },
            tenant: {
              type: 'string',
              pattern: TENANT.source,
              description: 'Namespace-shaped label; derived from the name when omitted.',
            },
            owner: { type: 'string', format: 'email', maxLength: 254, description: "The owner's address" },
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
              sites: { type: 'array', items: { type: 'string' } },
              owner: { type: 'object', properties: { email: { type: 'string' }, id: { type: 'string', nullable: true }, status: { type: 'string', enum: ['owner', 'invited'] } } },
              invitation: { type: 'object', properties: { id: { type: 'string' }, token: { type: 'string' }, link: { type: 'string', nullable: true }, expiresAt: { type: 'string' } } },
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
      const { name, owner } = parsed.data
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
      let seated
      try {
        created = await createOrganisation({ name, tenant })
        // An org is entitled to jinbe from birth: without it in org_sites the policy refuses its org routes.
        await redisRbacRepository.setOrgSites(created.id, [JINBE])
        seated = await seatOwner(created.id, owner, { id: request.userContext?.id ?? null, email: request.userContext?.email ?? '' })
      } catch (err) {
        request.log.error({ err }, 'The organisation could not be created')
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'The organisation directory could not be written.',
        })
      }
      rbacService.notifyBindingsChanged('organization_created', auditActor(request)).catch(() => {})

      auditEventService
        .emit({
          type: 'organization.created',
          actor: auditActor(request),
          target: { type: 'organization', id: created.id },
          details: { name, tenant, owner, ownerStatus: seated.owner.status },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(201).send({ id: created.id, name, tenant, sites: [JINBE], ...seated })
    },
  )

  // Rename or re-tenant an organisation. Only what is sent changes.
  fastify.patch(
    '/organizations/:id',
    {
      ...needs('orgs:write'),
      schema: {
        description: 'Change an organisation: its name and/or tenant. Needs orgs:write.',
        tags: ['admin'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } },
        body: {
          type: 'object',
          properties: {
            name: { type: 'string', minLength: 1, maxLength: 200 },
            tenant: { type: 'string', pattern: TENANT.source },
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
      // Not-found and outages are answered by the error handler (404 organisation_not_found, 503).
      const updated = await updateOrganisation(id, parsed.data)

      auditEventService
        .emit({
          type: 'organization.updated',
          actor: auditActor(request),
          target: { type: 'organization', id },
          details: parsed.data,
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.send({ id, name: updated.name, tenant: updated.tenant })
    },
  )

  // Delete an organisation nobody belongs to. With members left it refuses (409) and says how many:
  // their memberships would otherwise point at nothing.
  fastify.delete(
    '/organizations/:id',
    {
      ...needs('orgs:delete'),
      schema: {
        description:
          'Delete an organisation that has no members left, with everything kept about it: its sites (org_sites and the ' +
          'sign-up entitlements), its domains, org roles, direct grants and pending invitations. Site intents still naming it ' +
          'are listed in the audit event and refused at their next preview and publish (unknown_org). Needs orgs:delete and a recent second factor.',
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
      const { id } = params.data

      await deleteOrganisation(id)
      // Nothing of the org stays: its entitlements (the sign-up ones too) and domains, its org role
      // assignments, its direct grants, its invitations.
      await redisRbacRepository.setOrgSites(id, [])
      await signUpStore.forgetOrg(id)
      await orgRolesRepository.forgetOrg(id)
      for (const [subject, held] of Object.entries(await directGrantsRepository.getAll())) {
        if (held.some((g) => g.scope === id)) await directGrantsRepository.forgetOrg(subject, id)
      }
      await orgInvitations.forgetOrg(id)
      rbacService.notifyBindingsChanged('organization_deleted', auditActor(request)).catch(() => {})
      const sitesNamingIt = (await sitesRepository.list().catch(() => []))
        .filter((r) => r.site.orgs.includes(id))
        .map((r) => r.site.name)
        .sort()
      if (sitesNamingIt.length) request.log.warn({ organizationId: id, sites: sitesNamingIt }, 'Deleted an organisation that site intents still name')

      auditEventService
        .emit({
          type: 'organization.deleted',
          actor: auditActor(request),
          target: { type: 'organization', id },
          details: { sitesNamingIt },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(204).send()
    },
  )
}
