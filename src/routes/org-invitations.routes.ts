import type { FastifyInstance, FastifyReply } from 'fastify'
import { z } from 'zod'
import { needs, open } from '../policy/route-access.js'
import { organizationIdParamJsonSchema } from '../schemas/organization-user.schema.js'
import { forbiddenResponseSchema, notFoundResponseSchema, serviceUnavailableResponseSchema, unauthorizedResponseSchema } from '../schemas/response-schemas.js'
import { kratosService } from '../services/kratos.service.js'
import { organisationsById } from '../services/organisation-store.js'
import { isMemberOf, joinOrganisation } from '../services/org-membership.service.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { orgRoleRefusals } from '../services/org-role-grants.js'
import { invitationLink, orgInvitations, viewOf, type Invitation } from '../services/org-invitations.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { orgRoleRefusedSchema } from './org-roles.routes.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'

/**
 * Invitations (services/org-invitations.ts): an org admin invites by address, the person accepts.
 *
 *   GET    /api/organizations/:organizationId/invitations                 org.members:read   pending ones
 *   POST   /api/organizations/:organizationId/invitations                 org.members:write  invite (roles: holding rule)
 *   DELETE /api/organizations/:organizationId/invitations/:invitationId   org.members:write  take one back
 *   GET    /api/me/invitations                    self   addressed to my verified address
 *   POST   /api/me/invitations/accept             self   by the link's token, or by id
 *   POST   /api/me/invitations/:invitationId/decline   self
 */

const ORG = { org: 'organizationId' } as const
const ROLE = /^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$/

const inviteBody = z.object({ email: z.string().trim().toLowerCase().email().max(254), roles: z.array(z.string().regex(ROLE)).max(32).default([]) }).strict()
const acceptBody = z.union([z.object({ token: z.string().min(16).max(128) }).strict(), z.object({ id: z.string().uuid() }).strict()])
const invitationParams = z.object({ organizationId: z.string().uuid(), invitationId: z.string().uuid() })
const selfParams = z.object({ invitationId: z.string().uuid() })

const invitationSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' }, org: { type: 'string' }, email: { type: 'string' },
    roles: { type: 'array', items: { type: 'string' } },
    invitedBy: { type: 'object', properties: { id: { type: 'string', nullable: true }, email: { type: 'string' } } },
    byPlatform: { type: 'boolean' },
    createdAt: { type: 'string' }, expiresAt: { type: 'string' },
    organizationName: { type: 'string', nullable: true },
  },
}
const errorSchema = { type: 'object', properties: { error: { type: 'string' }, code: { type: 'string' }, message: { type: 'string' } } }
const notFound = { ...notFoundResponseSchema, properties: { ...notFoundResponseSchema.properties, error: { type: 'string' } } }

const emailOf = (identity: KratosIdentity) => String((identity.traits as { email?: unknown } | undefined)?.email ?? '').trim().toLowerCase()
const verified = (identity: KratosIdentity, email: string) =>
  !!email && (identity.verifiable_addresses ?? []).some((a) => a.via === 'email' && a.value.trim().toLowerCase() === email && a.verified)

function unavailable(reply: FastifyReply, err: unknown) {
  if (!(err instanceof AuthzUnavailableError)) throw err
  return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `Unable to verify authorization: ${err.message}` })
}

function audit(type: string, actor: ReturnType<typeof auditActor>, invitation: Invitation, details: Record<string, unknown> = {}) {
  auditEventService.emit({
    type, actor, target: { type: 'organization', id: invitation.org },
    details: { invitationId: invitation.id, email: invitation.email, roles: invitation.roles, ...details }, source: 'jinbe-api',
  }).catch(() => {})
}

/** Under /api/organizations/:organizationId. */
export async function orgInvitationRoutes(fastify: FastifyInstance) {
  fastify.get('/invitations', {
    ...needs('org.members:read', ORG),
    schema: {
      description: "This organization's pending invitations (no token), newest first.",
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      response: { 200: { type: 'object', properties: { invitations: { type: 'array', items: invitationSchema } } }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    return reply.send({ invitations: (await orgInvitations.ofOrg(organizationId)).map(viewOf) })
  })

  fastify.post('/invitations', {
    ...needs('org.members:write', ORG),
    schema: {
      description:
        'Invite somebody into this organization by address, whether they have an account or not. They join only by accepting, ' +
        'signed in with that address verified (POST /api/me/invitations/accept). Org roles given on acceptance pass the holding ' +
        'rule now (and again then). The token — and `link` when INVITATION_URL is set — is returned ONCE: send it to them. ' +
        'A pending invitation of the same address here is replaced. 409 already_member.',
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      body: {
        type: 'object', required: ['email'], additionalProperties: false,
        properties: { email: { type: 'string', format: 'email', maxLength: 254 }, roles: { type: 'array', maxItems: 32, items: { type: 'string', pattern: ROLE.source } } },
      },
      response: {
        201: { type: 'object', properties: { invitation: invitationSchema, token: { type: 'string' }, link: { type: 'string', nullable: true } } },
        400: errorSchema, 401: unauthorizedResponseSchema, 403: orgRoleRefusedSchema, 404: notFound, 409: errorSchema, 503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    const parsed = inviteBody.safeParse(request.body)
    if (!parsed.success) return reply.status(400).send({ error: 'Bad Request', message: parsed.error.issues.map((i) => i.message).join('; ') })
    const { email, roles } = parsed.data
    const [org] = await organisationsById([organizationId])
    if (!org) return reply.status(404).send({ error: 'organisation_not_found', message: `No organisation ${organizationId} is held.` })
    const existing = await kratosService.findByEmail(email)
    if (existing && (await isMemberOf(existing, organizationId))) {
      return reply.status(409).send({ error: 'Conflict', code: 'already_member', message: 'This person is already a member of the organization.' })
    }
    const inviter = request.userContext?.email ?? ''
    let refused
    try {
      refused = await orgRoleRefusals(inviter, organizationId, roles, { email, joining: true })
    } catch (err) {
      return unavailable(reply, err)
    }
    if (refused.length > 0) return reply.status(403).send({ error: 'Forbidden', message: `Not allowed to assign: ${refused.map((r) => r.role).join(', ')}`, refused })

    const { invitation, token } = await orgInvitations.create({ org: organizationId, email, roles, invitedBy: { id: request.userContext?.id ?? null, email: inviter } })
    audit('organization.invitation_created', auditActor(request), invitation)
    return reply.status(201).send({ invitation: viewOf(invitation), token, link: invitationLink(token) })
  })

  fastify.delete('/invitations/:invitationId', {
    ...needs('org.members:write', ORG),
    schema: {
      description: 'Take back a pending invitation of this organization.',
      tags: ['organization-users'],
      params: { type: 'object', required: ['organizationId', 'invitationId'], properties: { organizationId: { type: 'string', format: 'uuid' }, invitationId: { type: 'string', format: 'uuid' } } },
      response: { 204: { type: 'null' }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound },
    },
  }, async (request, reply) => {
    const { organizationId, invitationId } = invitationParams.parse(request.params)
    const invitation = await orgInvitations.byId(invitationId)
    if (!invitation || invitation.org !== organizationId) return reply.status(404).send({ error: 'Not Found', message: 'No such pending invitation in this organization' })
    await orgInvitations.remove(invitationId)
    audit('organization.invitation_revoked', auditActor(request), invitation)
    return reply.status(204).send()
  })
}

/** Under /api/me. */
export async function selfInvitationRoutes(fastify: FastifyInstance) {
  /** The caller's identity and their address when it is verified; null otherwise. */
  const caller = async (id: string | undefined) => {
    if (!id || id === 'unknown') return null
    const identity = await kratosService.getIdentity(id)
    const email = emailOf(identity)
    return { identity, email, verified: verified(identity, email) }
  }

  fastify.get('/invitations', {
    ...open('self'),
    schema: {
      description: "Pending invitations addressed to the caller's verified address, with each organization's name. Empty while the address is not verified.",
      tags: ['me'],
      response: { 200: { type: 'object', properties: { invitations: { type: 'array', items: invitationSchema } } }, 401: errorSchema },
    },
  }, async (request, reply) => {
    const me = await caller(request.userContext?.id)
    if (!me) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const mine = me.verified ? await orgInvitations.forEmail(me.email) : []
    const names = new Map((await organisationsById([...new Set(mine.map((i) => i.org))]).catch(() => [])).map((o) => [o.id, o.name]))
    return reply.send({ invitations: mine.map((i) => ({ ...viewOf(i), organizationName: names.get(i.org) ?? null })) })
  })

  fastify.get('/invitations/by-token', {
    ...open('self'),
    schema: {
      description:
        "The invitation behind a link's token, for the page that offers Accept: its organization, roles and expiry, with " +
        'whether the caller may accept it now. 404 for an unknown, used or expired token; 403 invitation_other_address when it ' +
        "was made for another address. The caller's address need not be verified yet (`verified` says so).",
      tags: ['me'],
      querystring: { type: 'object', required: ['token'], properties: { token: { type: 'string', minLength: 16, maxLength: 128 } } },
      response: {
        200: { type: 'object', properties: { invitation: invitationSchema, verified: { type: 'boolean' } } },
        401: errorSchema, 403: errorSchema, 404: errorSchema,
      },
    },
  }, async (request, reply) => {
    const me = await caller(request.userContext?.id)
    if (!me) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const { token } = request.query as { token: string }
    const invitation = await orgInvitations.byToken(token)
    if (!invitation) return reply.status(404).send({ error: 'Not Found', code: 'invitation_not_found', message: 'This invitation does not exist, was taken back, or has expired' })
    // Only the invited address learns what the invitation holds: a forwarded link shows nothing.
    if (invitation.email !== me.email) return reply.status(403).send({ error: 'Forbidden', code: 'invitation_other_address', message: "This invitation is for another address: sign in with the address it was sent to" })
    const [org] = await organisationsById([invitation.org]).catch(() => [])
    return reply.send({ invitation: { ...viewOf(invitation), organizationName: org?.name ?? null }, verified: me.verified })
  })

  fastify.post('/invitations/accept', {
    ...open('self'),
    schema: {
      description:
        "Accept an invitation — by the link's `token`, or by `id` (from GET /api/me/invitations) — signed in with the invited " +
        'address verified: join the organization, with the org roles the inviter may still hand out (`dropped` names the others).',
      tags: ['me'],
      body: { type: 'object', additionalProperties: false, properties: { token: { type: 'string', minLength: 16, maxLength: 128 }, id: { type: 'string', format: 'uuid' } } },
      response: {
        200: { type: 'object', properties: { organization: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string', nullable: true } } }, roles: { type: 'array', items: { type: 'string' } }, dropped: { type: 'array', items: { type: 'string' } } } },
        400: errorSchema, 401: errorSchema, 403: errorSchema, 404: errorSchema, 503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    const parsed = acceptBody.safeParse(request.body)
    if (!parsed.success) return reply.status(400).send({ error: 'Bad Request', message: 'Send the invitation token, or its id' })
    const me = await caller(request.userContext?.id)
    if (!me) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const invitation = 'token' in parsed.data ? await orgInvitations.byToken(parsed.data.token) : await orgInvitations.byId(parsed.data.id)
    if (!invitation) return reply.status(404).send({ error: 'Not Found', code: 'invitation_not_found', message: 'This invitation does not exist, was taken back, or has expired' })
    // Consent: the invited address itself, proven. A link forwarded to somebody else opens nothing.
    if (invitation.email !== me.email) return reply.status(403).send({ error: 'Forbidden', code: 'invitation_other_address', message: "This invitation is for another address: sign in with the address it was sent to" })
    if (!me.verified) return reply.status(403).send({ error: 'Forbidden', code: 'email_not_verified', message: 'Verify your address first, then accept the invitation' })

    let refused
    try {
      refused = invitation.byPlatform ? [] : await orgRoleRefusals(invitation.invitedBy.email, invitation.org, invitation.roles, { email: me.email, joining: true })
    } catch (err) {
      return unavailable(reply, err)
    }
    const dropped = refused.map((r) => r.role)
    const roles = invitation.roles.filter((r) => !dropped.includes(r))
    await joinOrganisation(me.identity, invitation.org)
    if (roles.length > 0) {
      const held = await orgRolesRepository.getForMember(invitation.org, me.identity.id)
      await orgRolesRepository.setForMember(invitation.org, me.identity.id, [...held, ...roles])
    }
    await orgInvitations.remove(invitation.id)
    rbacService.notifyBindingsChanged('invitation_accepted', auditActor(request)).catch(() => {})
    audit('organization.invitation_accepted', auditActor(request), invitation, { roles, dropped, member: me.identity.id })
    const [org] = await organisationsById([invitation.org]).catch(() => [])
    return reply.send({ organization: { id: invitation.org, name: org?.name ?? null }, roles, dropped })
  })

  fastify.post('/invitations/:invitationId/decline', {
    ...open('self'),
    schema: {
      description: 'Decline an invitation addressed to the caller.',
      tags: ['me'],
      params: { type: 'object', required: ['invitationId'], properties: { invitationId: { type: 'string', format: 'uuid' } } },
      response: { 204: { type: 'null' }, 401: errorSchema, 404: errorSchema },
    },
  }, async (request, reply) => {
    const { invitationId } = selfParams.parse(request.params)
    const me = await caller(request.userContext?.id)
    if (!me) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const invitation = await orgInvitations.byId(invitationId)
    if (!invitation || invitation.email !== me.email) return reply.status(404).send({ error: 'Not Found', code: 'invitation_not_found', message: 'No such pending invitation for you' })
    await orgInvitations.remove(invitation.id)
    audit('organization.invitation_declined', auditActor(request), invitation)
    return reply.status(204).send()
  })
}
