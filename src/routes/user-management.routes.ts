import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { adminController } from '../controllers/admin.controller.js'
import { rights, secondFactorRequired } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { requireRecentMfa } from '../middleware/require-admin.js'
import { callerRights, demandPermissions, requirePermission } from '../middleware/require-permission.js'
import { enforcing } from '../policy/declared-routes.js'
import { auditEventService } from '../services/audit-event.service.js'
import { KratosApiError, kratosService, MFA_METHODS, type MfaMethod } from '../services/kratos.service.js'
import {
  acceptableReturnTo,
  LoginLinkNoAddressError,
  LoginLinkRateLimitedError,
  LoginLinkReturnToRefusedError,
  LoginLinkUnavailableError,
  sendLoginLink,
} from '../services/login-link.service.js'
import {
  NoSecondFactorError,
  resetSecondFactors,
  SecondFactorResetError,
  secondFactorsOf,
} from '../services/second-factor-reset.service.js'
import { lookupUsers, LOOKUP_MAX } from '../services/user-lookup.service.js'
import { allows, requiredForEdit, type CheckedPermission, type EditableIdentity } from '../services/user-permissions.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  userIdParamSchema,
  usersQuerySchema,
  kratosIdentityJsonSchema,
  kratosIdentityListJsonSchema,
  userCreateJsonSchema,
  userUpdateJsonSchema,
} from '../schemas/admin.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * Managing users, one permission per action — so a support desk can fix somebody's address, see and
 * end their sessions and send them a way back in, without administering anything else.
 *
 * NOT behind the admin plugin's `admin:read` gate: the support role does not hold it. Each route
 * enforces its own permission here, in the app layer, because the gateway is not the only way in
 * (NetworkPolicy is not enforced). Administrators pass every check through the coarse permission
 * each fine one refines (see `USER_PERMISSIONS`).
 */
export async function userManagementRoutes(fastify: FastifyInstance) {
  const idParams = zodToJsonSchema(userIdParamSchema)
  const errors = { 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema }

  fastify.get('/users', {
    preHandler: requirePermission('users:read'),
    schema: {
      description: 'List all users from Kratos identity service. Needs users:read.',
      tags: ['admin'],
      querystring: zodToJsonSchema(usersQuerySchema),
      response: {
        200: {
          type: 'object',
          properties: { data: kratosIdentityListJsonSchema, next_page_token: { type: 'string', nullable: true } },
        },
        ...errors,
      },
    },
  }, adminController.listUsers.bind(adminController) as never)

  // Declared before /users/:id; Fastify's router prefers the static segment.
  fastify.get('/users/search', {
    preHandler: requirePermission('users:read'),
    schema: {
      description: 'Search identities by email or name substring (cached; no directory walk). Needs users:read.',
      tags: ['admin'],
      querystring: { type: 'object', properties: { q: { type: 'string' }, limit: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { data: { type: 'array', items: { type: 'object', additionalProperties: true } } } },
        ...errors,
      },
    },
  }, adminController.searchUsers.bind(adminController) as never)

  // Quick find: as-you-type from the checker and the people screen. Each keystroke is at most one
  // bounded Kratos query (see lookupUsers), and the limit is per caller so one open tab cannot
  // starve the others.
  fastify.get<{ Querystring: { q: string; limit?: number } }>('/users/lookup', {
    preHandler: requirePermission('users:read'),
    config: { rateLimit: { max: 120, timeWindow: '1 minute', keyGenerator: (r: FastifyRequest) => r.userContext?.id ?? r.ip } },
    schema: {
      description:
        'Find a person by Kratos identity id (exact), whole email (exact) or the start of an email; falls back to a ' +
        'substring match over email and name when no address starts with it. At most 10 hits, each with groups, ' +
        'organisations and 2FA (null = could not be read). Needs users:read.',
      tags: ['admin'],
      querystring: {
        type: 'object',
        required: ['q'],
        properties: { q: { type: 'string', minLength: 1, maxLength: 320 }, limit: { type: 'integer', minimum: 1, maximum: LOOKUP_MAX } },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            match: { type: 'string', enum: ['id', 'email', 'prefix', 'contains', 'none'] },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  email: { type: 'string' },
                  name: { type: ['string', 'null'] },
                  active: { type: 'boolean' },
                  groups: { type: ['array', 'null'], items: { type: 'string' } },
                  organizations: { type: ['array', 'null'], items: { type: 'string' } },
                  mfa: { type: ['boolean', 'null'] },
                },
              },
            },
          },
        },
        ...errors,
      },
    },
  }, async (request, reply) => {
    return reply.send(await lookupUsers(request.query.q, request.query.limit))
  })

  fastify.get('/users/:id', {
    preHandler: requirePermission('users:read'),
    schema: {
      description: 'Get user by ID from Kratos identity service. Needs users:read.',
      tags: ['admin'],
      params: idParams,
      response: { 200: kratosIdentityJsonSchema, ...errors },
    },
  }, adminController.getUser.bind(adminController) as never)

  fastify.post('/users', {
    preHandler: enforcing(requireCreatePermissions, 'users:create'),
    schema: {
      description:
        'Create new user in Kratos identity service. Needs users:create; users:assign_group to give groups; users:recovery to send an invite.',
      tags: ['admin'],
      body: {
        oneOf: [
          // Simplified flat format from kuma UI
          {
            type: 'object',
            required: ['email'],
            properties: {
              email: { type: 'string', format: 'email' },
              name: { type: 'string' },
              groups: { type: 'array', items: { type: 'string' } },
              sendInvite: { type: 'boolean' },
            },
            additionalProperties: false,
          },
          // Full Kratos format
          userCreateJsonSchema,
        ],
      },
      response: { 201: kratosIdentityJsonSchema, ...errors },
    },
  }, adminController.createUser.bind(adminController) as never)

  fastify.put('/users/:id', {
    preHandler: enforcing(requireEditPermissions, 'users:update'),
    schema: {
      description:
        'Update a user. Needs users:update for the name, users:update_email for the address, admin:write for anything outside the traits.',
      tags: ['admin'],
      params: idParams,
      body: userUpdateJsonSchema,
      response: { 200: kratosIdentityJsonSchema, ...errors },
    },
  }, adminController.updateUser.bind(adminController))

  fastify.delete('/users/:id', {
    preHandler: requirePermission('users:delete'),
    schema: {
      description: 'Delete user by ID from Kratos identity service. Needs users:delete.',
      tags: ['admin'],
      params: idParams,
      response: { 204: { type: 'null', description: 'User deleted successfully' }, ...errors },
    },
  }, adminController.deleteUser.bind(adminController) as never)

  fastify.post('/users/:id/recovery-email', {
    preHandler: requirePermission('users:recovery'),
    schema: {
      description: 'Send a recovery email to the user. Triggers Kratos self-service recovery flow. Needs users:recovery.',
      tags: ['admin'],
      params: idParams,
      response: { 204: { type: 'null', description: 'Recovery email sent' }, ...errors },
    },
  }, adminController.sendRecoveryEmail.bind(adminController) as never)

  fastify.post('/users/:id/login-link', {
    preHandler: requirePermission('users:send_login_link'),
    schema: {
      description:
        'Email the user a one-click sign-in link (Kratos recovery link, sent by Kratos). The link is never returned. Needs users:send_login_link.',
      tags: ['admin'],
      params: idParams,
      body: {
        type: ['object', 'null'],
        properties: { return_to: { type: 'string', maxLength: 2048 } },
        additionalProperties: false,
      },
      response: {
        200: {
          type: 'object',
          properties: { sent: { type: 'boolean' }, expiresAt: { type: 'string', nullable: true } },
          additionalProperties: false,
        },
        ...errors,
      },
    },
  }, sendLoginLinkHandler as never)

  fastify.get('/users/:id/second-factors', {
    preHandler: requirePermission('users:read'),
    schema: {
      description:
        'The second factors the user has enrolled (passkeys are first factors and not listed), and whether their role ' +
        'requires two-step sign-in (null when the policy cannot say). Needs users:read.',
      tags: ['admin'],
      params: idParams,
      response: {
        200: {
          type: 'object',
          properties: {
            methods: { type: 'array', items: { type: 'string', enum: [...MFA_METHODS] } },
            required: { type: 'boolean', nullable: true },
          },
          additionalProperties: false,
        },
        ...errors,
      },
    },
  }, secondFactorsHandler as never)

  fastify.post('/users/:id/second-factors/reset', {
    preHandler: [requirePermission('users:reset_second_factor'), requireRecentMfa],
    schema: {
      description:
        'Remove the user\'s second factors (authenticator app, security keys, backup codes; passkeys stay) for somebody ' +
        'who lost them, and by default end their sessions. Never your own. Needs users:reset_second_factor and a second ' +
        'factor of your own proven within 15 minutes; refused when the user holds rights you do not.',
      tags: ['admin'],
      params: idParams,
      body: {
        type: 'object',
        required: ['reason'],
        properties: {
          reason: { type: 'string', minLength: 1, maxLength: 500 },
          revokeSessions: { type: 'boolean', default: true },
        },
        additionalProperties: false,
      },
      response: {
        200: {
          type: 'object',
          properties: {
            removed: { type: 'array', items: { type: 'string', enum: [...MFA_METHODS] } },
            sessionsRevoked: { type: 'boolean' },
          },
          additionalProperties: false,
        },
        ...errors,
      },
    },
  }, resetSecondFactorsHandler as never)

  // Proxied from Kratos admin — never exposed directly to the browser.
  fastify.get('/users/:id/sessions', {
    preHandler: requirePermission('sessions:read'),
    schema: {
      description: 'List active sessions for a Kratos identity. Needs sessions:read.',
      tags: ['admin'],
      params: idParams,
      response: { 200: { type: 'array', items: { type: 'object', additionalProperties: true } }, ...errors },
    },
  }, adminController.listUserSessions.bind(adminController) as never)

  fastify.delete('/sessions/:sessionId', {
    preHandler: requirePermission('sessions:revoke'),
    schema: {
      description: 'Revoke a session by ID. Needs sessions:revoke.',
      tags: ['admin'],
      params: { type: 'object', properties: { sessionId: { type: 'string' } }, required: ['sessionId'] },
      response: { 204: { type: 'null' }, ...errors },
    },
  }, adminController.revokeSession.bind(adminController) as never)

  fastify.delete('/users/:id/sessions', {
    preHandler: requirePermission('sessions:revoke'),
    schema: {
      description: 'Revoke all sessions for a Kratos identity. Needs sessions:revoke.',
      tags: ['admin'],
      params: idParams,
      response: { 204: { type: 'null' }, ...errors },
    },
  }, adminController.revokeAllUserSessions.bind(adminController) as never)
}

/** Creating needs `users:create`; handing out a group or sending an invite on the way needs theirs. */
async function requireCreatePermissions(request: FastifyRequest, reply: FastifyReply) {
  const body = (request.body ?? {}) as Record<string, unknown>
  const meta = (body.metadata_admin ?? {}) as Record<string, unknown>
  const groups = (Array.isArray(body.groups) ? body.groups : Array.isArray(meta.groups) ? meta.groups : []) as string[]
  const required: CheckedPermission[] = ['users:create']
  // Base `users` confers nothing — the same exemption the grant gate in the handler makes.
  if (groups.some((g) => g !== 'users')) required.push('users:assign_group')
  if (body.sendInvite === true) required.push('users:recovery')
  if (!(await demandPermissions(request, reply, required))) return reply
}

/** An edit needs what it changes: the name, the address, or (outside the traits) administration. */
async function requireEditPermissions(request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) {
  // Decide on the caller first: somebody who may edit nothing learns nothing about the user.
  const rights = await callerRights(request, reply)
  if (!rights) return reply
  if (!allows(rights.permissions, 'users:update') && !allows(rights.permissions, 'users:update_email')) {
    await demandPermissions(request, reply, ['users:update'])
    return reply
  }
  const current = await kratosService.getIdentity(request.params.id)
  const required = requiredForEdit(current as EditableIdentity, (request.body ?? {}) as EditableIdentity)
  if (!(await demandPermissions(request, reply, required))) return reply
}

async function sendLoginLinkHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { return_to?: string } | null }>,
  reply: FastifyReply,
) {
  const { id } = request.params
  const returnTo = request.body?.return_to
  if (returnTo !== undefined && !acceptableReturnTo(returnTo)) {
    return reply.status(400).send({ error: 'Bad Request', message: 'return_to must be an absolute http(s) URL.' })
  }

  let expiresAt: string | null
  try {
    ;({ expiresAt } = await sendLoginLink(id, returnTo))
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) {
      return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
    }
    if (err instanceof LoginLinkRateLimitedError) {
      return reply.status(429).header('Retry-After', String(err.retryAfterSeconds)).send({
        error: 'Too Many Requests',
        message: 'Too many sign-in links were sent to this user recently. Try again later.',
      })
    }
    if (err instanceof LoginLinkReturnToRefusedError) {
      return reply.status(400).send({ error: 'Bad Request', message: 'return_to is not an allowed return address.' })
    }
    if (err instanceof LoginLinkNoAddressError) {
      return reply.status(422).send({ error: 'Unprocessable Entity', message: 'This user has no email address.' })
    }
    if (err instanceof LoginLinkUnavailableError) {
      request.log.warn({ err: err.message }, '[login-link] Kratos does not offer recovery by link')
      return reply.status(409).send({ error: 'login_link_unavailable', message: err.message })
    }
    throw err
  }

  // Who sent it and to whom — by identity only. The address stays out of the trail.
  auditEventService.emit({
    category: 'auth',
    kind: 'change',
    verb: 'login_link',
    target: `user:${id}`,
    targetType: 'user',
    targetId: id,
    result: 'applied',
    actor: {
      id: request.userContext?.id ?? null,
      email: null,
      ip: request.ip ?? null,
      ua: (request.headers['user-agent'] as string) || null,
      sessionId: request.userContext?.sessionId ?? null,
    },
    requestId: (request.headers['x-request-id'] as string) || null,
    source: 'jinbe-api',
    v1Event: 'user.login_link_sent',
  }).catch(() => {})

  return reply.send({ sent: true, expiresAt })
}

async function secondFactorsHandler(request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) {
  let found: Awaited<ReturnType<typeof secondFactorsOf>>
  try {
    found = await secondFactorsOf(request.params.id)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) {
      return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
    }
    throw err
  }
  // Only to phrase the console's warning; the gate that enforces it is elsewhere.
  const required = found.email ? await secondFactorRequired(found.email).catch(() => null) : false
  return reply.send({ methods: found.methods, required })
}

/**
 * The guard the route table cannot express: this is about WHO the target is.
 *   - never yourself: removing your own factor is the settings page's job, where Kratos asks for
 *     the factor first — this path would let a stolen session strip the account's last defence;
 *   - never somebody holding an administrative right you do not: with the address editable and a
 *     sign-in link one click away, removing a stronger account's factor is taking the account over.
 *     Administrative = the wildcard, the admin tree, user and session management, applying sites.
 *     Everyday site permissions are left out: an administrator can hand those out anyway.
 */
const ADMINISTRATIVE = /^(\*$|admin[.:]|users:|sessions:|sites:)/

async function resetSecondFactorsHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { reason: string; revokeSessions?: boolean } }>,
  reply: FastifyReply,
) {
  const { id } = request.params
  const reason = request.body.reason.trim()
  if (!reason) return reply.status(400).send({ error: 'Bad Request', message: 'Say why the factors are being removed.' })
  if (id === request.userContext?.id) {
    return reply.status(403).send({
      error: 'own_second_factor',
      message: 'You cannot remove your own two-step sign-in here. Use your account settings.',
    })
  }

  let found: Awaited<ReturnType<typeof secondFactorsOf>>
  try {
    found = await secondFactorsOf(id)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) {
      return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
    }
    throw err
  }

  if (found.email) {
    let theirs: string[]
    try {
      theirs = (await rights(found.email)).permissions
    } catch {
      return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify the user\'s rights. Please try again later.' })
    }
    const mine = request.rbacInfo?.permissions ?? []
    const beyond = theirs.filter((p) => ADMINISTRATIVE.test(p) && !allows(mine, p as CheckedPermission))
    if (beyond.length) {
      return reply.status(403).send({
        error: 'outranked',
        message: 'This user holds administrative rights you do not. Only somebody holding them can remove their two-step sign-in.',
      })
    }
  }

  const a = auditActor(request)
  const trail = (result: 'applied' | 'failed', factors: MfaMethod[], sessionsRevoked: boolean) =>
    auditEventService.emit({
      category: 'auth',
      kind: 'security',
      verb: 'mfa_reset',
      target: `user:${id}`,
      targetType: 'user',
      targetId: id,
      result,
      severity: 'high',
      reason,
      actor: { id: a.id, email: a.email, name: a.name, ip: a.ip, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      source: 'jinbe-api',
      v1Event: 'user.second_factor_reset',
      details: { reason, factors, sessionsRevoked },
    }).catch(() => {})

  let outcome: { removed: MfaMethod[]; sessionsRevoked: boolean }
  try {
    outcome = await resetSecondFactors(id, found.methods, { revokeSessions: request.body.revokeSessions ?? true })
  } catch (err) {
    if (err instanceof NoSecondFactorError) {
      return reply.status(409).send({ error: 'no_second_factor', message: 'This user has no two-step sign-in to remove.' })
    }
    if (err instanceof SecondFactorResetError) {
      trail('failed', err.removed, false)
      request.log.error({ err: (err.cause as Error)?.message, removed: err.removed }, '[second-factor-reset] stopped part-way')
      return reply.status(502).send({ error: 'reset_incomplete', message: err.message, removed: err.removed })
    }
    throw err
  }

  trail('applied', outcome.removed, outcome.sessionsRevoked)
  return reply.send(outcome)
}
