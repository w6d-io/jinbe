import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { adminController } from '../controllers/admin.controller.js'
import { callerRights, demandPermissions, requirePermission } from '../middleware/require-permission.js'
import { enforcing } from '../policy/declared-routes.js'
import { auditEventService } from '../services/audit-event.service.js'
import { KratosApiError, kratosService } from '../services/kratos.service.js'
import {
  acceptableReturnTo,
  LoginLinkNoAddressError,
  LoginLinkRateLimitedError,
  LoginLinkReturnToRefusedError,
  LoginLinkUnavailableError,
  sendLoginLink,
} from '../services/login-link.service.js'
import { allows, requiredForEdit, type CheckedPermission, type EditableIdentity } from '../services/user-permissions.js'
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
