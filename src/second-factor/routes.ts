import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { requireAdmin, requireRecentMfa, requireSuperAdmin } from '../middleware/require-admin.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { badRequestResponseSchema } from '../schemas/response-schemas.js'
import { secondFactorStatus } from './status.js'
import { DEFAULT_SECOND_FACTOR_GROUPS, GROUP_NAME, MAX_GROUPS, getSecondFactorGroups, setSecondFactorGroups } from './settings.js'

const groupsBody = {
  type: 'object',
  properties: {
    groups: { type: 'array', items: { type: 'string' } },
    defaultGroups: { type: 'array', items: { type: 'string' } },
  },
}

/**
 * GET /api/public/second-factor — the signed-in visitor's own 2FA status, for login-ui (status.ts).
 * No session gate (require-auth PUBLIC_ROUTES): it reads the visitor's own Kratos cookie itself and
 * answers about nobody else. Rate limited per IP.
 */
export async function secondFactorPublicRoutes(fastify: FastifyInstance) {
  fastify.get('/', {
    config: { rateLimit: { max: 120, timeWindow: '1 minute' } },
    schema: {
      description:
        'The signed-in visitor (own Kratos session cookie) must set up or prove a second factor before continuing? ' +
        '{secondFactorRequired, hasSecondFactor, methods, aal}; 401 without a session; 503 policy_unavailable | identity_unavailable.',
      tags: ['second-factor'],
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    reply.header('cache-control', 'private, no-store')
    try {
      return await secondFactorStatus(request.headers.cookie)
    } catch (err) {
      const e = err as { statusCode?: number; code?: string; message?: string }
      if (!e.statusCode) throw err
      return reply.status(e.statusCode).send({ error: e.code, message: e.message })
    }
  })
}

/**
 * The groups whose members must hold a second factor (settings.ts).
 *   GET /api/admin/settings/second-factor — admin
 *   PUT /api/admin/settings/second-factor — super_admin + a recent second factor: deciding who may
 *       sign in without one is itself a sign-in-security change.
 */
export async function secondFactorSettingsRoutes(fastify: FastifyInstance) {
  fastify.get('/second-factor', {
    preHandler: requireAdmin,
    schema: {
      description: 'Groups whose members must set up a second factor at sign-in and hold aal2 on every permission-carrying route.',
      tags: ['second-factor'],
      response: { 200: groupsBody },
    },
  }, async () => ({ groups: await getSecondFactorGroups(), defaultGroups: [...DEFAULT_SECOND_FACTOR_GROUPS] }))

  fastify.put('/second-factor', {
    preHandler: [requireSuperAdmin, requireRecentMfa],
    schema: {
      description:
        'Replace the groups whose members must use two-step sign-in. Every name must be an existing group; an empty list ' +
        'requires nobody. Published to OPA as data.second_factor. Requires super_admin + a second factor proven within 15 minutes.',
      tags: ['second-factor'],
      body: {
        type: 'object',
        required: ['groups'],
        additionalProperties: false,
        properties: { groups: { type: 'array', maxItems: MAX_GROUPS, items: { type: 'string', maxLength: 100 } } },
      },
      response: { 200: groupsBody, 400: badRequestResponseSchema },
    },
  }, async (request, reply) => {
    const { groups } = request.body as { groups: string[] }
    const malformed = groups.filter((g) => !GROUP_NAME.test(g))
    if (malformed.length) {
      return reply.status(400).send({ error: 'invalid_group', message: `Not a group name: ${malformed.join(', ')}` })
    }
    const known = await redisRbacRepository.getGroups()
    const unknown = groups.filter((g) => !(g in known))
    if (unknown.length) {
      return reply.status(400).send({ error: 'unknown_group', message: `No such group: ${unknown.join(', ')}` })
    }
    const before = await getSecondFactorGroups()
    const saved = await setSecondFactorGroups(groups)
    const a = auditActor(request)
    auditEventService.emit({
      category: 'rbac', kind: 'change', verb: 'update', target: 'second-factor-groups',
      result: 'applied', severity: 'high',
      actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { before, after: saved },
    }).catch(() => {})
    return { groups: saved, defaultGroups: [...DEFAULT_SECOND_FACTOR_GROUPS] }
  })
}
