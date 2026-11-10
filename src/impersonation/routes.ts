import type { FastifyInstance, FastifyReply, FastifyRequest, HTTPMethods } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { env } from '../config/env.js'
import { rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { denyAudit } from '../audit/deny.js'
import { devRights } from '../middleware/require-admin.js'
import { needs, open } from '../policy/route-access.js'
import { userIdParamSchema } from '../schemas/admin.schema.js'
import { forbiddenResponseSchema, unauthorizedResponseSchema } from '../schemas/response-schemas.js'
import { KratosApiError, kratosService } from '../services/kratos.service.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { auditActor } from '../utils/audit-actor.js'
import { checkImpersonation } from './check.js'
import {
  IMPERSONATE,
  MIN_MINUTES,
  activeView,
  clearedImpersonationCookie,
  emailOf,
  impersonationAudit,
  impersonationCookie,
  impersonationEnabled,
  nameOf,
  targetProblem,
} from './service.js'
import { impersonationStore } from './store.js'

/** The console's routes and the gateway's check (service.ts says what impersonation is). */

const REASON_MIN = 5
const REASON_MAX = 500

const activeSchema = {
  type: 'object',
  properties: {
    target: {
      type: 'object',
      properties: { id: { type: 'string' }, email: { type: 'string' }, name: { type: 'string' } },
      required: ['id', 'email', 'name'],
      additionalProperties: false,
    },
    reason: { type: 'string' },
    startedAt: { type: 'string', format: 'date-time' },
    expiresAt: { type: 'string', format: 'date-time' },
    mode: { type: 'string', enum: ['read'] },
  },
  required: ['target', 'reason', 'startedAt', 'expiresAt', 'mode'],
  additionalProperties: false,
} as const

const refusalSchema = {
  type: 'object',
  properties: { error: { type: 'string' }, code: { type: 'string', example: 'impersonation_disabled' }, message: { type: 'string' } },
} as const

const MESSAGES = {
  impersonation_disabled: 'Impersonation is not enabled on this platform.',
  impersonation_session_required: 'Impersonation starts from a browser session in the console; this credential cannot start one.',
  impersonation_self: 'You cannot impersonate yourself.',
  impersonation_target_admin: 'Super administrators cannot be impersonated.',
  impersonation_target_unavailable: 'This identity cannot be impersonated: it is unknown, inactive, or not a person.',
} as const

type RefusalCode = keyof typeof MESSAGES

function refuse(request: FastifyRequest, reply: FastifyReply, code: RefusalCode) {
  const status = code === 'impersonation_disabled' ? 404 : 403
  if (status === 403) denyAudit(request, code, { statusCode: 403, severity: 'warn' })
  return reply.status(status).send({ error: status === 404 ? 'Not Found' : 'Forbidden', code, message: MESSAGES[code] })
}

/**
 * Before the permission and the step-up: a platform without impersonation answers 404 whoever asks,
 * and nobody is sent to prove a second factor for something this credential could never start.
 */
async function startable(request: FastifyRequest, reply: FastifyReply) {
  if (!impersonationEnabled()) return refuse(request, reply, 'impersonation_disabled')
  const uc = request.userContext
  if (uc?.authVia !== 'session' || !uc.sessionId || request.machine) return refuse(request, reply, 'impersonation_session_required')
}

/** Whether the caller holds users:impersonate. Display only (the start route's guard decides). */
async function mayImpersonate(request: FastifyRequest): Promise<boolean> {
  const email = request.userContext?.email
  if (!email || email === 'unknown') return false
  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') return devRights().permissions.includes(IMPERSONATE)
  try {
    return (await rights(email)).permissions.includes(IMPERSONATE)
  } catch {
    return false
  }
}

async function stateHandler(request: FastifyRequest, reply: FastifyReply) {
  const enabled = impersonationEnabled()
  const sessionId = request.userContext?.authVia === 'session' ? request.userContext.sessionId : undefined
  const [allowed, grant] = await Promise.all([
    enabled ? mayImpersonate(request) : false,
    enabled && sessionId ? impersonationStore.bySession(sessionId) : null,
  ])
  return reply.send({ enabled, allowed, maxMinutes: env.IMPERSONATION_MAX_MINUTES, active: grant ? activeView(grant) : null })
}

async function startHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { reason: string; minutes?: number } }>,
  reply: FastifyReply,
) {
  const { id } = request.params
  const uc = request.userContext!
  const reason = request.body.reason.trim()
  if (reason.length < REASON_MIN || reason.length > REASON_MAX) {
    return reply.status(400).send({ error: 'Bad Request', message: `Say why, in ${REASON_MIN} to ${REASON_MAX} characters.` })
  }
  const max = env.IMPERSONATION_MAX_MINUTES
  const minutes = request.body.minutes ?? max
  if (minutes > max) {
    return reply.status(400).send({ error: 'Bad Request', message: `An impersonation lasts ${MIN_MINUTES} to ${max} minutes.` })
  }
  if (id === uc.id) return refuse(request, reply, 'impersonation_self')

  let identity: KratosIdentity | null
  try {
    identity = await kratosService.getIdentity(id)
  } catch (err) {
    if (!(err instanceof KratosApiError && err.statusCode === 404)) throw err
    identity = null
  }
  let problem: Awaited<ReturnType<typeof targetProblem>>
  try {
    problem = await targetProblem(identity)
  } catch {
    return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: "Unable to verify the user's rights. Please try again later." })
  }
  if (problem || !identity) return refuse(request, reply, problem ?? 'impersonation_target_unavailable')

  const ttl = minutes * 60
  const { grant, token, replaced } = await impersonationStore.start({
    adminId: uc.id,
    adminEmail: uc.email,
    adminSessionId: uc.sessionId!,
    targetId: identity.id,
    targetEmail: emailOf(identity) ?? '',
    targetName: nameOf(identity),
    reason,
  }, ttl)

  const a = auditActor(request)
  if (replaced) impersonationAudit('impersonation.stopped', replaced, { actor: a, details: { ended: 'replaced', by: grant.id } })
  impersonationAudit('impersonation.started', grant, { actor: a, details: { minutes } })
  request.log.info({ grantId: grant.id, admin: uc.id, target: identity.id, minutes }, '[impersonation] started')

  return reply.status(201).header('Set-Cookie', impersonationCookie(token, ttl)).header('Cache-Control', 'no-store').send({ active: activeView(grant) })
}

/** Stopping is protective: any signed-in caller, no permission, no step-up, nothing active is fine. */
async function stopHandler(request: FastifyRequest, reply: FastifyReply) {
  const sessionId = request.userContext?.sessionId
  const grant = sessionId ? await impersonationStore.endForSession(sessionId) : null
  if (grant) {
    impersonationAudit('impersonation.stopped', grant, { actor: auditActor(request), details: { ended: 'stopped' } })
    request.log.info({ grantId: grant.id, admin: grant.adminId, target: grant.targetId }, '[impersonation] stopped')
  }
  return reply.status(204).header('Set-Cookie', clearedImpersonationCookie()).send()
}

/** Registered under /api/admin. */
export async function impersonationRoutes(fastify: FastifyInstance) {
  fastify.get('/impersonation', {
    ...open('self'),
    schema: {
      description:
        'Impersonation, for the caller: whether the platform has it on, whether the caller holds users:impersonate, ' +
        'and what is running on this session. Any signed-in person.',
      tags: ['admin'],
      response: {
        200: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            allowed: { type: 'boolean' },
            maxMinutes: { type: 'integer' },
            active: { ...activeSchema, nullable: true },
          },
          required: ['enabled', 'allowed', 'maxMinutes', 'active'],
          additionalProperties: false,
        },
        401: unauthorizedResponseSchema,
      },
    },
  }, stateHandler)

  fastify.post('/users/:id/impersonate', {
    ...needs(IMPERSONATE), // step-up from the catalogue
    onRequest: startable,
    schema: {
      description:
        'Browse the sites behind the gateway as this user, read-only (GET, HEAD, OPTIONS), until it expires or is stopped. ' +
        'Sets the impersonation cookie; the console and this API keep seeing the caller. Needs users:impersonate, a browser ' +
        'session and a second factor of your own proven within 15 minutes. Never yourself, a super administrator, a ' +
        'machine or an inactive identity. One at a time per session: starting another replaces it.',
      tags: ['admin'],
      params: zodToJsonSchema(userIdParamSchema),
      body: {
        type: 'object',
        required: ['reason'],
        properties: {
          reason: { type: 'string', minLength: REASON_MIN, maxLength: 2000, description: `Why, ${REASON_MIN} to ${REASON_MAX} characters once trimmed; kept in the audit trail.` },
          minutes: { type: 'integer', minimum: MIN_MINUTES, maximum: 60, description: 'How long; at most IMPERSONATION_MAX_MINUTES, which is also the default.' },
        },
        additionalProperties: false,
      },
      response: {
        201: { type: 'object', properties: { active: activeSchema }, required: ['active'], additionalProperties: false },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: refusalSchema,
      },
    },
  }, startHandler as never)

  fastify.delete('/impersonation', {
    ...open('self'),
    schema: {
      description: 'Stop the impersonation running on this session and clear its cookie. Succeeds with nothing running.',
      tags: ['admin'],
      response: { 204: { type: 'null', description: 'Stopped' }, 401: unauthorizedResponseSchema },
    },
  }, stopHandler)
}

/** The methods a site request may have; anything rarer finds no route here, which the gateway also reads as a refusal. */
const CHECK_METHODS: HTTPMethods[] = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']

const forwardedHost = (request: FastifyRequest): string | null => {
  const raw = request.headers['x-forwarded-host']
  const host = (Array.isArray(raw) ? raw[0] : raw)?.split(',')[0]?.trim().toLowerCase()
  return host && /^[a-z0-9.-]{1,253}(:\d{1,5})?$/.test(host) ? host : null
}

/**
 * The gateway's check, registered under /api/oathkeeper: every method, because Oathkeeper asks with
 * the method of the request it is deciding. Open to the session gate and to the rate limit (one
 * caller, the gateway, for every browsing administrator); it answers 200 only to a request that
 * proves itself (check.ts) and reads no other credential.
 */
export async function impersonationCheckRoutes(fastify: FastifyInstance) {
  fastify.route({
    method: CHECK_METHODS,
    url: '/impersonation/session',
    config: { ...open('machine').config, rateLimit: false },
    schema: {
      description:
        'Asked by the gateway for a request carrying the impersonation cookie: 200 with a session-shaped body for the ' +
        'impersonated user, or 401 with the reason. Not reachable through the gateway.',
      tags: ['oathkeeper'],
      // No response schema: the identity is passed on as Kratos returns it.
    },
    handler: async (request, reply) => {
      const host = forwardedHost(request)
      const result = await checkImpersonation({ method: request.method, cookieHeader: request.headers.cookie, host })
      reply.header('Cache-Control', 'no-store')
      if (result.ok) return reply.send(result.session)
      request.log.info({ reason: result.reason, grantId: result.grant?.id, host, method: request.method }, '[impersonation] check refused')
      return reply.status(401).send({ error: 'Unauthorized', reason: result.reason })
    },
  })
}
