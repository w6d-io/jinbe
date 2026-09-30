import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { needs } from '../policy/route-access.js'
import { userIdParamSchema } from '../schemas/admin.schema.js'
import { forbiddenResponseSchema, notFoundResponseSchema, unauthorizedResponseSchema } from '../schemas/response-schemas.js'
import { auditEventService } from '../services/audit-event.service.js'
import {
  AddressUnavailableError,
  addressDigest,
  changeEmail,
  NoAddressError,
  SameAddressError,
} from '../services/email-change.service.js'
import { KratosApiError, kratosService } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { noticeAddressChanged } from '../services/security-notice.js'
import { outranking } from '../services/user-permissions.js'
import {
  AlreadyVerifiedError,
  countVerificationLink,
  sendVerificationLink,
  UnknownAddressError,
  unverifiedAddress,
  VerificationRateLimitedError,
  VerificationUnavailableError,
} from '../services/verification.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * A user's addresses, for an administrator (mcp-write-wave.md §3): changing the sign-in address, and
 * resending the link that verifies one. Both are direct for a delegated caller (an MCP key acting as
 * its holder): the delegation gate refuses one aimed at the caller, and the address change carries the
 * catalogue's step-up (a personal key may stand on the factor proven at its creation).
 */
export async function userAddressRoutes(fastify: FastifyInstance) {
  const params = zodToJsonSchema(userIdParamSchema)
  const errors = { 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema }

  fastify.post('/users/:id/email', {
    ...needs('users:update_email'), // step-up from the catalogue
    schema: {
      description:
        "Change a user's sign-in address. The new address starts unverified and is sent a verification link (Kratos, method link); " +
        'the old address is owed a notice (recorded in the audit trail: jinbe has no mailer); a hashed history of previous addresses is kept 30 days. ' +
        'Never your own (use your account settings), never somebody holding administrative rights you do not. A taken address answers 409 ' +
        'address_unavailable without naming the account. Needs users:update_email and a second factor proven within 15 minutes.',
      tags: ['admin'],
      params,
      body: {
        type: 'object',
        required: ['email'],
        properties: { email: { type: 'string', format: 'email', maxLength: 254 } },
        additionalProperties: false,
      },
      response: {
        200: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            verified: { type: 'boolean' },
            verificationSent: { type: 'boolean' },
            verificationError: { type: 'string' },
            oldAddressNotice: {
              type: 'object',
              properties: { delivered: { type: 'boolean' }, recorded: { type: 'boolean' }, channel: { type: 'string' } },
            },
          },
        },
        ...errors,
      },
    },
  }, changeEmailHandler as never)

  fastify.post('/users/:id/verification', {
    ...needs('users:verify'),
    schema: {
      description:
        'Resend the verification link (Kratos, method link) for an unverified address of the user: the one given, else the unverified ' +
        'sign-in address. The link goes to the user and is never returned. 409 already_verified when there is nothing to verify; 3 links ' +
        'per user per 15 minutes and 30 per caller per hour (429 with Retry-After). Needs users:verify.',
      tags: ['admin'],
      params,
      body: {
        type: ['object', 'null'],
        properties: { address: { type: 'string', format: 'email', maxLength: 254 } },
        additionalProperties: false,
      },
      response: {
        202: { type: 'object', properties: { sent: { type: 'boolean' } }, additionalProperties: false },
        ...errors,
      },
    },
  }, resendVerificationHandler as never)
}

const notFound = (reply: FastifyReply) => reply.status(404).send({ error: 'Not Found', message: 'User not found' })

async function changeEmailHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { email: string } }>,
  reply: FastifyReply,
) {
  const { id } = request.params
  if (id === request.userContext?.id) {
    return reply.status(403).send({ error: 'own_address', message: 'You cannot change your own address here. Use your account settings.' })
  }

  let target
  try {
    target = await kratosService.getIdentity(id)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) return notFound(reply)
    throw err
  }

  // A new address plus a recovery mail is an account takeover: never over somebody stronger.
  const theirAddress = typeof target.traits?.email === 'string' ? target.traits.email : null
  if (theirAddress) {
    let theirs: string[]
    try {
      theirs = (await rights(theirAddress)).permissions
    } catch {
      return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: "Unable to verify the user's rights. Please try again later." })
    }
    if (outranking(theirs, request.rbacInfo?.permissions ?? []).length) {
      return reply.status(403).send({
        error: 'outranked',
        message: 'This user holds administrative rights you do not. Only somebody holding them can change their address.',
      })
    }
  }

  const actor = auditActor(request)
  let changed
  try {
    changed = await changeEmail(id, request.body.email, actor.id ?? null)
  } catch (err) {
    if (err instanceof AddressUnavailableError) {
      return reply.status(409).send({ error: 'address_unavailable', message: 'This address cannot be used. Choose another one.' })
    }
    if (err instanceof SameAddressError) return reply.status(400).send({ error: 'address_unchanged', message: err.message })
    if (err instanceof NoAddressError) return reply.status(422).send({ error: 'no_address', message: err.message })
    if (err instanceof KratosApiError && err.statusCode === 404) return notFound(reply)
    if (err instanceof KratosApiError && err.statusCode === 400) {
      return reply.status(400).send({ error: 'invalid_address', message: 'The identity schema refused this address.' })
    }
    throw err
  }
  const email = String(changed.identity.traits?.email ?? request.body.email)

  rbacService.notifyBindingsChanged('email_changed', actor).catch(() => {})
  auditEventService.emit({
    category: 'auth',
    kind: 'security',
    verb: 'email_change',
    target: `user:${id}`,
    targetType: 'user',
    targetId: id,
    result: 'applied',
    severity: 'high',
    actor,
    requestId: actor.requestId,
    source: 'jinbe-api',
    v1Event: 'user.email_changed',
    details: { previous: changed.previousDigest, next: changed.nextDigest },
  }).catch(() => {})

  // The link to the new address. The change stands whether or not it went out; the answer says which.
  let verificationSent = false
  let verificationError: string | undefined
  try {
    await sendVerificationLink(email)
    verificationSent = true
  } catch (err) {
    verificationError = err instanceof VerificationUnavailableError ? 'verification_link_unavailable' : 'send_failed'
    request.log.warn({ err: (err as Error).message, id }, '[email-change] address changed, verification link not sent')
  }

  const oldAddressNotice = await noticeAddressChanged(id, changed.previousDigest, actor)
  return reply.send({ id, email, verified: false, verificationSent, ...(verificationError ? { verificationError } : {}), oldAddressNotice })
}

async function resendVerificationHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { address?: string } | null }>,
  reply: FastifyReply,
) {
  const { id } = request.params
  let address: string
  try {
    address = unverifiedAddress(await kratosService.getIdentity(id), request.body?.address)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) return notFound(reply)
    if (err instanceof AlreadyVerifiedError) return reply.status(409).send({ error: 'already_verified', message: err.message })
    if (err instanceof UnknownAddressError) return reply.status(422).send({ error: 'unknown_address', message: err.message })
    throw err
  }

  try {
    await countVerificationLink(id, request.userContext?.id ?? 'unknown')
  } catch (err) {
    if (err instanceof VerificationRateLimitedError) {
      return reply.status(429).header('Retry-After', String(err.retryAfterSeconds)).send({
        error: 'rate_limited',
        message: err.scope === 'target'
          ? 'Too many verification links were sent to this user recently. Try again later.'
          : 'You sent too many verification links in the last hour. Try again later.',
        retryAfter: err.retryAfterSeconds,
      })
    }
    throw err
  }

  try {
    await sendVerificationLink(address)
  } catch (err) {
    if (err instanceof VerificationUnavailableError) {
      request.log.warn({ err: err.message }, '[verification] Kratos does not offer verification by link')
      return reply.status(409).send({ error: 'verification_link_unavailable', message: err.message })
    }
    throw err
  }

  const actor = auditActor(request)
  auditEventService.emit({
    category: 'auth',
    kind: 'change',
    verb: 'verification_sent',
    target: `user:${id}`,
    targetType: 'user',
    targetId: id,
    result: 'applied',
    actor,
    requestId: actor.requestId,
    source: 'jinbe-api',
    v1Event: 'user.verification_sent',
    details: { address: addressDigest(address) },
  }).catch(() => {})
  return reply.status(202).send({ sent: true })
}
