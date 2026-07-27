import type { FastifyRequest, FastifyReply } from 'fastify'
import { createHmac, timingSafeEqual } from 'crypto'
import { env } from '../config/env.js'
import { auditEventService, type AuditEvent } from '../services/audit-event.service.js'

/**
 * Kratos after-hook webhook (A5).
 *
 * Kratos can hook every self-service flow EXCEPT `error` and `logout`, so this
 * captures login / MFA (settings second-factor) / settings / registration —
 * logout is NOT hookable (audited instead via the admin session-revoke path).
 *
 * [P0-1] The endpoint is PUBLIC at the gateway (Kratos calls it without a
 * session), so it MUST self-authenticate. On an unauthenticated call it returns
 * 401 and emits NOTHING — an attacker must never be able to write an
 * attacker-chosen audit row.
 */

/** Header carrying the shared api_key (Kratos `web_hook config.auth.type: api_key`). */
const SECRET_HEADER = 'x-kratos-webhook-secret'

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

/**
 * Authenticate the caller. Defense-in-depth: accept EITHER a constant-time
 * matching api_key header OR a valid `Ory-Signature` HMAC-SHA256 over the raw
 * body. When the secret is not configured, every call is rejected (fail-closed).
 */
export function verifyKratosWebhookAuth(request: FastifyRequest): boolean {
  const secret = env.KRATOS_WEBHOOK_SECRET
  if (!secret) return false

  // 1. api_key header (or `Authorization: Bearer <secret>`), constant-time.
  const rawHeader = (request.headers[SECRET_HEADER] ?? request.headers['authorization'] ?? '') as string
  const provided = rawHeader.startsWith('Bearer ') ? rawHeader.slice(7) : rawHeader
  if (provided && safeEqual(provided, secret)) return true

  // 2. Ory-Signature HMAC-SHA256 over the raw body (t=…,s=…), constant-time.
  const sig = request.headers['ory-signature'] as string | undefined
  const raw = (request as FastifyRequest & { rawBody?: string }).rawBody
  if (sig && raw) {
    const expected = createHmac('sha256', secret).update(raw).digest('hex')
    const s = /(?:^|,)\s*s=([a-f0-9]+)/i.exec(sig)?.[1]
    if (s && safeEqual(s, expected)) return true
  }

  return false
}

interface KratosHookBody {
  flow?: string
  flow_type?: string
  method?: string
  aal?: string
  outcome?: string
  ip?: string
  ua?: string
  session_id?: string
  sessionId?: string
  identity?: { id?: string; traits?: { email?: string }; email?: string }
  identity_id?: string
  email?: string
}

const MFA_METHODS = new Set(['totp', 'webauthn', 'lookup_secret'])

export class WebhookController {
  /** POST /api/webhooks/kratos */
  async kratos(request: FastifyRequest, reply: FastifyReply) {
    if (!verifyKratosWebhookAuth(request)) {
      // Emit NOTHING — no attacker-chosen row.
      request.log.warn({ path: '/api/webhooks/kratos', ip: request.ip }, 'Rejected unauthenticated Kratos webhook')
      return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing webhook credentials' })
    }

    const body = (request.body ?? {}) as KratosHookBody
    const flowType = body.flow ?? body.flow_type ?? 'unknown'
    const actorEmail = body.identity?.traits?.email ?? body.identity?.email ?? body.email ?? null
    const aal = body.aal
    const method = body.method
    const outcome = body.outcome ?? 'success'
    const sessionId = body.session_id ?? body.sessionId ?? null
    const identityId = body.identity?.id ?? body.identity_id

    // Classify the auth event. Logout is not hookable, so it never arrives here.
    let verb = 'login'
    if (flowType === 'settings') verb = method && MFA_METHODS.has(method) ? 'mfa' : 'settings'
    else if (flowType === 'registration') verb = 'create'
    else if (flowType === 'login') verb = method && MFA_METHODS.has(method) ? 'mfa' : 'login'
    else if (flowType === 'recovery' || flowType === 'verification') verb = flowType

    const failed = /fail|error|denied/i.test(outcome)

    const event: AuditEvent = {
      category: 'auth',
      kind: 'auth',
      verb,
      target: actorEmail ? `user:${actorEmail}` : 'user:unknown',
      result: failed ? 'denied' : 'ok',
      severity: verb === 'mfa' && /remov|disable|delet/i.test(outcome) ? 'high' : undefined,
      actor: {
        email: actorEmail,
        ip: body.ip ?? request.ip ?? null,
        ua: body.ua ?? ((request.headers['user-agent'] as string) || null),
        sessionId,
      },
      targetId: identityId,
      targetType: 'user',
      mfa: method && MFA_METHODS.has(method) ? method : undefined,
      source: 'kratos-webhook',
      // Strict allow-list — no raw Kratos payload reaches the log.
      details: { flowType, actorEmail, aal, method, outcome, sessionId },
    }

    await auditEventService.emit(event)
    return reply.status(200).send({ ok: true })
  }
}

export const webhookController = new WebhookController()
