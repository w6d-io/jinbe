import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { createHash } from 'crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { requireAdmin, requireRecentMfa, requireSuperAdmin } from '../middleware/require-admin.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { verifyKratosWebhookAuth } from '../controllers/webhook.controller.js'
import { providerStatus } from './captcha.js'
import { DISPOSABLE_DOMAINS } from './disposable.js'
import { guardFlow, kratosRefusalBody, type GuardInput } from './guard.js'
import {
  CAPTCHA_FLOWS,
  defaultSignInProtection,
  getSignInProtection,
  setSignInProtection,
  validateSignInProtection,
  type CaptchaFlow,
} from './settings.js'

const problemSchema = {
  type: 'object',
  properties: {
    error: { type: 'string' },
    message: { type: 'string' },
    problems: { type: 'array', items: { type: 'object', properties: { field: { type: 'string' }, message: { type: 'string' } } } },
  },
}

const settingsSchema = {
  type: 'object',
  properties: {
    captcha: {
      type: 'object',
      properties: {
        flows: { type: 'object', properties: Object.fromEntries(CAPTCHA_FLOWS.map((f) => [f, { type: 'boolean' }])) },
        failMode: { type: 'string' },
      },
    },
    registration: {
      type: 'object',
      properties: {
        mode: { type: 'string' },
        allowEmails: { type: 'array', items: { type: 'string' } },
        allowDomains: { type: 'array', items: { type: 'string' } },
        denyDomains: { type: 'array', items: { type: 'string' } },
        blockDisposable: { type: 'boolean' },
      },
    },
  },
}

const providerSchema = {
  type: 'object',
  properties: {
    provider: { type: 'string' },
    configured: { type: 'boolean' },
    siteKey: { type: ['string', 'null'] },
    secretSet: { type: 'boolean' },
    testKeys: { type: 'boolean' },
    problem: { type: ['string', 'null'] },
  },
}

/**
 * A recovery or verification flow POSTs to the same URL to send the email and to submit the code, and
 * the gateway cannot tell them apart. So a token that passed once becomes a short pass for that flow:
 * a few more gateway checks within ten minutes are answered from Redis, without the provider (which
 * would refuse a second use). Redis down: every check asks the provider.
 */
export const GATEWAY_PASS_TTL_S = 600
export const GATEWAY_PASS_USES = 5
const passKey = (token: string) => `sip:pass:${createHash('sha256').update(token).digest('hex')}`

async function gatewayPass(token: string): Promise<'valid' | 'spent' | 'unknown'> {
  try {
    const redis = getRedisClient()
    const key = passKey(token)
    if (!(await redis.exists(key))) return 'unknown'
    return (await redis.incr(key)) <= GATEWAY_PASS_USES ? 'valid' : 'spent'
  } catch {
    return 'unknown'
  }
}

async function rememberGatewayPass(token: string): Promise<void> {
  try {
    await getRedisClient().set(passKey(token), '1', 'EX', GATEWAY_PASS_TTL_S)
  } catch {
    // Without the pass the next check of this flow asks the provider again.
  }
}

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)

/**
 * POST /api/webhooks/kratos/guard — the interrupting Kratos web_hook (guard.ts). Registered inside
 * webhookRoutes so it shares the raw-body parser the Ory-Signature check needs. The Jsonnet body
 * (charts: selfservice.flows.{registration,login}.after) sends
 * {flow, flow_type, method, requested_aal, email, captcha_token, ip}.
 *
 * 200 {} lets the flow go on; 400 with Kratos' `messages` shape stops it with a form message;
 * 401 (bad secret) makes Kratos fail the flow — a misconfigured hook refuses rather than waves through.
 */
export async function signInGuardHook(request: FastifyRequest, reply: FastifyReply) {
  if (!verifyKratosWebhookAuth(request)) {
    request.log.warn({ path: '/api/webhooks/kratos/guard' }, 'Rejected unauthenticated Kratos guard webhook')
    return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing webhook credentials' })
  }
  const b = (request.body ?? {}) as Record<string, unknown>
  const flow = b.flow as CaptchaFlow
  if (!CAPTCHA_FLOWS.includes(flow)) {
    return reply.status(400).send({ error: 'unknown_flow', message: 'flow must be registration, login, recovery or verification' })
  }
  const input: GuardInput = {
    flow,
    flowType: str(b.flow_type),
    method: str(b.method),
    requestedAal: str(b.requested_aal),
    email: str(b.email),
    captchaToken: str(b.captcha_token),
    ip: str(b.ip)?.split(',')[0].trim() ?? null,
  }
  const decision = await guardFlow(input)
  if (decision.allow) return reply.status(200).send({})
  const domain = input.email?.split('@')[1] ?? null
  // Refusals are counted (jinbe_sign_in_guard_decisions_total); the log carries the domain, never the address or token.
  request.log.info({ flow, flowType: input.flowType, result: decision.result, domain }, 'Sign-in guard refused a Kratos flow')
  return reply.status(400).send(kratosRefusalBody(decision.message))
}

/**
 * Public, for login-ui and the gateway:
 *   GET  /api/public/sign-in-protection        which flows show the widget, the site key, the sign-up mode
 *   POST /api/public/sign-in-protection/check  the gateway's bot check for flows Kratos cannot interrupt
 */
export async function signInProtectionPublicRoutes(fastify: FastifyInstance) {
  fastify.get('/', {
    config: { rateLimit: { max: 600, timeWindow: '1 minute' } },
    schema: {
      description:
        'What login-ui needs to draw the sign-in pages: the bot-check provider, its public site key and the flows that ask for it, ' +
        'and the sign-up mode (with the allowed domains when sign-up is limited). Never the secret, never the listed addresses.',
      tags: ['sign-in-protection'],
    },
  }, async (_request, reply) => {
    reply.header('cache-control', 'public, max-age=10')
    let settings
    try {
      settings = await getSignInProtection()
    } catch {
      return reply.status(503).send({ error: 'settings_unavailable', message: 'Sign-in protection settings cannot be read right now' })
    }
    const p = providerStatus()
    return {
      captcha: {
        provider: p.provider,
        configured: p.configured,
        siteKey: p.configured ? p.siteKey : null,
        scriptUrl: p.scriptUrl,
        flows: settings.captcha.flows,
      },
      registration: {
        mode: settings.registration.mode,
        domains: settings.registration.mode === 'allowlist' ? settings.registration.allowDomains.filter((d) => !d.startsWith('*.')) : [],
      },
    }
  })

  // Called by an Oathkeeper remote_json authorizer on POST /self-service/{recovery,verification}
  // (charts), with the token login-ui put in the `stl_kcap` cookie. 200 lets the request through,
  // 403 stops it. Unauthenticated on purpose: it only says whether a one-time token is good, and
  // spends it doing so.
  fastify.post('/check', {
    config: { rateLimit: { max: 1200, timeWindow: '1 minute' } },
    schema: {
      description: 'Gateway bot check for recovery and verification submits: 200 when the flow does not ask for it or the token passes, 403 otherwise.',
      tags: ['sign-in-protection'],
      body: {
        type: 'object',
        required: ['flow'],
        properties: { flow: { type: 'string', enum: ['recovery', 'verification'] }, token: { type: 'string', maxLength: 4096 }, ip: { type: 'string', maxLength: 64 } },
      },
    },
  }, async (request, reply) => {
    const b = request.body as { flow: 'recovery' | 'verification'; token?: string; ip?: string }
    if (b.token) {
      const pass = await gatewayPass(b.token)
      if (pass === 'valid') return { ok: true }
      if (pass === 'spent') return reply.status(403).send({ error: 'captcha_invalid', message: 'The bot check has expired. Please complete it again.' })
    }
    const decision = await guardFlow({ flow: b.flow, captchaToken: b.token || null, ip: b.ip || null })
    if (decision.allow) {
      if (b.token && decision.result === 'allowed') await rememberGatewayPass(b.token)
      return { ok: true }
    }
    return reply.status(403).send({ error: decision.result, message: decision.message.text })
  })
}

/**
 * The setting (settings.ts).
 *   GET /api/admin/settings/sign-in-protection — admin
 *   PUT /api/admin/settings/sign-in-protection — super_admin + a recent second factor: who may create
 *       an account and whether bots are stopped is itself a sign-in-security change.
 */
export async function signInProtectionSettingsRoutes(fastify: FastifyInstance) {
  const view = async () => ({
    settings: await getSignInProtection(),
    defaults: defaultSignInProtection(),
    provider: (({ scriptUrl: _s, ...p }) => p)(providerStatus()),
    disposableDomains: DISPOSABLE_DOMAINS.size,
  })

  fastify.get('/sign-in-protection', {
    preHandler: requireAdmin,
    schema: {
      description: 'Bot check per sign-in flow, the provider status (never the secret), the sign-up mode and its allow and deny lists.',
      tags: ['sign-in-protection'],
      response: { 200: { type: 'object', properties: { settings: settingsSchema, defaults: settingsSchema, provider: providerSchema, disposableDomains: { type: 'number' } } } },
    },
  }, view)

  fastify.put('/sign-in-protection', {
    preHandler: [requireSuperAdmin, requireRecentMfa],
    schema: {
      description:
        'Replace the sign-in protection settings. Turning the bot check on needs a configured provider. Enforced by the Kratos ' +
        'web_hook on every guarded submit within 5 seconds. Requires super_admin + a second factor proven within 15 minutes.',
      tags: ['sign-in-protection'],
      body: { type: 'object', required: ['captcha', 'registration'], additionalProperties: false, properties: settingsSchema.properties },
      response: { 400: problemSchema },
    },
  }, async (request, reply) => {
    const checked = validateSignInProtection(request.body)
    if (!checked.ok) {
      return reply.status(400).send({ error: 'invalid_settings', message: checked.problems.map((p) => `${p.field}: ${p.message}`).join('; '), problems: checked.problems })
    }
    const next = checked.value
    const before = await getSignInProtection()
    const turningOn = CAPTCHA_FLOWS.filter((f) => next.captcha.flows[f] && !before.captcha.flows[f])
    const provider = providerStatus()
    if (turningOn.length && !provider.configured) {
      // Fail-closed with no provider would refuse every attempt of that flow — sign-in included.
      return reply.status(400).send({
        error: 'captcha_not_configured',
        message: `The bot check cannot be turned on: ${provider.problem}.`,
        problems: turningOn.map((f) => ({ field: `captcha.flows.${f}`, message: 'no configured provider' })),
      })
    }
    const saved = await setSignInProtection(next)
    const a = auditActor(request)
    auditEventService.emit({
      category: 'rbac', kind: 'change', verb: 'update', target: 'sign-in-protection',
      result: 'applied', severity: 'high', v1Event: 'config.sign_in_protection.changed',
      actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { before, after: saved },
    }).catch(() => {})
    return view()
  })
}
