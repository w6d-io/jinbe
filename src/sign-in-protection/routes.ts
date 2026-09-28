import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { requireAdmin, requireRecentMfa, requireSuperAdmin } from '../middleware/require-admin.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { verifyKratosWebhookAuth } from '../controllers/webhook.controller.js'
import { providerStatus } from './captcha.js'
import { DISPOSABLE_DOMAINS } from './disposable.js'
import { guardFlow, guardSettings, kratosAllowBody, kratosRefusalBody, type Decision, type GuardInput } from './guard.js'
import { protectedTraits } from './protected-traits.js'
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

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)

/**
 * POST /api/webhooks/kratos/guard — the interrupting Kratos web_hook (guard.ts). Registered inside
 * webhookRoutes so it shares the raw-body parser the Ory-Signature check needs. The Jsonnet body
 * (charts: selfservice.flows.{registration,login}.after) sends
 * {flow, flow_type, method, requested_aal, email, traits, captcha_token, ip}; the settings one
 * (selfservice.flows.settings.after.profile) sends {flow: 'settings', method, traits, stored_traits}.
 *
 * 200 {} lets the flow go on, 200 {identity: {traits}} goes on with those traits written instead;
 * 400 with Kratos' `messages` shape stops it with a form message; 401 (bad secret) makes Kratos fail
 * the flow — a misconfigured hook refuses rather than waves through.
 */
export async function signInGuardHook(request: FastifyRequest, reply: FastifyReply) {
  if (!verifyKratosWebhookAuth(request)) {
    request.log.warn({ path: '/api/webhooks/kratos/guard' }, 'Rejected unauthenticated Kratos guard webhook')
    return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing webhook credentials' })
  }
  const b = (request.body ?? {}) as Record<string, unknown>
  const flow = b.flow as CaptchaFlow | 'settings'
  if (flow !== 'settings' && !CAPTCHA_FLOWS.includes(flow)) {
    return reply.status(400).send({ error: 'unknown_flow', message: 'flow must be registration, login, recovery, verification or settings' })
  }
  const input: GuardInput | null = flow === 'settings' ? null : {
    flow,
    flowType: str(b.flow_type),
    method: str(b.method),
    requestedAal: str(b.requested_aal),
    email: str(b.email),
    traits: b.traits,
    captchaToken: str(b.captcha_token),
    ip: str(b.ip)?.split(',')[0].trim() ?? null,
  }
  const decision: Decision = input ? await guardFlow(input) : guardSettings({ traits: b.traits, storedTraits: b.stored_traits })
  if (decision.allow) {
    if (decision.traits) request.log.info({ flow }, 'Sign-in guard put back or dropped protected traits')
    return reply.status(200).send(kratosAllowBody(decision))
  }
  const domain = input?.email?.split('@')[1] ?? null
  // Refusals are counted (jinbe_sign_in_guard_decisions_total); the log carries the domain, never the address or token.
  request.log.info({ flow, flowType: input?.flowType, result: decision.result, domain }, 'Sign-in guard refused a Kratos flow')
  return reply.status(400).send(kratosRefusalBody(decision.message))
}

/**
 * Public, for login-ui: GET /api/public/sign-in-protection — which flows show the widget, the site key,
 * the sign-up mode. (The gateway's side is the sign-in gate, gate-routes.ts.)
 */
export async function signInProtectionPublicRoutes(fastify: FastifyInstance) {
  fastify.get('/', {
    config: { rateLimit: { max: 600, timeWindow: '1 minute' } },
    schema: {
      description:
        'What login-ui needs to draw the sign-in pages: the bot-check provider, its public site key and the flows that ask for it, ' +
        'the sign-up mode (with the allowed domains when sign-up is limited), and the identity traits only an administrator sets ' +
        '(never shown as form fields). Never the secret, never the listed addresses.',
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
      protectedTraits: protectedTraits(),
    }
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
