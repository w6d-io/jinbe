import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// Sign-in protection: the setting (rbac:config sign_in_protection), the bot check against the
// provider, the registration policy, and the interrupting Kratos web_hook that enforces both.

const h = vi.hoisted(() => ({
  config: {} as Record<string, string>,
  redisDown: false,
  emit: vi.fn(async () => 'id'),
  env: {} as Record<string, unknown>,
  kv: new Map<string, number>(),
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in h.env ? h.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getConfig: vi.fn(async () => {
      if (h.redisDown) throw new Error('ECONNREFUSED')
      return { ...h.config }
    }),
    setConfig: vi.fn(async (k: string, v: string) => { h.config[k] = v }),
  },
}))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    exists: async (k: string) => (h.kv.has(k) ? 1 : 0),
    incr: async (k: string) => { const v = (h.kv.get(k) ?? 0) + 1; h.kv.set(k, v); return v },
    set: async (k: string, v: string) => { h.kv.set(k, Number(v)); return 'OK' },
  }),
}))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../middleware/require-admin.js', () => ({
  requireAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-admin']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireSuperAdmin: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-write']) return reply.status(403).send({ error: 'Forbidden' })
  },
  requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required' })
  },
}))

import { webhookRoutes } from '../../routes/webhook.routes.js'
import { signInProtectionPublicRoutes, signInProtectionSettingsRoutes } from '../../sign-in-protection/routes.js'
import { providerStatus, verifyCaptcha } from '../../sign-in-protection/captcha.js'
import { isDisposable } from '../../sign-in-protection/disposable.js'
import { GUARD_MESSAGE_IDS, guardFlow, registrationVerdict } from '../../sign-in-protection/guard.js'
import {
  SIGN_IN_PROTECTION_KEY,
  defaultSignInProtection,
  parseSignInProtection,
  resetSignInProtectionCache,
  validateSignInProtection,
  type SignInProtection,
} from '../../sign-in-protection/settings.js'
import { isPublicRoute } from '../../middleware/require-auth.js'
import { secondFactorScope } from '../../second-factor/gate.js'

// Cloudflare's published Turnstile test keys.
const PASS_SECRET = '1x0000000000000000000000000000000AA'
const FAIL_SECRET = '2x0000000000000000000000000000000AA'
const SITE_KEY = '1x00000000000000000000AA'
const DUMMY_TOKEN = 'XXXX.DUMMY.TOKEN.XXXX'
const HOOK_SECRET = 'hook-secret-for-tests'

function store(p: Partial<{ captcha: Partial<SignInProtection['captcha']>; registration: Partial<SignInProtection['registration']> }>) {
  const d = defaultSignInProtection()
  const v = { captcha: { ...d.captcha, ...p.captcha }, registration: { ...d.registration, ...p.registration } }
  h.config[SIGN_IN_PROTECTION_KEY] = JSON.stringify(v)
  resetSignInProtectionCache()
}

/** A siteverify stand-in answering like the provider would for the configured secret. */
function siteverify(answer: Record<string, unknown> | 'down' | number) {
  return vi.fn(async () => {
    if (answer === 'down') throw new TypeError('fetch failed')
    if (typeof answer === 'number') return new Response('oops', { status: answer })
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof fetch
}

beforeEach(() => {
  h.config = {}
  h.redisDown = false
  h.kv.clear()
  h.env = { CAPTCHA_SITE_KEY: SITE_KEY, CAPTCHA_SECRET_KEY: PASS_SECRET, KRATOS_WEBHOOK_SECRET: HOOK_SECRET }
  resetSignInProtectionCache()
})

describe('settings', () => {
  it('unset is today: no bot check, open sign-up', () => {
    expect(parseSignInProtection(undefined)).toEqual(defaultSignInProtection())
    expect(parseSignInProtection('{not json')).toEqual(defaultSignInProtection())
  })

  it('cleans lists (trim, lowercase, dedupe, sort) and refuses what is not an email or a domain', () => {
    const ok = validateSignInProtection({
      captcha: { flows: { registration: true } },
      registration: { mode: 'allowlist', allowEmails: [' Bob@Example.com ', 'bob@example.com'], allowDomains: ['Corp.IO', '*.corp.io'] },
    })
    expect(ok.ok && ok.value.registration).toMatchObject({ allowEmails: ['bob@example.com'], allowDomains: ['*.corp.io', 'corp.io'] })
    expect(ok.ok && ok.value.captcha.flows).toEqual({ registration: true, login: false, recovery: false, verification: false })

    const bad = validateSignInProtection({ captcha: { failMode: 'maybe' }, registration: { mode: 'invite', allowEmails: ['nope'], denyDomains: ['http://x.io'] } })
    expect(bad.ok).toBe(false)
    expect(!bad.ok && bad.problems.map((p) => p.field).sort()).toEqual(['captcha.failMode', 'registration.allowEmails', 'registration.denyDomains', 'registration.mode'])
  })

  it('an allow-list needs at least one entry to be saved, but an empty one read back lets nobody in', () => {
    expect(validateSignInProtection({ registration: { mode: 'allowlist' } }).ok).toBe(false)
    const stored = parseSignInProtection(JSON.stringify({ registration: { mode: 'allowlist' } }))
    expect(stored.registration.mode).toBe('allowlist')
    expect(registrationVerdict('a@b.io', stored.registration)?.allow).toBe(false)
  })
})

describe('registration policy', () => {
  const policy = (p: Partial<SignInProtection['registration']>) => ({ ...defaultSignInProtection().registration, ...p })

  it('open lets everyone in; closed nobody', () => {
    expect(registrationVerdict('anyone@gmail.com', policy({}))).toBeNull()
    const closed = registrationVerdict('anyone@corp.io', policy({ mode: 'closed' }))
    expect(closed).toMatchObject({ allow: false, result: 'registration_closed' })
    expect(closed && !closed.allow && closed.message.text).toMatch(/closed.*administrator/i)
  })

  it('allowlist: exact emails and domains; *.domain covers subdomains only', () => {
    const p = policy({ mode: 'allowlist', allowEmails: ['guest@gmail.com'], allowDomains: ['corp.io', '*.lab.io'] })
    expect(registrationVerdict('Guest@Gmail.com', p)).toBeNull()
    expect(registrationVerdict('ann@corp.io', p)).toBeNull()
    expect(registrationVerdict('ann@eu.lab.io', p)).toBeNull()
    expect(registrationVerdict('ann@lab.io', p)?.result).toBe('registration_not_allowed')
    expect(registrationVerdict('ann@corp.io.evil.com', p)?.result).toBe('registration_not_allowed')
    expect(registrationVerdict('other@gmail.com', p)?.result).toBe('registration_not_allowed')
    const refused = registrationVerdict('x@y.io', p)
    expect(refused && !refused.allow && refused.message).toMatchObject({ text: 'Sign-ups are limited to @corp.io addresses and a few others.', pointer: '#/' })
  })

  it('disposable inboxes: built-in list when switched on, the console deny-list always; a listed address wins', () => {
    expect(isDisposable('mailinator.com')).toBe(true)
    expect(isDisposable('x.mailinator.com')).toBe(true)
    expect(isDisposable('gmail.com')).toBe(false)
    expect(registrationVerdict('a@mailinator.com', policy({}))).toBeNull()
    expect(registrationVerdict('a@mailinator.com', policy({ blockDisposable: true }))?.result).toBe('registration_disposable')
    expect(registrationVerdict('a@spam.example', policy({ denyDomains: ['spam.example'] }))?.result).toBe('registration_disposable')
    expect(registrationVerdict('a@sub.spam.example', policy({ denyDomains: ['spam.example'] }))?.result).toBe('registration_disposable')
    expect(registrationVerdict('qa@mailinator.com', policy({ blockDisposable: true, allowEmails: ['qa@mailinator.com'] }))).toBeNull()
  })
})

describe('provider (Turnstile)', () => {
  it('status: configured with both keys; the secret is never part of it', () => {
    const s = providerStatus()
    expect(s).toMatchObject({ provider: 'turnstile', configured: true, siteKey: SITE_KEY, secretSet: true, testKeys: true })
    expect(JSON.stringify(s)).not.toContain(PASS_SECRET)
    h.env.CAPTCHA_SECRET_KEY = undefined
    expect(providerStatus()).toMatchObject({ configured: false, problem: 'CAPTCHA_SECRET_KEY is not set' })
  })

  it('test keys are refused in production unless allowed', () => {
    h.env.NODE_ENV = 'production'
    expect(providerStatus()).toMatchObject({ configured: false, testKeys: true })
    h.env.CAPTCHA_ALLOW_TEST_KEYS = true
    expect(providerStatus().configured).toBe(true)
  })

  it('posts secret + token + remoteip as a form and reads success', async () => {
    const f = siteverify({ success: true })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'registration', remoteIp: '203.0.113.9' }, f)).toEqual({ ok: true })
    const [url, init] = (f as unknown as { mock: { calls: [string, RequestInit][] } }).mock.calls[0]
    expect(url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify')
    expect(Object.fromEntries(new URLSearchParams(init.body as string))).toEqual({ secret: PASS_SECRET, response: DUMMY_TOKEN, remoteip: '203.0.113.9' })
  })

  it('missing token, bad answer, provider trouble', async () => {
    const never = vi.fn() as unknown as typeof fetch
    expect(await verifyCaptcha('', { action: 'login' }, never)).toEqual({ ok: false, reason: 'missing' })
    expect(never).not.toHaveBeenCalled()
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify({ success: false, 'error-codes': ['invalid-input-response'] }))).toMatchObject({ reason: 'invalid' })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify({ success: false, 'error-codes': ['timeout-or-duplicate'] }))).toMatchObject({ reason: 'invalid' })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify({ success: false, 'error-codes': ['invalid-input-secret'] }))).toMatchObject({ reason: 'unavailable' })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify('down'))).toMatchObject({ reason: 'unavailable' })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify(502))).toMatchObject({ reason: 'unavailable' })
    h.env.CAPTCHA_SITE_KEY = undefined
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, never)).toEqual({ ok: false, reason: 'not_configured' })
  })

  it('real keys: a token solved for another flow or on another host does not pass', async () => {
    h.env.CAPTCHA_SECRET_KEY = '0x4AAAAAAA-real-secret'
    h.env.CAPTCHA_EXPECTED_HOSTNAMES = ['auth.example.com']
    const ok = { success: true, hostname: 'auth.example.com', action: 'registration' }
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'registration' }, siteverify(ok))).toEqual({ ok: true })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'login' }, siteverify(ok))).toMatchObject({ reason: 'invalid', codes: ['action-mismatch'] })
    expect(await verifyCaptcha(DUMMY_TOKEN, { action: 'registration' }, siteverify({ ...ok, hostname: 'evil.io' }))).toMatchObject({ codes: ['hostname-mismatch'] })
  })

  it('reCAPTCHA v3: below the score threshold is a bad answer', async () => {
    h.env.CAPTCHA_PROVIDER = 'recaptcha'
    h.env.CAPTCHA_SECRET_KEY = 'real-recaptcha-secret'
    expect(await verifyCaptcha('t', { action: 'login' }, siteverify({ success: true, action: 'login', score: 0.9 }))).toEqual({ ok: true })
    expect(await verifyCaptcha('t', { action: 'login' }, siteverify({ success: true, action: 'login', score: 0.1 }))).toMatchObject({ codes: ['score-too-low'] })
  })
})

describe('guard decisions', () => {
  it('nothing switched on: every flow goes on, registration included', async () => {
    const never = vi.fn() as unknown as typeof fetch
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io' }, never)).toEqual({ allow: true, result: 'allowed' })
    expect(await guardFlow({ flow: 'login', method: 'password' }, never)).toEqual({ allow: true, result: 'not_guarded' })
    expect(never).not.toHaveBeenCalled()
  })

  it('bot check on registration: no token refused, a good one passes', async () => {
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false } } })
    const refused = await guardFlow({ flow: 'registration', flowType: 'api', email: 'a@b.io' }, siteverify({ success: true }))
    expect(refused).toMatchObject({ allow: false, result: 'captcha_missing', message: { id: GUARD_MESSAGE_IDS.captcha_missing } })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, siteverify({ success: true }))).toEqual({ allow: true, result: 'allowed' })
  })

  it('Cloudflare always-fail secret: refused', async () => {
    h.env.CAPTCHA_SECRET_KEY = FAIL_SECRET
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false } } })
    const f = siteverify({ success: false, 'error-codes': ['invalid-input-response'] })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, f)).toMatchObject({ allow: false, result: 'captcha_invalid' })
  })

  it('provider down: closed refuses, open lets through', async () => {
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false }, failMode: 'closed' } })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, siteverify('down'))).toMatchObject({ result: 'captcha_unavailable' })
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false }, failMode: 'open' } })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, siteverify('down'))).toEqual({ allow: true, result: 'fail_open' })
    // Fail-open never waives a missing answer, nor the sign-up policy.
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io' }, siteverify('down'))).toMatchObject({ result: 'captcha_missing' })
  })

  it('login: first factor only — a second-factor step or a passkey is not asked', async () => {
    store({ captcha: { flows: { registration: false, login: true, recovery: false, verification: false } } })
    const f = siteverify({ success: true })
    expect(await guardFlow({ flow: 'login', method: 'password', requestedAal: 'aal1' }, f)).toMatchObject({ result: 'captcha_missing' })
    expect(await guardFlow({ flow: 'login', method: 'totp', requestedAal: 'aal2' }, f)).toEqual({ allow: true, result: 'not_guarded' })
    expect(await guardFlow({ flow: 'login', method: 'webauthn', requestedAal: 'aal1' }, f)).toEqual({ allow: true, result: 'not_guarded' })
  })

  it('closed sign-up is refused before any provider call; policy runs after the bot check', async () => {
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false } }, registration: { mode: 'closed' } })
    const never = vi.fn() as unknown as typeof fetch
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, never)).toMatchObject({ result: 'registration_closed' })
    expect(never).not.toHaveBeenCalled()
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false } }, registration: { mode: 'allowlist', allowDomains: ['corp.io'] } })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io' }, never)).toMatchObject({ result: 'captcha_missing' })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io', captchaToken: DUMMY_TOKEN }, siteverify({ success: true }))).toMatchObject({ result: 'registration_not_allowed' })
  })

  it('settings store down with nothing cached: sign-up waits, sign-in goes on', async () => {
    h.redisDown = true
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io' })).toMatchObject({ allow: false, result: 'settings_unavailable' })
    expect(await guardFlow({ flow: 'login', method: 'password' })).toEqual({ allow: true, result: 'fail_open' })
  })

  it('settings store down after a good read: the last document keeps being enforced', async () => {
    store({ registration: { mode: 'closed' } })
    expect(await guardFlow({ flow: 'registration', email: 'a@b.io' })).toMatchObject({ result: 'registration_closed' })
    h.redisDown = true
    vi.useFakeTimers()
    vi.setSystemTime(Date.now() + 60_000)
    try {
      expect(await guardFlow({ flow: 'registration', email: 'a@b.io' })).toMatchObject({ result: 'registration_closed' })
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('routes', () => {
  let app: FastifyInstance
  const fetchSpy = vi.spyOn(globalThis, 'fetch')

  beforeAll(async () => {
    app = Fastify()
    await app.register(async (api) => {
      await api.register(webhookRoutes, { prefix: '/webhooks' })
      await api.register(signInProtectionSettingsRoutes, { prefix: '/admin/settings' })
      await api.register(signInProtectionPublicRoutes, { prefix: '/public/sign-in-protection' })
    }, { prefix: '/api' })
    await app.ready()
  })
  afterAll(async () => { await app.close(); fetchSpy.mockRestore() })
  afterEach(() => fetchSpy.mockReset())

  const hook = (body: Record<string, unknown>, secret: string | null = HOOK_SECRET) =>
    app.inject({ method: 'POST', url: '/api/webhooks/kratos/guard', headers: secret ? { 'x-kratos-webhook-secret': secret } : {}, payload: body })

  it('the hook paths answer without a session, and the two-step gate exempts them', () => {
    expect(isPublicRoute('/api/webhooks/kratos/guard')).toBe(true)
    expect(isPublicRoute('/api/public/sign-in-protection')).toBe(true)
    expect(isPublicRoute('/api/public/sign-in-protection/check')).toBe(true)
    expect(isPublicRoute('/api/admin/settings/sign-in-protection')).toBe(false)
    expect(secondFactorScope('/api/webhooks/kratos/guard')).toMatchObject({ gated: false })
    expect(secondFactorScope('/api/admin/settings/sign-in-protection')).toEqual({ gated: true })
  })

  it('hook: refuses a caller without the shared secret', async () => {
    const res = await hook({ flow: 'registration' }, 'wrong')
    expect(res.statusCode).toBe(401)
    expect((await hook({ flow: 'registration' }, null)).statusCode).toBe(401)
  })

  it('hook: allowed → 200 {}; refused → 400 in the shape Kratos turns into a form message', async () => {
    expect((await hook({ flow: 'registration', flow_type: 'api', method: 'password', email: 'a@b.io' })).json()).toEqual({})
    store({ registration: { mode: 'allowlist', allowDomains: ['corp.io'] } })
    const res = await hook({ flow: 'registration', flow_type: 'api', method: 'password', email: 'scanner@mailinator.com' })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({
      messages: [{ instance_ptr: '#/', messages: [{ id: 4000912, text: 'Sign-ups are limited to @corp.io addresses.', type: 'error' }] }],
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('hook: bot check reads captcha_token and asks the provider', async () => {
    store({ captcha: { flows: { registration: true, login: false, recovery: false, verification: false } } })
    const missing = await hook({ flow: 'registration', flow_type: 'api', method: 'password', email: 'a@b.io', captcha_token: null })
    expect(missing.statusCode).toBe(400)
    expect(missing.json().messages[0]).toMatchObject({ instance_ptr: '#/', messages: [{ id: 4000901, type: 'error' }] })
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { status: 200 }))
    const ok = await hook({ flow: 'registration', flow_type: 'browser', method: 'password', email: 'a@b.io', captcha_token: DUMMY_TOKEN, ip: '198.51.100.7, 10.0.0.1' })
    expect(ok.statusCode).toBe(200)
    const body = new URLSearchParams(fetchSpy.mock.calls[0][1]?.body as string)
    expect(body.get('remoteip')).toBe('198.51.100.7')
  })

  it('public settings: site key and flows, never the secret or the listed addresses', async () => {
    store({ captcha: { flows: { registration: true, login: true, recovery: false, verification: false } }, registration: { mode: 'allowlist', allowEmails: ['vip@gmail.com'], allowDomains: ['corp.io', '*.lab.io'] } })
    const res = await app.inject({ method: 'GET', url: '/api/public/sign-in-protection' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      captcha: { provider: 'turnstile', configured: true, siteKey: SITE_KEY, scriptUrl: expect.stringContaining('challenges.cloudflare.com'), flows: { registration: true, login: true, recovery: false, verification: false } },
      registration: { mode: 'allowlist', domains: ['corp.io'] },
    })
    expect(res.body).not.toContain(PASS_SECRET)
    expect(res.body).not.toContain('vip@gmail.com')
  })

  it('gateway check: 200 when the flow does not ask, 403 without a token, 200 with a good one', async () => {
    const check = (payload: Record<string, unknown>) => app.inject({ method: 'POST', url: '/api/public/sign-in-protection/check', payload })
    expect((await check({ flow: 'recovery', token: '' })).statusCode).toBe(200)
    store({ captcha: { flows: { registration: false, login: false, recovery: true, verification: false } } })
    const refused = await check({ flow: 'recovery', token: '' })
    expect(refused.statusCode).toBe(403)
    expect(refused.json()).toMatchObject({ error: 'captcha_missing' })
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { status: 200 }))
    expect((await check({ flow: 'recovery', token: DUMMY_TOKEN })).statusCode).toBe(200)
    expect((await check({ flow: 'registration', token: DUMMY_TOKEN })).statusCode).toBe(400)
  })

  it('gateway check: a passing token is a short pass for the flow (send email, submit code, resend), then spent', async () => {
    store({ captcha: { flows: { registration: false, login: false, recovery: true, verification: false } } })
    const check = () => app.inject({ method: 'POST', url: '/api/public/sign-in-protection/check', payload: { flow: 'recovery', token: 'tok-1' } })
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { status: 200 }))
    expect((await check()).statusCode).toBe(200)
    for (let i = 0; i < 4; i++) expect((await check()).statusCode).toBe(200)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const spent = await check()
    expect(spent.statusCode).toBe(403)
    expect(spent.json()).toMatchObject({ error: 'captcha_invalid' })
  })

  it('admin: read needs admin; write needs super_admin and a recent second factor', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/admin/settings/sign-in-protection' })).statusCode).toBe(403)
    const read = await app.inject({ method: 'GET', url: '/api/admin/settings/sign-in-protection', headers: { 'x-test-admin': '1' } })
    expect(read.json()).toMatchObject({ settings: defaultSignInProtection(), provider: { configured: true, secretSet: true }, disposableDomains: expect.any(Number) })
    expect(read.body).not.toContain(PASS_SECRET)
    const body = { captcha: defaultSignInProtection().captcha, registration: { ...defaultSignInProtection().registration, mode: 'closed' } }
    expect((await app.inject({ method: 'PUT', url: '/api/admin/settings/sign-in-protection', headers: { 'x-test-admin': '1' }, payload: body })).statusCode).toBe(403)
    expect((await app.inject({ method: 'PUT', url: '/api/admin/settings/sign-in-protection', headers: { 'x-test-write': '1' }, payload: body })).statusCode).toBe(422)
  })

  it('admin write: validated, stored, audited with before/after', async () => {
    const headers = { 'x-test-write': '1', 'x-test-mfa': '1' }
    const bad = await app.inject({ method: 'PUT', url: '/api/admin/settings/sign-in-protection', headers, payload: { captcha: {}, registration: { mode: 'allowlist', allowDomains: ['not a domain'] } } })
    expect(bad.statusCode).toBe(400)
    expect(bad.json()).toMatchObject({ error: 'invalid_settings', problems: [{ field: 'registration.allowDomains' }] })

    const payload = { captcha: { flows: { registration: true, login: false, recovery: false, verification: false }, failMode: 'closed' }, registration: { mode: 'allowlist', allowEmails: [], allowDomains: ['Corp.io'], denyDomains: [], blockDisposable: true } }
    const res = await app.inject({ method: 'PUT', url: '/api/admin/settings/sign-in-protection', headers, payload })
    expect(res.statusCode).toBe(200)
    expect(res.json().settings.registration.allowDomains).toEqual(['corp.io'])
    expect(JSON.parse(h.config[SIGN_IN_PROTECTION_KEY]).captcha.flows.registration).toBe(true)
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({
      target: 'sign-in-protection', severity: 'high',
      details: { before: defaultSignInProtection(), after: expect.objectContaining({ registration: expect.objectContaining({ mode: 'allowlist' }) }) },
    }))
  })

  it('admin write: the bot check cannot be turned on without a configured provider', async () => {
    h.env.CAPTCHA_SECRET_KEY = undefined
    const payload = { captcha: { flows: { registration: false, login: true, recovery: false, verification: false }, failMode: 'closed' }, registration: defaultSignInProtection().registration }
    const res = await app.inject({ method: 'PUT', url: '/api/admin/settings/sign-in-protection', headers: { 'x-test-write': '1', 'x-test-mfa': '1' }, payload })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toMatchObject({ error: 'captcha_not_configured', message: expect.stringContaining('CAPTCHA_SECRET_KEY') })
    expect(h.config[SIGN_IN_PROTECTION_KEY]).toBeUndefined()
  })
})
