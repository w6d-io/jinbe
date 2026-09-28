import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import http from 'node:http'
import type { AddressInfo } from 'node:net'

// The sign-in gate: self-service submits judged before Kratos (bot-check token, code limits), then
// replayed to Kratos as they came.

const h = vi.hoisted(() => ({
  config: {} as Record<string, string>,
  env: {} as Record<string, unknown>,
  kv: new Map<string, { v: string; exp?: number }>(),
  redisDown: false,
  rules: [] as Array<{ id: string }>,
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in h.env ? h.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getConfig: vi.fn(async () => ({ ...h.config })),
    setConfig: vi.fn(async (k: string, v: string) => { h.config[k] = v }),
    getAccessRules: vi.fn(async () => h.rules),
    setAccessRules: vi.fn(async (r: Array<{ id: string }>) => { h.rules = r }),
  },
}))
vi.mock('../../services/redis-client.service.js', () => {
  const up = () => { if (h.redisDown) throw new Error('ECONNREFUSED') }
  return {
    getRedisClient: () => ({
      get: async (k: string) => { up(); return h.kv.get(k)?.v ?? null },
      set: async (k: string, v: string, _ex?: string, s?: number) => { up(); h.kv.set(k, { v, exp: s }); return 'OK' },
      del: async (k: string) => { up(); return h.kv.delete(k) ? 1 : 0 },
      exists: async (k: string) => { up(); return h.kv.has(k) ? 1 : 0 },
      incr: async (k: string) => { up(); const e = h.kv.get(k); const v = Number(e?.v ?? 0) + 1; h.kv.set(k, { v: String(v), exp: e?.exp }); return v },
      expire: async (k: string, s: number) => { up(); const e = h.kv.get(k); if (e) e.exp = s; return 1 },
      ttl: async (k: string) => { up(); return h.kv.get(k)?.exp ?? -1 },
    }),
  }
})

import { signInGateRoutes } from '../../sign-in-protection/gate-routes.js'
import { classifySubmit, gateSubmit, gatewayClientIp, parseSubmitBody } from '../../sign-in-protection/gate.js'
import { guardFlow } from '../../sign-in-protection/guard.js'
import { SIGN_IN_PROTECTION_KEY, defaultSignInProtection, resetSignInProtectionCache, type CaptchaFlow } from '../../sign-in-protection/settings.js'
import { buildBuiltInRules } from '../../bootstrap/build-rules.js'
import { upsertBuiltInRules } from '../../bootstrap/upsert-rules.js'
import { isPublicRoute } from '../../middleware/require-auth.js'

const PASS_SECRET = '1x0000000000000000000000000000000AA'
const SITE_KEY = '1x00000000000000000000AA'
const TOKEN = 'XXXX.DUMMY.TOKEN.XXXX'

function guard(flows: Partial<Record<CaptchaFlow, boolean>>, failMode: 'closed' | 'open' = 'closed') {
  const d = defaultSignInProtection()
  h.config[SIGN_IN_PROTECTION_KEY] = JSON.stringify({ ...d, captcha: { flows: { ...d.captcha.flows, ...flows }, failMode } })
  resetSignInProtectionCache()
}

function siteverify(answer: Record<string, unknown> | 'down') {
  return vi.fn(async () => {
    if (answer === 'down') throw new TypeError('fetch failed')
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>
}

beforeEach(() => {
  h.config = {}
  h.kv.clear()
  h.redisDown = false
  h.env = { CAPTCHA_SITE_KEY: SITE_KEY, CAPTCHA_SECRET_KEY: PASS_SECRET }
  resetSignInProtectionCache()
})

describe('what a submit is', () => {
  it('a code or link asked for is a send; a code typed, a password, a profile step are not', () => {
    expect(classifySubmit('login', { method: 'code', identifier: ' Ann@Corp.io ' })).toEqual({ step: 'send', address: 'ann@corp.io' })
    expect(classifySubmit('login', { method: 'code', identifier: 'ann@corp.io', code: '123456' }).step).toBe('other')
    expect(classifySubmit('login', { method: 'code', identifier: 'ann@corp.io', code: '123456', resend: 'code' }).step).toBe('send')
    expect(classifySubmit('login', { method: 'identifier_first', identifier: 'ann@corp.io' }).step).toBe('send')
    expect(classifySubmit('login', { method: 'password', identifier: 'ann@corp.io', password: 'x' }).step).toBe('other')
    expect(classifySubmit('login', { method: 'oidc', provider: 'google' }).step).toBe('other')
    expect(classifySubmit('registration', { method: 'code', traits: { email: 'Bob@x.io' } })).toEqual({ step: 'send', address: 'bob@x.io' })
    expect(classifySubmit('registration', { method: 'code', 'traits.email': 'bob@x.io' }).address).toBe('bob@x.io')
    expect(classifySubmit('registration', { method: 'profile', traits: { email: 'bob@x.io' } }).step).toBe('other')
    expect(classifySubmit('recovery', { method: 'code', email: 'c@x.io' })).toEqual({ step: 'send', address: 'c@x.io' })
    expect(classifySubmit('recovery', { method: 'code', code: '000000' }).step).toBe('other')
    expect(classifySubmit('verification', { method: 'link', email: 'd@x.io' }).step).toBe('send')
  })

  it('an unreadable submit is judged as a send', () => {
    expect(classifySubmit('login', {}).step).toBe('send')
    expect(classifySubmit('login', { method: 'something-new' }).step).toBe('send')
    expect(parseSubmitBody('application/json', Buffer.from('{nope'))).toEqual({})
    expect(parseSubmitBody('text/plain', Buffer.from('method=password'))).toEqual({})
  })

  it('reads JSON and form bodies', () => {
    expect(parseSubmitBody('application/json; charset=utf-8', Buffer.from('{"method":"code","identifier":"a@b.io"}'))).toEqual({ method: 'code', identifier: 'a@b.io' })
    expect(parseSubmitBody('application/x-www-form-urlencoded', Buffer.from('method=code&traits.email=a%40b.io&method=password'))).toEqual({ method: 'code', 'traits.email': 'a@b.io' })
  })

  it('the client IP is the edge one, never the first X-Forwarded-For entry the client wrote', () => {
    expect(gatewayClientIp({ 'x-envoy-external-address': '176.1.2.3', 'x-forwarded-for': '1.2.3.4,176.1.2.3' }, '10.0.0.1')).toBe('176.1.2.3')
    expect(gatewayClientIp({ 'x-forwarded-for': '1.2.3.4, 176.1.2.3' }, '10.0.0.1')).toBe('176.1.2.3')
    expect(gatewayClientIp({}, '10.0.0.1')).toBe('10.0.0.1')
  })
})

describe('gate decisions', () => {
  const noSession = async () => false
  const send = (over: Partial<Parameters<typeof gateSubmit>[0]> = {}) =>
    ({ flow: 'login' as CaptchaFlow, fields: { method: 'code', identifier: 'ann@corp.io' }, token: TOKEN, ip: '176.1.2.3', hasSession: noSession, ...over })

  it('a flow without the bot check still gets the code limits', async () => {
    const f = siteverify({ success: true })
    expect(await gateSubmit(send({ token: null }), f)).toMatchObject({ allow: true, result: 'not_guarded' })
    expect(f).not.toHaveBeenCalled()
  })

  it('a guarded send needs a token the provider accepts, spent here and left verified for the hook', async () => {
    guard({ login: true })
    expect(await gateSubmit(send({ token: null }), siteverify({ success: true }))).toMatchObject({ allow: false, status: 403, result: 'captcha_missing' })
    expect(await gateSubmit(send(), siteverify({ success: false, 'error-codes': ['invalid-input-response'] }))).toMatchObject({ allow: false, result: 'captcha_invalid' })

    expect(await gateSubmit(send(), siteverify({ success: true }))).toMatchObject({ allow: true, result: 'allowed' })
    // The provider would now refuse the token (timeout-or-duplicate); the hook takes the gate's word, once.
    const spent = siteverify({ success: false, 'error-codes': ['timeout-or-duplicate'] })
    expect(await guardFlow({ flow: 'login', method: 'code', captchaToken: TOKEN }, spent)).toMatchObject({ allow: true, result: 'allowed' })
    expect(spent).not.toHaveBeenCalled()
    expect(await guardFlow({ flow: 'login', method: 'code', captchaToken: TOKEN }, spent)).toMatchObject({ allow: false, result: 'captcha_invalid' })
  })

  it('a token verified for one flow is not a pass for another', async () => {
    guard({ login: true, registration: true })
    await gateSubmit(send(), siteverify({ success: true }))
    const spent = siteverify({ success: false, 'error-codes': ['timeout-or-duplicate'] })
    expect(await guardFlow({ flow: 'registration', method: 'code', captchaToken: TOKEN, traits: { email: 'a@b.io' } }, spent)).toMatchObject({ allow: false })
  })

  it('a code typed or a password goes on without a token', async () => {
    guard({ login: true })
    expect(await gateSubmit(send({ token: null, fields: { method: 'code', identifier: 'ann@corp.io', code: '123456' } }))).toMatchObject({ allow: true, step: 'other' })
    expect(await gateSubmit(send({ token: null, fields: { method: 'password', identifier: 'ann@corp.io', password: 'pw' } }))).toMatchObject({ allow: true, step: 'other' })
  })

  it('a signed-in person (second factor, refresh) needs no token', async () => {
    guard({ login: true })
    expect(await gateSubmit(send({ token: null, hasSession: async () => true }))).toMatchObject({ allow: true, result: 'session' })
  })

  it('provider down: closed refuses, open lets it through', async () => {
    guard({ recovery: true })
    const rec = send({ flow: 'recovery', fields: { method: 'code', email: 'c@x.io' } })
    expect(await gateSubmit(rec, siteverify('down'))).toMatchObject({ allow: false, result: 'captcha_unavailable', status: 403 })
    guard({ recovery: true }, 'open')
    expect(await gateSubmit(rec, siteverify('down'))).toMatchObject({ allow: true, result: 'fail_open' })
  })

  it('5 codes per address and 20 per IP per window, with the wait', async () => {
    h.env.SIGN_IN_GATE_CODES_PER_ADDRESS = 5
    h.env.SIGN_IN_GATE_CODES_PER_IP = 20
    for (let i = 0; i < 5; i++) expect((await gateSubmit(send())).allow).toBe(true)
    const sixth = await gateSubmit(send())
    expect(sixth).toMatchObject({ allow: false, status: 429, result: 'rate_limited', retryAfter: 900 })
    expect(!sixth.allow && sixth.message).toMatch(/this address.*15 minutes/)

    for (let i = 0; i < 14; i++) expect((await gateSubmit(send({ fields: { method: 'code', identifier: `u${i}@corp.io` } }))).allow).toBe(true)
    const byIp = await gateSubmit(send({ fields: { method: 'code', identifier: 'fresh@corp.io' } }))
    expect(byIp).toMatchObject({ allow: false, status: 429 })
    expect(!byIp.allow && byIp.message).toMatch(/your network/)
    expect((await gateSubmit(send({ ip: '176.9.9.9', fields: { method: 'code', identifier: 'other@corp.io' } }))).allow).toBe(true)
  })

  it('a code sign-up the policy refuses is refused before any code is sent', async () => {
    const d = defaultSignInProtection()
    h.config[SIGN_IN_PROTECTION_KEY] = JSON.stringify({ ...d, registration: { ...d.registration, mode: 'allowlist', allowDomains: ['corp.io'] } })
    resetSignInProtectionCache()
    const reg = (email: string) => send({ flow: 'registration', fields: { method: 'code', traits: { email } } })
    expect(await gateSubmit(reg('victim@gmail.com'))).toMatchObject({ allow: false, status: 403, result: 'registration_not_allowed', message: expect.stringMatching(/@corp\.io/) })
    expect(await gateSubmit(reg('ann@corp.io'))).toMatchObject({ allow: true })
  })

  it('a refused bot check does not use up the address budget', async () => {
    guard({ login: true })
    for (let i = 0; i < 10; i++) await gateSubmit(send({ token: null }))
    expect(await gateSubmit(send(), siteverify({ success: true }))).toMatchObject({ allow: true })
  })

  it('Redis down: the limits are skipped, the bot check still applies', async () => {
    guard({ login: true })
    h.redisDown = true
    expect(await gateSubmit(send({ token: null }))).toMatchObject({ allow: false, result: 'captcha_missing' })
    for (let i = 0; i < 8; i++) expect((await gateSubmit(send(), siteverify({ success: true }))).allow).toBe(true)
  })
})

describe('gate route (proxy to Kratos)', () => {
  let app: FastifyInstance
  let kratos: http.Server
  const seen: Array<{ method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string }> = []
  let provider = siteverify({ success: true })

  beforeAll(async () => {
    kratos = http.createServer((req, res) => {
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, body })
        res.setHeader('set-cookie', ['csrf_token_x=1; Path=/', 'ory_kratos_session=2; Path=/'])
        res.writeHead(400, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ id: 'flow-1', ui: { messages: [] } }))
      })
    })
    await new Promise<void>((r) => kratos.listen(0, '127.0.0.1', () => r()))
    const port = (kratos.address() as AddressInfo).port
    app = Fastify()
    await app.register(signInGateRoutes, {
      prefix: '/api/public/sign-in-protection/gate',
      fetchImpl: ((...a: Parameters<typeof fetch>) => provider(...a)) as typeof fetch,
      kratosUrl: `http://127.0.0.1:${port}`,
    })
    await app.ready()
  })
  afterAll(async () => { await app.close(); await new Promise((r) => kratos.close(r)) })
  beforeEach(() => { seen.length = 0; provider = siteverify({ success: true }) })

  const post = (flow: string, body: unknown, headers: Record<string, string> = {}) => app.inject({
    method: 'POST',
    url: `/api/public/sign-in-protection/gate/self-service/${flow}?flow=abc`,
    headers: { 'content-type': 'application/json', host: 'auth.example.com', 'x-envoy-external-address': '176.1.2.3', ...headers },
    payload: JSON.stringify(body),
  })

  it('is on the public list (no session needed to sign in)', () => {
    expect(isPublicRoute('/api/public/sign-in-protection/gate/self-service/login')).toBe(true)
  })

  it('an allowed submit reaches Kratos as sent, minus the token; Kratos answers as is', async () => {
    guard({ login: true })
    const res = await post('login', { method: 'code', identifier: 'ann@corp.io', csrf_token: 'c' }, { 'x-captcha-token': TOKEN, cookie: 'csrf_token_x=1', accept: 'application/json' })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({ id: 'flow-1', ui: { messages: [] } })
    expect(res.headers['set-cookie']).toEqual(['csrf_token_x=1; Path=/', 'ory_kratos_session=2; Path=/'])
    expect(seen).toHaveLength(1)
    expect(seen[0]).toMatchObject({ method: 'POST', url: '/self-service/login?flow=abc', body: '{"method":"code","identifier":"ann@corp.io","csrf_token":"c"}' })
    expect(seen[0].headers).toMatchObject({ host: 'auth.example.com', cookie: 'csrf_token_x=1', accept: 'application/json' })
    expect(seen[0].headers['x-captcha-token']).toBeUndefined()
  })

  it('a refused submit never reaches Kratos: 403 in the Kratos error shape', async () => {
    guard({ registration: true })
    const res = await post('registration', { method: 'code', traits: { email: 'a@b.io' } })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: { id: 'captcha_missing', code: 403, message: expect.stringMatching(/bot check/) } })
    expect(seen).toHaveLength(0)
  })

  it('over the limit: 429 with Retry-After', async () => {
    h.env.SIGN_IN_GATE_CODES_PER_ADDRESS = 1
    expect((await post('recovery', { method: 'code', email: 'c@x.io' })).statusCode).toBe(400)
    const res = await post('recovery', { method: 'code', email: 'c@x.io' })
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('900')
    expect(res.json().error).toMatchObject({ id: 'rate_limited', retry_after: 900 })
    expect(seen).toHaveLength(1)
  })

  it('form posts are read and forwarded untouched; unknown flows are not proxied', async () => {
    guard({ verification: true })
    const res = await app.inject({
      method: 'POST', url: '/api/public/sign-in-protection/gate/self-service/verification?flow=v',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-captcha-token': TOKEN },
      payload: 'method=link&email=d%40x.io',
    })
    expect(res.statusCode).toBe(400)
    expect(seen[0]).toMatchObject({ url: '/self-service/verification?flow=v', body: 'method=link&email=d%40x.io' })
    expect((await post('settings', { method: 'profile' })).statusCode).toBe(404)
    expect(seen).toHaveLength(1)
  })

  it('Kratos unreachable: 502, not a hang', async () => {
    const down = Fastify()
    await down.register(signInGateRoutes, { prefix: '/g', kratosUrl: 'http://127.0.0.1:1' })
    const res = await down.inject({ method: 'POST', url: '/g/self-service/login?flow=x', headers: { 'content-type': 'application/json' }, payload: '{"method":"password"}' })
    expect(res.statusCode).toBe(502)
    await down.close()
  })
})

describe('bootstrap rules with the gate', () => {
  const urls = { kratosPublic: 'http://kratos-public:80', kratosAdmin: 'x', loginUi: 'http://ui:80', adminUi: 'http://kuma:80', jinbeInternal: 'http://jinbe:8080' }
  const domains = { auth: 'auth.example.com', app: 'kuma.example.com', api: 'api.example.com' }
  // Oathkeeper's regexp strategy: text outside <…> is literal, inside is a regex; matched on scheme://host/path.
  const toRegex = (u: string) =>
    new RegExp(`^${u.split(/(<[^>]*>)/).map((p) => (p.startsWith('<') ? p.slice(1, -1) : p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`)
  const matching = (rules: ReturnType<typeof buildBuiltInRules>, method: string, url: string) =>
    rules.filter((r) => r.match.methods.includes(method) && toRegex(r.match.url).test(url)).map((r) => r.id)

  it('off: Kratos gets every self-service POST directly, as before', () => {
    const rules = buildBuiltInRules({ domains, urls })
    expect(rules.map((r) => r.id)).not.toContain('selfservice-gate')
    expect(matching(rules, 'POST', 'https://auth.example.com/self-service/login')).toEqual(['kratos-public'])
  })

  it('on: exactly one rule per request; the four code-sending flows go through jinbe', () => {
    const rules = buildBuiltInRules({ domains, urls, signInGate: true })
    const gate = rules.find((r) => r.id === 'selfservice-gate')!
    expect(gate.upstream).toEqual({ url: 'http://jinbe:8080/api/public/sign-in-protection/gate', preserve_host: true })
    for (const flow of ['login', 'registration', 'recovery', 'verification']) {
      expect(matching(rules, 'POST', `https://auth.example.com/self-service/${flow}`)).toEqual(['selfservice-gate'])
      expect(matching(rules, 'GET', `https://auth.example.com/self-service/${flow}/browser`)).toEqual(['kratos-public'])
    }
    for (const path of ['self-service/settings', 'self-service/methods/oidc/callback/apple', 'self-service/fed-cm/token', 'sessions/token-exchange']) {
      expect(matching(rules, 'POST', `https://auth.example.com/${path}`)).toEqual(['selfservice-kratos-post'])
    }
    expect(matching(rules, 'OPTIONS', 'https://auth.example.com/self-service/login')).toEqual(['kratos-public'])
    expect(matching(rules, 'DELETE', 'https://auth.example.com/sessions/abc')).toEqual(['kratos-public'])
    // No other way to POST to Kratos on the sign-in domain.
    expect(matching(rules, 'POST', 'https://auth.example.com/self-service/logout')).toEqual([])
  })

  it('turned off again, the gate rules leave Redis (kept, they would overlap kratos-public); custom rules stay', async () => {
    const log = { info: () => {} } as unknown as Parameters<typeof upsertBuiltInRules>[1]
    h.rules = [{ id: 'my-app' }]
    await upsertBuiltInRules(buildBuiltInRules({ domains, urls, signInGate: true }), log)
    expect(h.rules.map((r) => r.id)).toEqual(expect.arrayContaining(['selfservice-gate', 'selfservice-kratos-post', 'my-app']))
    await upsertBuiltInRules(buildBuiltInRules({ domains, urls }), log)
    expect(h.rules.map((r) => r.id)).not.toContain('selfservice-gate')
    expect(h.rules.map((r) => r.id)).not.toContain('selfservice-kratos-post')
    expect(h.rules.map((r) => r.id)).toContain('my-app')
  })
})
