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
import { classifySubmit, gateSubmit, gatewayClientIp, parseSubmitBody, submitToken, type GateFlow } from '../../sign-in-protection/gate.js'
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

  it('the token: the header first, else the transient_payload field (JSON or form)', () => {
    expect(submitToken('h', { transient_payload: { captcha_token: 'b' } })).toBe('h')
    expect(submitToken(null, { transient_payload: { captcha_token: 'b' } })).toBe('b')
    expect(submitToken(null, { 'transient_payload.captcha_token': 'f' })).toBe('f')
    expect(submitToken(null, {})).toBeNull()
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
  const OFF = { registration: false, login: false, recovery: false, verification: false }
  const noSession = async () => null
  const FLOW = '6a1f2c3d-0000-4000-8000-000000000001'
  const send = (over: Partial<Parameters<typeof gateSubmit>[0]> = {}) =>
    ({ flow: 'login' as GateFlow, flowId: FLOW, fields: { method: 'code', identifier: 'ann@corp.io' }, token: TOKEN, ip: '176.1.2.3', session: noSession, ...over })
  const ok = () => siteverify({ success: true })
  const spent = () => siteverify({ success: false, 'error-codes': ['timeout-or-duplicate'] })

  it('unset settings with a configured provider: every flow is checked', async () => {
    expect(await gateSubmit(send({ token: null }), ok())).toMatchObject({ allow: false, result: 'captcha_missing' })
  })

  it('a flow without the bot check still gets the code limits, and no provider call', async () => {
    guard(OFF)
    const f = ok()
    expect(await gateSubmit(send({ token: null }), f)).toMatchObject({ allow: true, result: 'not_guarded' })
    expect(await gateSubmit(send({ token: null, fields: { method: 'password', identifier: 'a@b.io', password: 'x' } }), f)).toMatchObject({ allow: true, result: 'passed' })
    expect(f).not.toHaveBeenCalled()
  })

  it('every submit of a checked flow needs a token — the address step, a password, a profile step — before Kratos looks anything up', async () => {
    for (const fields of [
      { method: 'identifier_first', identifier: 'ann@corp.io' },
      { method: 'password', identifier: 'ann@corp.io', password: 'pw' },
      { method: 'code', identifier: 'ann@corp.io', code: '123456' },
      { method: 'oidc', provider: 'google' },
    ]) expect(await gateSubmit(send({ token: null, fields }), ok())).toMatchObject({ allow: false, status: 403, result: 'captcha_missing' })
    expect(await gateSubmit(send({ flow: 'registration', token: null, fields: { method: 'profile', traits: { email: 'a@corp.io' } } }), ok())).toMatchObject({ allow: false, result: 'captcha_missing' })
    expect(await gateSubmit(send({ flow: 'recovery', token: null, fields: { method: 'link', email: 'a@corp.io' } }), ok())).toMatchObject({ allow: false, result: 'captcha_missing' })
    expect(await gateSubmit(send(), siteverify({ success: false, 'error-codes': ['invalid-input-response'] }))).toMatchObject({ allow: false, result: 'captcha_invalid' })
  })

  it('a solved check sends one code; the code typed after it rides on the pass; the guard hook takes the gate’s word once', async () => {
    expect(await gateSubmit(send(), ok())).toMatchObject({ allow: true, step: 'send', result: 'allowed' })
    const s = spent()
    expect(await gateSubmit(send({ fields: { method: 'code', identifier: 'ann@corp.io', code: '123456' } }), s)).toMatchObject({ allow: true, result: 'flow_pass' })
    expect(await gateSubmit(send({ fields: { method: 'code', code: '654321' } }), s)).toMatchObject({ allow: true, result: 'flow_pass' })
    expect(s).not.toHaveBeenCalled()
    expect(await guardFlow({ flow: 'login', method: 'code', captchaToken: TOKEN }, s)).toMatchObject({ allow: true, result: 'allowed' })
    expect(await guardFlow({ flow: 'login', method: 'code', captchaToken: TOKEN }, s)).toMatchObject({ allow: false, result: 'captcha_invalid' })
  })

  it('the pass never covers a second email, another address, or another flow', async () => {
    await gateSubmit(send(), ok())
    expect(await gateSubmit(send({ fields: { method: 'code', identifier: 'ann@corp.io', resend: 'code' } }), spent())).toMatchObject({ allow: false, result: 'captcha_invalid' })
    expect(await gateSubmit(send({ fields: { method: 'code', identifier: 'bob@corp.io' } }), spent())).toMatchObject({ allow: false, result: 'captcha_invalid' })
    expect(await gateSubmit(send({ fields: { method: 'code', identifier: 'bob@corp.io', code: '1' } }), spent())).toMatchObject({ allow: false })
    expect(await gateSubmit(send({ flowId: '6a1f2c3d-0000-4000-8000-000000000002', fields: { method: 'code', code: '1' } }), spent())).toMatchObject({ allow: false })
    const other = await gateSubmit(send({ token: 'OTHER.TOKEN', fields: { method: 'code', code: '1' } }), spent())
    expect(other).toMatchObject({ allow: false })
  })

  it('sign-up: the details step’s solve also sends the one code for that address', async () => {
    const reg = (fields: Record<string, unknown>) => send({ flow: 'registration', fields })
    expect(await gateSubmit(reg({ method: 'profile', traits: { email: 'ann@corp.io', name: 'Ann' } }), ok())).toMatchObject({ allow: true, step: 'other', result: 'allowed' })
    expect(await gateSubmit(reg({ method: 'code', traits: { email: 'ann@corp.io' } }), spent())).toMatchObject({ allow: true, step: 'send', result: 'flow_pass' })
    expect(await gateSubmit(reg({ method: 'code', traits: { email: 'ann@corp.io' }, code: '123456' }), spent())).toMatchObject({ allow: true, result: 'flow_pass' })
    expect(await gateSubmit(reg({ method: 'code', traits: { email: 'ann@corp.io' }, resend: 'code' }), spent())).toMatchObject({ allow: false })
  })

  it('a pass has a few uses', async () => {
    await gateSubmit(send(), ok())
    const results = []
    for (let i = 0; i < 10; i++) results.push((await gateSubmit(send({ fields: { method: 'code', code: String(i) } }), spent())).allow)
    expect(results.filter(Boolean)).toHaveLength(8)
  })

  it('a signed-in person signing in again (second factor, refresh) needs no token; other flows still do', async () => {
    const session = async () => ({ email: 'ann@corp.io' })
    expect(await gateSubmit(send({ token: null, session }))).toMatchObject({ allow: true, result: 'session' })
    expect(await gateSubmit(send({ flow: 'recovery', token: null, session, fields: { method: 'code', email: 'x@corp.io' } }), ok())).toMatchObject({ allow: false })
  })

  it('settings: an email change is checked (verification toggle) and limited; any other save is not', async () => {
    const session = async () => ({ email: 'ann@corp.io' })
    const set = (fields: Record<string, unknown>, token: string | null = null) => send({ flow: 'settings', token, session, fields })
    expect(await gateSubmit(set({ method: 'profile', traits: { email: 'ann@corp.io', name: 'A' } }))).toMatchObject({ allow: true, step: 'other', result: 'passed' })
    expect(await gateSubmit(set({ method: 'totp', totp_code: '1' }))).toMatchObject({ allow: true })
    expect(await gateSubmit(set({ method: 'profile', traits: { email: 'victim@gmail.com' } }))).toMatchObject({ allow: false, result: 'captcha_missing' })
    expect(await gateSubmit(set({ method: 'profile', traits: { email: 'victim@gmail.com' } }, TOKEN), ok())).toMatchObject({ allow: true, step: 'send', result: 'allowed' })
    guard({ ...OFF, login: true })
    expect(await gateSubmit(set({ method: 'profile', traits: { email: 'victim2@gmail.com' } }))).toMatchObject({ allow: true, result: 'not_guarded' })
  })

  it('provider down: closed refuses, open lets it through', async () => {
    guard({ recovery: true })
    const rec = send({ flow: 'recovery', fields: { method: 'code', email: 'c@x.io' } })
    expect(await gateSubmit(rec, siteverify('down'))).toMatchObject({ allow: false, result: 'captcha_unavailable', status: 403 })
    guard({ recovery: true }, 'open')
    expect(await gateSubmit(rec, siteverify('down'))).toMatchObject({ allow: true, result: 'fail_open' })
  })

  it('a code sign-up the policy refuses is refused before any code is sent', async () => {
    const d = defaultSignInProtection()
    h.config[SIGN_IN_PROTECTION_KEY] = JSON.stringify({ ...d, captcha: { ...d.captcha, flows: OFF }, registration: { ...d.registration, mode: 'allowlist', allowDomains: ['corp.io'] } })
    resetSignInProtectionCache()
    const reg = (email: string) => send({ flow: 'registration', fields: { method: 'code', traits: { email } } })
    expect(await gateSubmit(reg('victim@gmail.com'))).toMatchObject({ allow: false, status: 403, result: 'registration_not_allowed', message: expect.stringMatching(/@corp\.io/) })
    expect(await gateSubmit(reg('ann@corp.io'))).toMatchObject({ allow: true })
  })

  it('5 codes per address and 20 per IP per window, with the wait', async () => {
    guard(OFF)
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

  it('a refused bot check does not use up the address budget', async () => {
    for (let i = 0; i < 10; i++) await gateSubmit(send({ token: null }))
    expect(await gateSubmit(send(), ok())).toMatchObject({ allow: true })
  })

  it('Redis down: no pass and no limits, the bot check still applies to every submit', async () => {
    h.redisDown = true
    expect(await gateSubmit(send({ token: null }))).toMatchObject({ allow: false, result: 'captcha_missing' })
    for (let i = 0; i < 8; i++) expect((await gateSubmit(send(), ok())).allow).toBe(true)
    expect(await gateSubmit(send({ fields: { method: 'code', code: '1' } }), spent())).toMatchObject({ allow: false })
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
    guard({ registration: false, login: false, recovery: false, verification: false })
    h.env.SIGN_IN_GATE_CODES_PER_ADDRESS = 1
    expect((await post('recovery', { method: 'code', email: 'c@x.io' })).statusCode).toBe(400)
    const res = await post('recovery', { method: 'code', email: 'c@x.io' })
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('900')
    expect(res.json().error).toMatchObject({ id: 'rate_limited', retry_after: 900 })
    expect(seen).toHaveLength(1)
  })

  it('a native form post (passkey) carries the token in transient_payload.captcha_token', async () => {
    guard({ login: true })
    const form = (payload: string) => app.inject({
      method: 'POST', url: '/api/public/sign-in-protection/gate/self-service/login?flow=f-passkey-1',
      headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload,
    })
    expect((await form('method=passkey&passkey_login=x')).statusCode).toBe(403)
    expect((await form(`method=passkey&passkey_login=x&transient_payload.captcha_token=${TOKEN}`)).statusCode).toBe(400)
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
    expect((await post('sessions', { method: 'profile' })).statusCode).toBe(404)
    expect(seen).toHaveLength(1)
  })

  it('Kratos unreachable: 502, not a hang', async () => {
    guard({ registration: false, login: false, recovery: false, verification: false })
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
    for (const flow of ['login', 'registration', 'recovery', 'verification', 'settings']) {
      expect(matching(rules, 'POST', `https://auth.example.com/self-service/${flow}`)).toEqual(['selfservice-gate'])
      expect(matching(rules, 'GET', `https://auth.example.com/self-service/${flow}/browser`)).toEqual(['kratos-public'])
    }
    for (const path of ['self-service/methods/oidc/callback/apple', 'self-service/fed-cm/token', 'sessions/token-exchange']) {
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
