import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// Protected identity traits: values the gateway forwards as trusted headers (x-person-uuid,
// x-applicant-uuid) that nobody may set on themselves — refused or put back by the Kratos guard hook.

const h = vi.hoisted(() => ({ config: {} as Record<string, string>, env: {} as Record<string, unknown> }))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in h.env ? h.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getConfig: vi.fn(async () => ({ ...h.config })), setConfig: vi.fn() },
}))
vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))

import { envSchema } from '../../config/env.js'
import { webhookRoutes } from '../../routes/webhook.routes.js'
import { signInProtectionPublicRoutes } from '../../sign-in-protection/routes.js'
import { GUARD_MESSAGE_IDS } from '../../sign-in-protection/guard.js'
import { registrationTraitsVerdict, settingsTraitsVerdict } from '../../sign-in-protection/protected-traits.js'
import { SIGN_IN_PROTECTION_KEY, defaultSignInProtection, resetSignInProtectionCache } from '../../sign-in-protection/settings.js'

const HOOK_SECRET = 'hook-secret-for-tests'
const NAMES = ['person_uuid', 'applicant_uuid']
const VICTIM = '7d0b6a4e-5f1c-4a8e-9b61-2f4d3c1e0a99'

beforeEach(() => {
  h.config = {}
  h.env = { KRATOS_WEBHOOK_SECRET: HOOK_SECRET, CAPTCHA_SITE_KEY: undefined, CAPTCHA_SECRET_KEY: undefined }
  resetSignInProtectionCache()
})

describe('PROTECTED_TRAITS', () => {
  const parse = (v?: string) => envSchema.shape.PROTECTED_TRAITS.safeParse(v)
  it('defaults to the two ids the gateway forwards; trims and dedupes; empty protects nothing', () => {
    expect(parse(undefined)).toMatchObject({ success: true, data: NAMES })
    expect(parse(' person_uuid , org_ref,person_uuid ')).toMatchObject({ success: true, data: ['person_uuid', 'org_ref'] })
    expect(parse('')).toMatchObject({ success: true, data: [] })
  })
  it('refuses the sign-up identifier and anything that is not a trait name', () => {
    expect(parse('person_uuid,email').success).toBe(false)
    expect(parse('traits.person_uuid').success).toBe(false)
  })
})

describe('sign-up', () => {
  it('only what a person knows goes through untouched', () => {
    expect(registrationTraitsVerdict({ email: 'a@b.io', name: 'Ada' }, NAMES)).toEqual({ ok: true })
  })
  it('a protected trait with a value is refused, whatever the form showed', () => {
    expect(registrationTraitsVerdict({ email: 'a@b.io', person_uuid: VICTIM }, NAMES)).toEqual({ ok: false, reason: 'protected_trait', keys: ['person_uuid'] })
    expect(registrationTraitsVerdict({ email: 'a@b.io', applicant_uuid: 0 }, NAMES)).toMatchObject({ ok: false, keys: ['applicant_uuid'] })
    expect(registrationTraitsVerdict({ email: 'a@b.io', person_uuid: { id: VICTIM } }, NAMES)).toMatchObject({ ok: false })
  })
  it('an empty one (an older form) is dropped from what Kratos writes', () => {
    expect(registrationTraitsVerdict({ email: 'a@b.io', name: 'Ada', person_uuid: '', applicant_uuid: null }, NAMES))
      .toEqual({ ok: true, traits: { email: 'a@b.io', name: 'Ada' } })
  })
  it('no traits to look at: not checked, so refused; nothing protected: nothing to check', () => {
    expect(registrationTraitsVerdict(undefined, NAMES)).toEqual({ ok: false, reason: 'unchecked' })
    expect(registrationTraitsVerdict(['x'], NAMES)).toEqual({ ok: false, reason: 'unchecked' })
    expect(registrationTraitsVerdict(undefined, [])).toEqual({ ok: true })
  })
})

describe('profile save', () => {
  const stored = { email: 'a@b.io', name: 'Ada', person_uuid: 'mine' }
  it('same values (the form sends them back unchanged) go through', () => {
    expect(settingsTraitsVerdict({ ...stored, name: 'Ada L.' }, stored, NAMES)).toEqual({ ok: true })
  })
  it('a new or changed value is refused — setting one where there was none included', () => {
    expect(settingsTraitsVerdict({ ...stored, person_uuid: VICTIM }, stored, NAMES)).toEqual({ ok: false, reason: 'protected_trait', keys: ['person_uuid'] })
    expect(settingsTraitsVerdict({ ...stored, applicant_uuid: VICTIM }, stored, NAMES)).toMatchObject({ ok: false, keys: ['applicant_uuid'] })
  })
  it('left out or emptied is put back to the stored value, never wiped', () => {
    expect(settingsTraitsVerdict({ email: 'a@b.io', name: 'Ada L.' }, stored, NAMES)).toEqual({ ok: true, traits: { email: 'a@b.io', name: 'Ada L.', person_uuid: 'mine' } })
    expect(settingsTraitsVerdict({ ...stored, person_uuid: '', applicant_uuid: '' }, stored, NAMES)).toEqual({ ok: true, traits: stored })
  })
  it('without the stored traits it cannot compare: refused', () => {
    expect(settingsTraitsVerdict(stored, undefined, NAMES)).toEqual({ ok: false, reason: 'unchecked' })
  })
})

describe('guard hook', () => {
  let app: FastifyInstance
  beforeAll(async () => {
    app = Fastify()
    await app.register(async (api) => {
      await api.register(webhookRoutes, { prefix: '/webhooks' })
      await api.register(signInProtectionPublicRoutes, { prefix: '/public/sign-in-protection' })
    }, { prefix: '/api' })
    await app.ready()
  })
  afterAll(() => app.close())

  const hook = (body: Record<string, unknown>, secret = HOOK_SECRET) =>
    app.inject({ method: 'POST', url: '/api/webhooks/kratos/guard', headers: { 'x-kratos-webhook-secret': secret }, payload: body })
  const reg = (traits: unknown) => hook({ flow: 'registration', flow_type: 'api', method: 'code', email: 'a@b.io', traits })

  it('sign-up with a protected trait: 400, a form-level message Kratos shows', async () => {
    const res = await reg({ email: 'a@b.io', person_uuid: VICTIM })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({
      messages: [{ instance_ptr: '#/', messages: [{ id: GUARD_MESSAGE_IDS.protected_trait, text: expect.stringContaining('only an administrator'), type: 'error' }] }],
    })
    expect(res.body).not.toContain(VICTIM)
  })

  it('refused before the sign-up policy and the bot check are asked', async () => {
    h.config[SIGN_IN_PROTECTION_KEY] = JSON.stringify({ ...defaultSignInProtection(), captcha: { flows: { registration: true, login: false, recovery: false, verification: false }, failMode: 'closed' } })
    const res = await reg({ email: 'a@b.io', applicant_uuid: VICTIM })
    expect(res.json().messages[0].messages[0].id).toBe(GUARD_MESSAGE_IDS.protected_trait)
  })

  it('sign-up: clean → 200 {}; empty protected fields → 200 with the traits to write instead', async () => {
    expect((await reg({ email: 'a@b.io', name: 'Ada' })).json()).toEqual({})
    const res = await reg({ email: 'a@b.io', person_uuid: '' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ identity: { traits: { email: 'a@b.io' } } })
  })

  it('sign-up body without traits (an older chart Jsonnet): refused, not waved through', async () => {
    const res = await hook({ flow: 'registration', flow_type: 'browser', method: 'code', email: 'a@b.io' })
    expect(res.statusCode).toBe(400)
    expect(res.json().messages[0].messages[0].id).toBe(GUARD_MESSAGE_IDS.protected_traits_unchecked)
  })

  it('login and the other flows do not need traits', async () => {
    expect((await hook({ flow: 'login', flow_type: 'browser', method: 'password' })).json()).toEqual({})
  })

  it('profile save: changed → 400; dropped → put back; unchanged → {}', async () => {
    const stored_traits = { email: 'a@b.io', person_uuid: 'mine' }
    const changed = await hook({ flow: 'settings', method: 'profile', traits: { email: 'a@b.io', person_uuid: VICTIM }, stored_traits })
    expect(changed.statusCode).toBe(400)
    expect(changed.json().messages[0].messages[0]).toMatchObject({ id: GUARD_MESSAGE_IDS.protected_trait, type: 'error' })
    const dropped = await hook({ flow: 'settings', method: 'profile', traits: { email: 'b@b.io' }, stored_traits })
    expect(dropped.json()).toEqual({ identity: { traits: { email: 'b@b.io', person_uuid: 'mine' } } })
    expect((await hook({ flow: 'settings', method: 'profile', traits: stored_traits, stored_traits })).json()).toEqual({})
  })

  it('profile save still needs the shared secret', async () => {
    expect((await hook({ flow: 'settings', traits: {}, stored_traits: {} }, 'wrong')).statusCode).toBe(401)
  })

  it('public settings name the protected traits for login-ui', async () => {
    h.env.PROTECTED_TRAITS = ['person_uuid', 'applicant_uuid', 'org_ref']
    const res = await app.inject({ method: 'GET', url: '/api/public/sign-in-protection' })
    expect(res.json().protectedTraits).toEqual(['person_uuid', 'applicant_uuid', 'org_ref'])
  })
})
