import { describe, expect, it } from 'vitest'
import { checkedEnvSchema, envSchema } from '../../config/env.js'
import { KratosSessionService } from '../../services/kratos-session.service.js'

// Impersonation's settings: off unless asked, a cookie the session matcher can never take, a check
// URL whenever it is on, and a ceiling on how long one may last.

// ENCRYPTION_KEY is the only field without a default.
const base = { ENCRYPTION_KEY: 'x'.repeat(32) }
const parse = (over: Record<string, string> = {}) => checkedEnvSchema.safeParse({ ...base, ...over })
const messages = (r: ReturnType<typeof parse>) => (r.success ? [] : r.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`))

describe('impersonation settings', () => {
  it('is off by default, with the default cookie name and a 30 minute ceiling', () => {
    const r = parse()
    expect(r.success).toBe(true)
    expect(r.success && r.data).toMatchObject({ IMPERSONATION_ENABLED: false, IMPERSONATION_COOKIE_NAME: 'platform_impersonation', IMPERSONATION_MAX_MINUTES: 30 })
    expect(r.success && r.data.IMPERSONATION_CHECK_URL).toBeUndefined()
  })

  it('needs the check URL when it is on', () => {
    expect(messages(parse({ IMPERSONATION_ENABLED: 'true' }))).toEqual(['IMPERSONATION_CHECK_URL: IMPERSONATION_CHECK_URL is required when IMPERSONATION_ENABLED is true'])
    expect(parse({ IMPERSONATION_ENABLED: 'true', IMPERSONATION_CHECK_URL: 'http://auth-jinbe:8080/api/oathkeeper/impersonation/session' }).success).toBe(true)
    expect(parse({ IMPERSONATION_ENABLED: 'true', IMPERSONATION_CHECK_URL: 'not a url' }).success).toBe(false)
  })

  it.each(['ory_kratos_session', 'ory_kratos_session_sandbox', 'ory_kratos_session_impersonation'])('refuses the cookie name %s, which the session matcher would take', (name) => {
    expect(envSchema.shape.IMPERSONATION_COOKIE_NAME.safeParse(name).success).toBe(false)
    // What the refusal protects: such a cookie would be handed to Kratos as a session cookie.
    expect(KratosSessionService.extractSessionCookie(`${name}=x`)).not.toBeNull()
  })

  it('accepts a plain cookie name and refuses one a Cookie header or a pattern could not carry', () => {
    const name = envSchema.shape.IMPERSONATION_COOKIE_NAME
    expect(name.safeParse('support_view').success).toBe(true)
    expect(KratosSessionService.extractSessionCookie('platform_impersonation=x; support_view=y')).toBeNull()
    for (const bad of ['', 'a b', 'a;b', 'a=b', 'a.b', 'a|b']) expect(name.safeParse(bad).success, bad).toBe(false)
  })

  it('caps the ceiling at 60 minutes and never goes under 5', () => {
    const max = envSchema.shape.IMPERSONATION_MAX_MINUTES
    expect(max.safeParse('60').success).toBe(true)
    expect(max.safeParse('5').success).toBe(true)
    expect(max.safeParse('61').success).toBe(false)
    expect(max.safeParse('4').success).toBe(false)
    expect(max.safeParse('7.5').success).toBe(false)
  })
})
