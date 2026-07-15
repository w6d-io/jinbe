import { describe, it, expect } from 'vitest'
import { envSchema } from '../../config/env.js'
import {
  checkAdminPasswordHardening,
  MIN_ADMIN_PASSWORD_LENGTH,
  WEAK_ADMIN_PASSWORD_PREFIX,
} from '../../cli/bootstrap-guards.js'

/**
 * The admin-password hardening lives in two places that must stay in sync:
 *   - src/config/env.ts             (zod schema, refuses to load env at all)
 *   - src/cli/bootstrap.ts          (runtime guard, defence-in-depth)
 *
 * These tests pin BOTH layers so a future loosening of one without the
 * other is caught in CI.
 */

// Minimum env required to pass the rest of envSchema (mirrors __tests__/setup.ts).
const baseEnv = {
  NODE_ENV: 'test',
  ENCRYPTION_KEY: 'test-encryption-key-32-chars-long',
  APP_NAME: 'jinbe',
  KRATOS_PUBLIC_URL: 'http://localhost:4433',
  KRATOS_ADMIN_URL: 'http://localhost:4434',
  OPA_URL: 'http://localhost:8181',
  ADMIN_EMAIL: 'admin@example.org',
} as const

describe('envSchema ADMIN_PASSWORD validation', () => {
  it('accepts a strong password (>= 16 chars, no weak prefix)', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'Tr0ub4dor&3-corr3ct' })
    expect(res.success).toBe(true)
  })

  it('rejects a password shorter than 16 chars', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'short-pw' })
    expect(res.success).toBe(false)
    if (!res.success) {
      const issues = res.error.issues.filter((i) => i.path[0] === 'ADMIN_PASSWORD')
      expect(issues.length).toBeGreaterThan(0)
    }
  })

  it('rejects exactly 15 chars (boundary)', () => {
    const fifteen = 'aB3!aB3!aB3!aB3' // 15 chars
    expect(fifteen.length).toBe(15)
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: fifteen })
    expect(res.success).toBe(false)
  })

  it('accepts exactly 16 chars when not a weak prefix (boundary)', () => {
    const sixteen = 'aB3!aB3!aB3!aB3!' // 16 chars
    expect(sixteen.length).toBe(16)
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: sixteen })
    expect(res.success).toBe(true)
  })

  it('rejects "changeme123!" (too short AND weak prefix)', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'changeme123!' })
    expect(res.success).toBe(false)
  })

  it('rejects "password1234" (12 chars, weak prefix)', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'password1234' })
    expect(res.success).toBe(false)
  })

  it('rejects a 16+ char string that still starts with "changeme"', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'changeme-and-then-some-padding',
    })
    expect(res.success).toBe(false)
  })

  it('rejects "admin" prefix case-insensitively', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'AdminPasswordWithEnoughChars1!',
    })
    expect(res.success).toBe(false)
  })

  it('rejects "PASSWORD" prefix (case-insensitive)', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'PASSWORD-with-lots-of-extra-chars',
    })
    expect(res.success).toBe(false)
  })

  it('rejects "123" prefix', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: '123-this-is-still-bad-even-long',
    })
    expect(res.success).toBe(false)
  })

  it('accepts an empty value (ADMIN_PASSWORD is optional)', () => {
    const res = envSchema.safeParse({ ...baseEnv })
    expect(res.success).toBe(true)
  })

  it('regression: previously-valid strong password remains valid', () => {
    // Sanity check: a realistic Vault-generated secret must still pass.
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'xK8#mP2$qR9!nL5@vT7&',
    })
    expect(res.success).toBe(true)
  })
})

describe('bootstrap CLI runtime guard (checkAdminPasswordHardening)', () => {
  it('returns null when password is undefined', () => {
    expect(checkAdminPasswordHardening(undefined)).toBeNull()
  })

  it('returns null when password is acceptable', () => {
    expect(checkAdminPasswordHardening('xK8#mP2$qR9!nL5@vT7&')).toBeNull()
  })

  it('flags tooShort for a 12-char password', () => {
    const res = checkAdminPasswordHardening('aB3!aB3!aB3!')
    expect(res).toEqual({ tooShort: true, weakPrefix: false })
  })

  it('flags both tooShort and weakPrefix for "changeme123!"', () => {
    const res = checkAdminPasswordHardening('changeme123!')
    expect(res).toEqual({ tooShort: true, weakPrefix: true })
  })

  it('flags weakPrefix for a 16+ char "password..." string', () => {
    const res = checkAdminPasswordHardening('password1234-and-some-more')
    expect(res).toEqual({ tooShort: false, weakPrefix: true })
  })

  it('exposes constants used by the env schema for parity checks', () => {
    expect(MIN_ADMIN_PASSWORD_LENGTH).toBe(16)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('changeme')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('password')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('admin')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('123')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('Tr0ub4dor')).toBe(false)
  })
})
