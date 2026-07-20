import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  checkAdminPasswordHardening,
  assertStrongAdminPassword,
  WeakAdminPasswordError,
  MIN_ADMIN_PASSWORD_LENGTH,
  WEAK_ADMIN_PASSWORD_PREFIX,
} from '../../config/admin-password.js'
import { envSchema } from '../../config/env.js'
import type { BootstrapLogger } from '../../bootstrap/types.js'

/**
 * ADMIN_PASSWORD hardening (J7). The policy is enforced fail-closed in two
 * independent layers that must stay in sync:
 *   - src/config/env.ts        (zod schema — rejects at process start)
 *   - src/bootstrap/seed-admin  (runtime guard — refuses to seed a weak admin)
 * Both consume the shared constants/helpers in src/config/admin-password.ts.
 */

// ---------------------------------------------------------------------------
// Shared pure policy
// ---------------------------------------------------------------------------

describe('admin-password policy constants', () => {
  it('requires a minimum length of 16', () => {
    expect(MIN_ADMIN_PASSWORD_LENGTH).toBe(16)
  })

  it('flags the well-known weak prefixes (case-insensitive)', () => {
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('changeme')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('password')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('admin')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('123')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('CHANGEME')).toBe(true)
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('Tr0ub4dor')).toBe(false)
  })
})

describe('checkAdminPasswordHardening', () => {
  it('returns null when password is undefined (absence handled elsewhere)', () => {
    expect(checkAdminPasswordHardening(undefined)).toBeNull()
  })

  it('returns null for a strong password', () => {
    expect(checkAdminPasswordHardening('xK8#mP2$qR9!nL5@vT7&')).toBeNull()
  })

  it('flags tooShort only for a 12-char, non-weak-prefix password', () => {
    const res = checkAdminPasswordHardening('aB3!aB3!aB3!')
    expect(res).toEqual({ tooShort: true, weakPrefix: false })
  })

  it('flags weakPrefix only for a >=16-char "password..." string', () => {
    const res = checkAdminPasswordHardening('password1234-and-some-more')
    expect(res).toEqual({ tooShort: false, weakPrefix: true })
  })

  it('flags both tooShort and weakPrefix for "changeme123!"', () => {
    const res = checkAdminPasswordHardening('changeme123!')
    expect(res).toEqual({ tooShort: true, weakPrefix: true })
  })

  it('treats length 15 as too short and length 16 as acceptable (boundary)', () => {
    expect(checkAdminPasswordHardening('Zx9!Zx9!Zx9!Zx9')).toEqual({ tooShort: true, weakPrefix: false })
    expect(checkAdminPasswordHardening('Zx9!Zx9!Zx9!Zx9!')).toBeNull()
  })
})

describe('assertStrongAdminPassword', () => {
  it('does not throw for a strong password', () => {
    expect(() => assertStrongAdminPassword('xK8#mP2$qR9!nL5@vT7&')).not.toThrow()
  })

  it('throws WeakAdminPasswordError for a missing password (fail-closed)', () => {
    expect(() => assertStrongAdminPassword(undefined)).toThrow(WeakAdminPasswordError)
    expect(() => assertStrongAdminPassword('')).toThrow(WeakAdminPasswordError)
  })

  it('throws WeakAdminPasswordError for a too-short password', () => {
    expect(() => assertStrongAdminPassword('aB3!aB3!aB3!')).toThrow(WeakAdminPasswordError)
  })

  it('throws WeakAdminPasswordError for a weak-prefix password', () => {
    expect(() => assertStrongAdminPassword('changeme-and-a-lot-more-chars')).toThrow(
      WeakAdminPasswordError,
    )
  })

  it('exposes the structured weakness on the thrown error', () => {
    try {
      assertStrongAdminPassword('changeme123!')
      throw new Error('expected assertStrongAdminPassword to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(WeakAdminPasswordError)
      expect((err as WeakAdminPasswordError).weakness).toEqual({ tooShort: true, weakPrefix: true })
    }
  })
})

// ---------------------------------------------------------------------------
// Config layer — envSchema
// ---------------------------------------------------------------------------

describe('envSchema ADMIN_PASSWORD validation', () => {
  // ENCRYPTION_KEY is the only field without a default/optional; everything
  // else the schema needs has a default, so this is a minimal valid base.
  const baseEnv = { ENCRYPTION_KEY: 'a'.repeat(32) }

  it('accepts a strong password (>= 16 chars, no weak prefix)', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'xK8#mP2$qR9!nL5@vT7&' })
    expect(res.success).toBe(true)
  })

  it('accepts an omitted ADMIN_PASSWORD (optional — validated only when present)', () => {
    expect(envSchema.safeParse(baseEnv).success).toBe(true)
  })

  it('rejects a password shorter than 16 chars', () => {
    const res = envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'short-pw' })
    expect(res.success).toBe(false)
  })

  it('rejects exactly 15 chars and accepts exactly 16 chars (boundary)', () => {
    const fifteen = 'Zx9!Zx9!Zx9!Zx9'
    const sixteen = 'Zx9!Zx9!Zx9!Zx9!'
    expect(fifteen.length).toBe(15)
    expect(sixteen.length).toBe(16)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: fifteen }).success).toBe(false)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: sixteen }).success).toBe(true)
  })

  it('rejects a long "changeme..." password (weak prefix)', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'changeme-and-then-some-padding',
    })
    expect(res.success).toBe(false)
  })

  it('rejects a long "PASSWORD..." password (weak prefix, case-insensitive)', () => {
    const res = envSchema.safeParse({
      ...baseEnv,
      ADMIN_PASSWORD: 'PASSWORD-with-lots-of-extra-chars',
    })
    expect(res.success).toBe(false)
  })

  it('rejects a long "admin..." and a long "123..." password (weak prefixes)', () => {
    expect(
      envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'AdminPasswordWithExtra1!' }).success,
    ).toBe(false)
    expect(
      envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: '123-this-is-still-bad-even-long' }).success,
    ).toBe(false)
  })

  it('rejects "changeme123!" (too short AND weak prefix)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: 'changeme123!' }).success).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Seed-admin layer — seedDefaultAdmin refuses to seed a weak admin
// ---------------------------------------------------------------------------

const kratosMock = vi.hoisted(() => ({
  listIdentities: vi.fn(),
  createIdentity: vi.fn(),
}))

vi.mock('../../services/kratos.service.js', () => ({
  kratosService: kratosMock,
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(message: string, statusCode: number) {
      super(message)
      this.statusCode = statusCode
    }
  },
}))

// Imported after the mock is registered (vi.mock is hoisted, so this is safe).
const { seedDefaultAdmin } = await import('../../bootstrap/seed-admin.js')

const logger: BootstrapLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}

describe('seedDefaultAdmin password hardening', () => {
  beforeEach(() => {
    kratosMock.listIdentities.mockReset()
    kratosMock.createIdentity.mockReset()
  })

  it('refuses to seed a too-short password and never calls Kratos', async () => {
    await expect(
      seedDefaultAdmin(
        { email: 'admin@example.org', password: 'aB3!aB3!aB3!', name: 'Admin' },
        logger,
      ),
    ).rejects.toBeInstanceOf(WeakAdminPasswordError)
    expect(kratosMock.listIdentities).not.toHaveBeenCalled()
    expect(kratosMock.createIdentity).not.toHaveBeenCalled()
  })

  it('refuses to seed a weak-prefix password and never calls Kratos', async () => {
    await expect(
      seedDefaultAdmin(
        { email: 'admin@example.org', password: 'changeme-and-a-lot-more-chars', name: 'Admin' },
        logger,
      ),
    ).rejects.toBeInstanceOf(WeakAdminPasswordError)
    expect(kratosMock.listIdentities).not.toHaveBeenCalled()
    expect(kratosMock.createIdentity).not.toHaveBeenCalled()
  })

  it('proceeds to create the identity for a strong password', async () => {
    kratosMock.listIdentities.mockResolvedValue({ identities: [] })
    kratosMock.createIdentity.mockResolvedValue({ id: 'id-1' })

    const res = await seedDefaultAdmin(
      { email: 'admin@example.org', password: 'xK8#mP2$qR9!nL5@vT7&', name: 'Admin' },
      logger,
    )

    expect(res).toEqual({ created: true })
    expect(kratosMock.createIdentity).toHaveBeenCalledTimes(1)
  })
})
