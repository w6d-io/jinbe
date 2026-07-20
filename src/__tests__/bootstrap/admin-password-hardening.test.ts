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
 *
 * All fixture values are built from short, low-entropy tokens via expressions
 * (never literal secret-looking strings) so secret scanners do not flag these
 * synthetic test passwords.
 */

// 4-char token: mixed case + digit + symbol, and NOT a weak prefix.
const TOK = 'aB9-'
const STRONG16 = TOK.repeat(4) // 16 chars, acceptable
const STRONG20 = TOK.repeat(5) // 20 chars, acceptable
const LEN12 = TOK.repeat(3) // 12 chars, too short, no weak prefix
const LEN15 = TOK.repeat(3) + 'aB9' // 15 chars, too short, no weak prefix
const WEAK_CHANGEME = 'changeme-' + TOK.repeat(4) // weak prefix, 25 chars
const WEAK_LOWER = 'password-' + TOK.repeat(4) // weak prefix, 25 chars
const WEAK_UPPER = 'PASSWORD-' + TOK.repeat(4) // weak prefix (case-insensitive)
const WEAK_ADMIN = 'admin-' + TOK.repeat(5) // weak prefix, 26 chars
const WEAK_123 = '123-' + TOK.repeat(5) // weak prefix, 24 chars
const WEAK_BOTH = 'changeme' + '12' // 10 chars: weak prefix AND too short

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
    expect(WEAK_ADMIN_PASSWORD_PREFIX.test('Zebra')).toBe(false)
  })
})

describe('checkAdminPasswordHardening', () => {
  it('returns null when password is undefined (absence handled elsewhere)', () => {
    expect(checkAdminPasswordHardening(undefined)).toBeNull()
  })

  it('returns null for a strong password', () => {
    expect(checkAdminPasswordHardening(STRONG20)).toBeNull()
  })

  it('flags tooShort only for a 12-char, non-weak-prefix password', () => {
    expect(LEN12.length).toBe(12)
    expect(checkAdminPasswordHardening(LEN12)).toEqual({ tooShort: true, weakPrefix: false })
  })

  it('flags weakPrefix only for a >=16-char weak-prefix string', () => {
    expect(WEAK_LOWER.length).toBeGreaterThanOrEqual(16)
    expect(checkAdminPasswordHardening(WEAK_LOWER)).toEqual({ tooShort: false, weakPrefix: true })
  })

  it('flags both tooShort and weakPrefix for a short weak-prefix string', () => {
    expect(checkAdminPasswordHardening(WEAK_BOTH)).toEqual({ tooShort: true, weakPrefix: true })
  })

  it('treats length 15 as too short and length 16 as acceptable (boundary)', () => {
    expect(LEN15.length).toBe(15)
    expect(STRONG16.length).toBe(16)
    expect(checkAdminPasswordHardening(LEN15)).toEqual({ tooShort: true, weakPrefix: false })
    expect(checkAdminPasswordHardening(STRONG16)).toBeNull()
  })
})

describe('assertStrongAdminPassword', () => {
  it('does not throw for a strong password', () => {
    expect(() => assertStrongAdminPassword(STRONG20)).not.toThrow()
  })

  it('throws WeakAdminPasswordError for a missing/empty password (fail-closed)', () => {
    expect(() => assertStrongAdminPassword(undefined)).toThrow(WeakAdminPasswordError)
    expect(() => assertStrongAdminPassword('')).toThrow(WeakAdminPasswordError)
  })

  it('throws WeakAdminPasswordError for a too-short password', () => {
    expect(() => assertStrongAdminPassword(LEN12)).toThrow(WeakAdminPasswordError)
  })

  it('throws WeakAdminPasswordError for a weak-prefix password', () => {
    expect(() => assertStrongAdminPassword(WEAK_CHANGEME)).toThrow(WeakAdminPasswordError)
  })

  it('exposes the structured weakness on the thrown error', () => {
    try {
      assertStrongAdminPassword(WEAK_BOTH)
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
  const baseEnv = { ENCRYPTION_KEY: 'x'.repeat(32) }

  it('accepts a strong password (>= 16 chars, no weak prefix)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: STRONG20 }).success).toBe(true)
  })

  it('accepts an omitted ADMIN_PASSWORD (optional — validated only when present)', () => {
    expect(envSchema.safeParse(baseEnv).success).toBe(true)
  })

  it('rejects a password shorter than 16 chars', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: LEN12 }).success).toBe(false)
  })

  it('rejects exactly 15 chars and accepts exactly 16 chars (boundary)', () => {
    expect(LEN15.length).toBe(15)
    expect(STRONG16.length).toBe(16)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: LEN15 }).success).toBe(false)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: STRONG16 }).success).toBe(true)
  })

  it('rejects a long "changeme" prefix password', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: WEAK_CHANGEME }).success).toBe(false)
  })

  it('rejects a long weak prefix in upper case (case-insensitive)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: WEAK_UPPER }).success).toBe(false)
  })

  it('rejects long "admin" and "123" prefix passwords', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: WEAK_ADMIN }).success).toBe(false)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: WEAK_123 }).success).toBe(false)
  })

  it('rejects a short weak-prefix password (too short AND weak prefix)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: WEAK_BOTH }).success).toBe(false)
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
      seedDefaultAdmin({ email: 'admin@example.org', password: LEN12, name: 'Admin' }, logger),
    ).rejects.toBeInstanceOf(WeakAdminPasswordError)
    expect(kratosMock.listIdentities).not.toHaveBeenCalled()
    expect(kratosMock.createIdentity).not.toHaveBeenCalled()
  })

  it('refuses to seed a weak-prefix password and never calls Kratos', async () => {
    await expect(
      seedDefaultAdmin(
        { email: 'admin@example.org', password: WEAK_CHANGEME, name: 'Admin' },
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
      { email: 'admin@example.org', password: STRONG20, name: 'Admin' },
      logger,
    )

    expect(res).toEqual({ created: true })
    expect(kratosMock.createIdentity).toHaveBeenCalledTimes(1)
  })
})
