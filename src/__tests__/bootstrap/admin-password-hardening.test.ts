import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  checkAdminPasswordHardening,
  assertStrongAdminPassword,
  estimateAdminPasswordEntropyBits,
  WeakAdminPasswordError,
  MIN_ADMIN_PASSWORD_LENGTH,
  MIN_ADMIN_PASSWORD_ENTROPY_BITS,
  MIN_ADMIN_PASSWORD_UNIQUE_CHARS,
} from '../../config/admin-password.js'
import { envSchema } from '../../config/env.js'
import type { BootstrapLogger } from '../../bootstrap/types.js'

/**
 * ADMIN_PASSWORD hardening (J7). The policy is enforced fail-closed in two
 * independent layers that must stay in sync:
 *   - src/config/env.ts        (zod schema — rejects at process start)
 *   - src/bootstrap/seed-admin  (runtime guard — refuses to seed a weak admin)
 * Both consume the shared helpers in src/config/admin-password.ts, which score
 * entropy (search-space bits + distinct-character floor + length) rather than
 * blocklisting fixed prefixes.
 *
 * All fixture values are built from short, obviously-synthetic tokens via
 * expressions (never literal secret-looking strings) so secret scanners do not
 * flag these test passwords.
 */

const AZ = 'abcdefghijklmnopqrstuvwxyz'
// N distinct sequential letters → high variety, clears the entropy floor.
const distinctOf = (n: number) => AZ.slice(0, n)

const STRONG16 = distinctOf(16) // 16 distinct chars — acceptable (boundary)
const STRONG20 = distinctOf(20) // 20 distinct chars — acceptable
const LEN12 = distinctOf(12) // 12 chars — too short (and under the bit floor)
const LEN15 = distinctOf(15) // 15 chars — too short, but entropy is fine

// High length, too few distinct characters → fails the distinct-char floor
// even though the nominal search space looks large. This is the class the old
// prefix denylist missed entirely.
const REPEAT_ONE = 'a'.repeat(20) // 1 distinct char
const REPEAT_TOKEN = 'aB9-'.repeat(5) // 20 chars, 4 distinct chars

// The false positive the prefix denylist got wrong: a high-variety value that
// merely STARTS with "123" is strong and must now be accepted.
const LEADING_123 = '123' + AZ.slice(3, 16) // 16 distinct chars, starts with 123

// Short AND low-entropy (repetitive) — violates both rules.
const SHORT_LOW = 'a'.repeat(10)

// ---------------------------------------------------------------------------
// Shared pure policy
// ---------------------------------------------------------------------------

describe('admin-password policy constants', () => {
  it('sets the documented floors', () => {
    expect(MIN_ADMIN_PASSWORD_LENGTH).toBe(16)
    expect(MIN_ADMIN_PASSWORD_ENTROPY_BITS).toBe(60)
    expect(MIN_ADMIN_PASSWORD_UNIQUE_CHARS).toBe(8)
  })
})

describe('estimateAdminPasswordEntropyBits', () => {
  it('is zero for empty and grows with length × pool size', () => {
    expect(estimateAdminPasswordEntropyBits('')).toBe(0)
    // 16 lowercase letters → 16 * log2(26) ≈ 75 bits.
    expect(estimateAdminPasswordEntropyBits(STRONG16)).toBeGreaterThan(70)
    // Mixed pool (digits + letters) scores higher per character than the
    // same-length lowercase-only value.
    expect(estimateAdminPasswordEntropyBits(LEADING_123)).toBeGreaterThan(
      estimateAdminPasswordEntropyBits(STRONG16),
    )
  })
})

describe('checkAdminPasswordHardening', () => {
  it('returns null when password is undefined (absence handled elsewhere)', () => {
    expect(checkAdminPasswordHardening(undefined)).toBeNull()
  })

  it('returns null for a strong, high-variety password', () => {
    expect(checkAdminPasswordHardening(STRONG20)).toBeNull()
  })

  it('accepts a strong value that merely starts with "123" (denylist regression)', () => {
    expect(LEADING_123.length).toBe(16)
    expect(checkAdminPasswordHardening(LEADING_123)).toBeNull()
  })

  it('flags tooShort for a 12-char password', () => {
    expect(LEN12.length).toBe(12)
    expect(checkAdminPasswordHardening(LEN12)).toMatchObject({ tooShort: true })
  })

  it('flags lowEntropy for a long but repetitive password', () => {
    expect(checkAdminPasswordHardening(REPEAT_ONE)).toMatchObject({
      tooShort: false,
      lowEntropy: true,
    })
    expect(checkAdminPasswordHardening(REPEAT_TOKEN)).toMatchObject({
      tooShort: false,
      lowEntropy: true,
    })
  })

  it('treats length 15 as too short and length 16 as acceptable (boundary)', () => {
    expect(LEN15.length).toBe(15)
    expect(STRONG16.length).toBe(16)
    expect(checkAdminPasswordHardening(LEN15)).toMatchObject({ tooShort: true, lowEntropy: false })
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

  it('throws WeakAdminPasswordError for a low-entropy (repetitive) password', () => {
    expect(() => assertStrongAdminPassword(REPEAT_TOKEN)).toThrow(WeakAdminPasswordError)
  })

  it('exposes the structured weakness on the thrown error', () => {
    try {
      assertStrongAdminPassword(SHORT_LOW)
      throw new Error('expected assertStrongAdminPassword to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(WeakAdminPasswordError)
      expect((err as WeakAdminPasswordError).weakness).toMatchObject({
        tooShort: true,
        lowEntropy: true,
      })
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

  it('accepts a strong password (>= 16 chars, high entropy)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: STRONG20 }).success).toBe(true)
  })

  it('accepts an omitted ADMIN_PASSWORD (optional — validated only when present)', () => {
    expect(envSchema.safeParse(baseEnv).success).toBe(true)
  })

  it('accepts a strong value starting with "123" (no longer a false positive)', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: LEADING_123 }).success).toBe(true)
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

  it('rejects a long but repetitive (low-entropy) password', () => {
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: REPEAT_ONE }).success).toBe(false)
    expect(envSchema.safeParse({ ...baseEnv, ADMIN_PASSWORD: REPEAT_TOKEN }).success).toBe(false)
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

  it('refuses to seed a low-entropy password and never calls Kratos', async () => {
    await expect(
      seedDefaultAdmin(
        { email: 'admin@example.org', password: REPEAT_TOKEN, name: 'Admin' },
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
