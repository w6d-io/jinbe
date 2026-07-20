/**
 * Bootstrap ADMIN_PASSWORD policy — pure, side-effect-free.
 *
 * The bootstrap ADMIN_PASSWORD seeds the very first `super_admins` identity
 * in Kratos. A weak value here is a direct path to full compromise of the
 * RBAC control plane, so the policy is enforced fail-closed in two
 * independent layers that both consume the constants/helpers below and can
 * therefore never drift apart:
 *
 *   - src/config/env.ts        zod validation — rejects at process start.
 *   - src/bootstrap/seed-admin  assertion at the Kratos identity-creation
 *                               call — refuses to seed even if the schema is
 *                               ever loosened or `admin` config is assembled
 *                               from another source.
 *
 * This module intentionally imports nothing so it stays a dependency-free
 * leaf (safe to import from the config layer without creating a cycle) and
 * can be unit-tested without triggering any module side effects.
 */

/** Minimum acceptable length for the bootstrap admin password. */
export const MIN_ADMIN_PASSWORD_LENGTH = 16

/**
 * Well-known weak prefixes, matched case-insensitively and anchored at the
 * start of the value so `changeme…`, `Password123`, `admin!`, `123456` are
 * all rejected regardless of any trailing padding used to satisfy the
 * length check. No `g` flag, so `.test()` is stateless.
 */
export const WEAK_ADMIN_PASSWORD_PREFIX = /^(changeme|password|admin|123)/i

export interface AdminPasswordWeakness {
  tooShort: boolean
  weakPrefix: boolean
}

/**
 * Returns `null` when the password is acceptable, or a structured weakness
 * descriptor when it violates one or both rules.
 *
 * An `undefined` password is treated as acceptable here: absence is a
 * separate concern handled by the first-run required-env check in the
 * bootstrap CLI. Use {@link assertStrongAdminPassword} at the seed path,
 * where a present-and-strong password is mandatory.
 */
export function checkAdminPasswordHardening(
  password: string | undefined,
): AdminPasswordWeakness | null {
  if (!password) return null
  const tooShort = password.length < MIN_ADMIN_PASSWORD_LENGTH
  const weakPrefix = WEAK_ADMIN_PASSWORD_PREFIX.test(password)
  if (!tooShort && !weakPrefix) return null
  return { tooShort, weakPrefix }
}

/** Human-readable reason string for logs and thrown errors. */
export function describeAdminPasswordWeakness(w: AdminPasswordWeakness): string {
  const reasons: string[] = []
  if (w.tooShort) reasons.push(`shorter than ${MIN_ADMIN_PASSWORD_LENGTH} characters`)
  if (w.weakPrefix) {
    reasons.push('starts with a well-known weak prefix (changeme/password/admin/123)')
  }
  return reasons.join('; ')
}

/** Thrown by {@link assertStrongAdminPassword} when the policy is violated. */
export class WeakAdminPasswordError extends Error {
  readonly weakness: AdminPasswordWeakness

  constructor(weakness: AdminPasswordWeakness) {
    super(
      `Refusing to seed admin: ADMIN_PASSWORD is ${describeAdminPasswordWeakness(weakness)}. ` +
        `Set a value of at least ${MIN_ADMIN_PASSWORD_LENGTH} characters that does not start ` +
        'with a well-known weak prefix (Vault-injected value recommended).',
    )
    this.name = 'WeakAdminPasswordError'
    this.weakness = weakness
  }
}

/**
 * Fail-closed assertion for the seed-admin path. Throws
 * {@link WeakAdminPasswordError} if the password is missing, too short, or
 * starts with a weak prefix. A missing/empty password is a violation at this
 * layer (the CLI guarantees presence on first run), so the seed can never
 * proceed with an unusable or weak credential.
 */
export function assertStrongAdminPassword(password: string | undefined): void {
  if (!password) {
    throw new WeakAdminPasswordError({ tooShort: true, weakPrefix: false })
  }
  const weakness = checkAdminPasswordHardening(password)
  if (weakness) {
    throw new WeakAdminPasswordError(weakness)
  }
}
