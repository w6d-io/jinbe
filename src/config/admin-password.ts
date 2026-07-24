/**
 * Bootstrap ADMIN_PASSWORD policy — pure, side-effect-free.
 *
 * The bootstrap ADMIN_PASSWORD seeds the very first `super_admins` identity
 * in Kratos. A weak value here is a direct path to full compromise of the
 * RBAC control plane, so the policy is enforced fail-closed in two
 * independent layers that both consume the helpers below and can therefore
 * never drift apart:
 *
 *   - src/config/env.ts        zod validation — rejects at process start.
 *   - src/bootstrap/seed-admin  assertion at the Kratos identity-creation
 *                               call — refuses to seed even if the schema is
 *                               ever loosened or `admin` config is assembled
 *                               from another source.
 *
 * The strength test scores entropy rather than blocklisting fixed prefixes:
 *
 *   - Search-space entropy: length × log2(character-pool size). This is the
 *     standard estimate of how large a brute-force space the value spans.
 *   - A distinct-character floor closes the well-known blind spot of the
 *     search-space estimate: a long value drawn from a large pool but built
 *     by repeating a short token (`aB9-aB9-aB9-aB9-`, `abababab…`, `aaaa…`)
 *     spans a large *nominal* pool yet is trivially guessable. Requiring a
 *     minimum count of distinct characters rejects those.
 *
 * Limitation (deliberate): a pure entropy estimate does not detect dictionary
 * words or keyboard/sequence patterns (`correcthorsebattery`, `qwertyuiop…`).
 * Catching those needs a pattern-aware scorer (e.g. zxcvbn) and a wordlist —
 * out of scope here. The length + entropy + distinct-character floors make an
 * intentionally-weak value large enough to also be caught, and the length
 * floor alone rejects the classic short defaults (`changeme123!` etc.).
 *
 * This module intentionally imports nothing so it stays a dependency-free
 * leaf (safe to import from the config layer without creating a cycle) and
 * can be unit-tested without triggering any module side effects.
 */

/** Minimum acceptable length for the bootstrap admin password. */
export const MIN_ADMIN_PASSWORD_LENGTH = 16

/** Minimum estimated search-space entropy, in bits. 60 bits comfortably
 *  admits a 16-character value from any mixed pool (e.g. 16 hex ≈ 82 bits by
 *  this measure) while rejecting short or narrow-pool values. */
export const MIN_ADMIN_PASSWORD_ENTROPY_BITS = 60

/** Minimum count of distinct characters — the anti-repetition guard. */
export const MIN_ADMIN_PASSWORD_UNIQUE_CHARS = 8

/**
 * Size of the character pool the value draws from, summed over the classes
 * actually present. Anything that is not ASCII letter/digit is bucketed as a
 * single "symbol" class (a conservative approximation of ASCII punctuation +
 * space + non-ASCII). Returns at least 1 so log2 is always finite.
 */
export function adminPasswordPoolSize(password: string): number {
  let size = 0
  if (/[a-z]/.test(password)) size += 26
  if (/[A-Z]/.test(password)) size += 26
  if (/[0-9]/.test(password)) size += 10
  if (/[^a-zA-Z0-9]/.test(password)) size += 33
  return size || 1
}

/**
 * Estimated search-space entropy in bits: `length × log2(poolSize)`. This is
 * an upper bound on strength — it does not account for repetition (handled
 * separately by the distinct-character floor) or dictionary patterns.
 */
export function estimateAdminPasswordEntropyBits(password: string): number {
  if (!password) return 0
  return password.length * Math.log2(adminPasswordPoolSize(password))
}

export interface AdminPasswordWeakness {
  /** Below {@link MIN_ADMIN_PASSWORD_LENGTH}. */
  tooShort: boolean
  /** Below the entropy floor, or too few distinct characters. */
  lowEntropy: boolean
  /** Estimated search-space entropy (bits), for messaging/telemetry. */
  estimatedBits: number
}

/**
 * Returns `null` when the password is acceptable, or a structured weakness
 * descriptor when it violates one or more rules.
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
  const estimatedBits = estimateAdminPasswordEntropyBits(password)
  const distinct = new Set(password).size
  const tooShort = password.length < MIN_ADMIN_PASSWORD_LENGTH
  const lowEntropy =
    estimatedBits < MIN_ADMIN_PASSWORD_ENTROPY_BITS || distinct < MIN_ADMIN_PASSWORD_UNIQUE_CHARS
  if (!tooShort && !lowEntropy) return null
  return { tooShort, lowEntropy, estimatedBits }
}

/** Human-readable reason string for logs and thrown errors. */
export function describeAdminPasswordWeakness(w: AdminPasswordWeakness): string {
  const reasons: string[] = []
  if (w.tooShort) reasons.push(`shorter than ${MIN_ADMIN_PASSWORD_LENGTH} characters`)
  if (w.lowEntropy) {
    reasons.push(
      `too predictable (≈${Math.round(w.estimatedBits)} bits of estimated entropy; ` +
        `need at least ${MIN_ADMIN_PASSWORD_ENTROPY_BITS} bits and ` +
        `${MIN_ADMIN_PASSWORD_UNIQUE_CHARS} distinct characters)`,
    )
  }
  return reasons.join('; ')
}

/** Thrown by {@link assertStrongAdminPassword} when the policy is violated. */
export class WeakAdminPasswordError extends Error {
  readonly weakness: AdminPasswordWeakness

  constructor(weakness: AdminPasswordWeakness) {
    super(
      `Refusing to seed admin: ADMIN_PASSWORD is ${describeAdminPasswordWeakness(weakness)}. ` +
        `Set a value of at least ${MIN_ADMIN_PASSWORD_LENGTH} characters with high entropy ` +
        '(a random or long passphrase; Vault-injected value recommended).',
    )
    this.name = 'WeakAdminPasswordError'
    this.weakness = weakness
  }
}

/**
 * Fail-closed assertion for the seed-admin path. Throws
 * {@link WeakAdminPasswordError} if the password is missing, too short, or
 * too low-entropy. A missing/empty password is a violation at this layer (the
 * CLI guarantees presence on first run), so the seed can never proceed with an
 * unusable or weak credential.
 */
export function assertStrongAdminPassword(password: string | undefined): void {
  if (!password) {
    throw new WeakAdminPasswordError({ tooShort: true, lowEntropy: true, estimatedBits: 0 })
  }
  const weakness = checkAdminPasswordHardening(password)
  if (weakness) {
    throw new WeakAdminPasswordError(weakness)
  }
}
