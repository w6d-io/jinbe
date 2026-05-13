/**
 * Pure guards for the bootstrap CLI. Kept in a side-effect-free module so
 * unit tests can import them without triggering the auto-run `void main()`
 * in src/cli/bootstrap.ts.
 *
 * The same checks are mirrored as zod refinements in src/config/env.ts;
 * the runtime guard here is defence-in-depth in case the schema is ever
 * loosened in a hot patch.
 */

export type AdminPasswordWeakness = {
  tooShort: boolean
  weakPrefix: boolean
}

export const MIN_ADMIN_PASSWORD_LENGTH = 16
export const WEAK_ADMIN_PASSWORD_PREFIX = /^(changeme|password|admin|123)/i

/**
 * Returns null when the password is acceptable, or a structured
 * weakness descriptor when it fails one or both rules.
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
