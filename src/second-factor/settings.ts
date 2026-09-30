import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { opalPublisher } from '../services/opal-publisher.js'

/**
 * The platform setting "groups whose members must have a second factor" — rbac:config
 * `second_factor_groups`, a JSON array of group names, published to OPA as data.second_factor.
 *
 * The policy decides from it (rbac.rego § 8c): a member of one of these groups needs an aal2
 * session on every route that carries a permission. Unset means the default, super_admins —
 * a deployment has to say "nobody" explicitly (an empty list), never inherit it from a missing key.
 */

export const SECOND_FACTOR_KEY = 'second_factor_groups'
export const DEFAULT_SECOND_FACTOR_GROUPS: readonly string[] = ['super_admins']
export const GROUP_NAME = /^[a-z_]+$/
export const MAX_GROUPS = 50

const TTL_MS = 5_000
let cached: { at: number; groups: string[]; explicit: boolean } | null = null

/** Test seam. */
export function resetSecondFactorSettingsCache(): void {
  cached = null
}

/** A stored value as a clean list, or null when it is not one (then the default applies). */
export function parseGroups(raw: string | undefined): string[] | null {
  if (raw === undefined) return null
  try {
    const v = JSON.parse(raw) as unknown
    if (!Array.isArray(v) || !v.every((g) => typeof g === 'string' && GROUP_NAME.test(g))) return null
    return [...new Set(v as string[])].sort()
  } catch {
    return null
  }
}

/** Throws when Redis cannot be read: the OPAL route answers 503 so OPA keeps what it holds. */
export async function getSecondFactorGroups(): Promise<string[]> {
  return (await getSecondFactorSetting()).groups
}

/** The list and whether an administrator set it (false: the default applies, the key is unset or malformed). */
export async function getSecondFactorSetting(): Promise<{ groups: string[]; explicit: boolean }> {
  if (cached && Date.now() - cached.at < TTL_MS) return { groups: cached.groups, explicit: cached.explicit }
  const config = await redisRbacRepository.getConfig()
  const stored = parseGroups(config[SECOND_FACTOR_KEY])
  cached = { at: Date.now(), groups: stored ?? [...DEFAULT_SECOND_FACTOR_GROUPS], explicit: stored !== null }
  return { groups: cached.groups, explicit: cached.explicit }
}

export async function setSecondFactorGroups(groups: string[]): Promise<string[]> {
  const clean = [...new Set(groups)].sort()
  await redisRbacRepository.setConfig(SECOND_FACTOR_KEY, JSON.stringify(clean))
  cached = { at: Date.now(), groups: clean, explicit: true }
  opalPublisher.schedule('second_factor')
  return clean
}
