import { queryOpa } from './opa-client.js'
import type { HeldRights } from './authorization-resolution.js'

/**
 * What somebody holds in one app, answered by the engine that enforces: OPA, over the RBAC data
 * jinbe publishes (Redis → OPAL → OPA, package `rbac`). Global roles are included — `user_info`
 * unions `groups[g].global` with `groups[g][app]`, exactly as `allow` does.
 *
 * ONE ENGINE. The gateway decides from this data; a guard reading anything else (the ConfigMap
 * model) could let through what the gateway refuses, or refuse what it lets through, and nobody
 * would see the two drift. This is the seam the other guards (requireAdmin, requireServiceAdmin)
 * move onto.
 *
 * Cached for a few seconds per (email, app): a guard runs on every request and a console fires
 * several at once. Short enough that a removed group stops granting almost at once. Only answers are
 * cached — a failure is asked again next time.
 *
 * Fails closed: OPA unconfigured, unreachable, or answering nothing (no `rbac` policy loaded, or a
 * subject the rule cannot place) throws, and the caller answers 503 — never an allow, and never a 403
 * that would read as "holds nothing" when the truth is "could not tell".
 */

export const EFFECTIVE_PERMISSIONS_TTL_MS = 5_000

export class EffectivePermissionsUnavailableError extends Error {}

interface UserInfo {
  groups?: string[]
  roles?: string[]
  permissions?: string[]
}

const cache = new Map<string, { at: number; rights: HeldRights }>()

export async function effectivePermissions(email: string, app: string): Promise<HeldRights> {
  const key = `${app}\u0000${email.toLowerCase()}`
  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < EFFECTIVE_PERMISSIONS_TTL_MS) return hit.rights

  let info: UserInfo | undefined
  try {
    info = await queryOpa<UserInfo>('rbac/user_info', { email, app })
  } catch (err) {
    throw new EffectivePermissionsUnavailableError((err as Error).message)
  }
  if (!info || typeof info !== 'object') {
    throw new EffectivePermissionsUnavailableError('OPA answered nothing for rbac/user_info')
  }

  const rights: HeldRights = {
    groups: [...(info.groups ?? [])].sort(),
    roles: [...(info.roles ?? [])].sort(),
    permissions: [...(info.permissions ?? [])].sort(),
  }
  // Bounded: a burst of distinct callers must not grow this for ever.
  if (cache.size >= 10_000) cache.clear()
  cache.set(key, { at: Date.now(), rights })
  return rights
}

/** Test seam. */
export function clearEffectivePermissionsCache(): void {
  cache.clear()
}
