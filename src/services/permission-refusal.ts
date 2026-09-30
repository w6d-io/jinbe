import { EVERYTHING } from '../policy/catalog.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { redisClientService } from './redis-client.service.js'
import { GLOBAL, exceeding, flatten, heldIn, isEmpty, loadRoles, type PermissionsByScope } from './grant-subset.js'

/**
 * What a 403 for a missing permission tells the caller besides "no": which groups would give it and
 * who to ask. kuma and auth-mcp render `grantedBy` and `hint`; the fields are added beside a refusal's
 * existing `error` / `code`, never in place of them.
 *
 * Group NAMES only, never their members. Read from the published model (groups → roles), staff
 * groups included; a group granting `*` is listed last — it grants everything, and is rarely the
 * group to ask for. Best effort: a model that cannot be read (Redis down, slow past
 * GRANTED_BY_TIMEOUT_MS) gives an empty list and a hint that says only "ask an administrator for
 * <permission>" — never "no group grants this", which it could not tell. The refusal stands either way.
 */
export interface RefusalDetails {
  grantedBy: string[]
  hint: string
}

/** A permission list, read in jinbe's own scope (global roles included). */
function inScope(needed: readonly string[] | PermissionsByScope, app: string): PermissionsByScope {
  return Array.isArray(needed) ? { [app]: [...needed] } : (needed as PermissionsByScope)
}

function storeReady(): boolean {
  try {
    return redisClientService.isConnected === true
  } catch {
    return false
  }
}

/** How long a refusal waits for the model before answering without the list. */
export const GRANTED_BY_TIMEOUT_MS = 500

/**
 * The groups whose roles, on their own, hold every one of `needed` — or null when the model could
 * not be read in time (a refusal never waits on a store that is down or slow).
 */
export async function holdersOf(needed: readonly string[] | PermissionsByScope, app = 'jinbe'): Promise<string[] | null> {
  const want = inScope(needed, app)
  if (isEmpty(want)) return []
  if (!storeReady()) return null
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), GRANTED_BY_TIMEOUT_MS)
    timer.unref?.()
  })
  try {
    return await Promise.race([readHolders(want), late])
  } finally {
    clearTimeout(timer)
  }
}

/** `holdersOf`, an empty list when it could not tell. */
export async function grantedBy(needed: readonly string[] | PermissionsByScope, app = 'jinbe'): Promise<string[]> {
  return (await holdersOf(needed, app)) ?? []
}

async function readHolders(want: PermissionsByScope): Promise<string[] | null> {
  try {
    const defs = await redisRbacRepository.getGroups()
    const scopes = Object.keys(want)
    const roles = await loadRoles([GLOBAL, ...scopes])
    const wildcard = (name: string) => Object.values(heldIn([defs[name]], roles, scopes)).some((p) => p.includes(EVERYTHING))
    return Object.entries(defs)
      .filter(([, def]) => isEmpty(exceeding(want, heldIn([def], roles, scopes))))
      .map(([name]) => name)
      .sort((a, b) => Number(wildcard(a)) - Number(wildcard(b)) || a.localeCompare(b))
  } catch {
    return null
  }
}

/** Who to ask: one of these groups; nobody short of a super admin (none); or, not known, an administrator. */
export function hintFor(groups: readonly string[] | null, needed: readonly string[] = []): string {
  if (groups === null) return `Ask an administrator for ${needed.length > 0 ? needed.join(', ') : 'access'}.`
  return groups.length > 0
    ? `Ask an administrator to add you to one of: ${groups.join(', ')}.`
    : 'No group grants this on its own; ask a super admin.'
}

export async function refusalDetails(needed: readonly string[] | PermissionsByScope, app = 'jinbe'): Promise<RefusalDetails> {
  const groups = await holdersOf(needed, app)
  const names = Array.isArray(needed) ? [...needed] : flatten(needed as PermissionsByScope)
  return { grantedBy: groups ?? [], hint: hintFor(groups, names) }
}

/** The fields a 403 for missing permissions adds: `permission` for one, `missing` for several. */
export async function missingPermissionFields(missing: readonly string[]): Promise<Record<string, unknown>> {
  const details = await refusalDetails(missing)
  return { ...(missing.length === 1 ? { permission: missing[0] } : { missing: [...missing] }), ...details }
}

/**
 * The fields a delegated caller's `scope_missing:<permission>` refusal adds: the token lacks the
 * scope, and the user may lack the permission too — the hint says both.
 */
export async function scopeRefusalFields(reason: string): Promise<Record<string, unknown>> {
  if (!reason.startsWith('scope_missing:')) return {}
  const permission = reason.slice('scope_missing:'.length)
  const groups = await holdersOf([permission])
  const who = hintFor(groups, [permission])
  return {
    permission,
    grantedBy: groups ?? [],
    hint: `This credential does not carry ${permission}: use a key that carries it. If you do not hold it yourself: ${who}`,
  }
}
