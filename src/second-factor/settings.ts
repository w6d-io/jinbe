import { redisRbacRepository, type GroupDefinition } from '../services/redis-rbac.repository.js'
import { staffGroupsRequiringSecondFactor } from '../policy/roles.js'
import { opalPublisher } from '../services/opal-publisher.js'
import { withRedisLock } from '../services/redis-lock.js'
import { flatten, groupGrants, loadRoles, type RolesByScope } from '../services/grant-subset.js'

/**
 * "Members must use 2FA" — ONE switch per group (owner decision 2026-09-30), and it drives both:
 *
 *   (a) sign-in: a member needs an aal2 session on every route that carries a permission — published
 *       to OPA as data.second_factor = {groups: [every group switched on]} (rbac.rego § 8c);
 *   (b) joining: nobody is added to the group before they have enrolled a second factor
 *       (user-groups.service).
 *
 * Stored in rbac:config `second_factor_group_flags`, a JSON object group → boolean. A group with no
 * stored value gets its DEFAULT, which the boot migration then writes down so it stops moving with the
 * group's roles: ON for a group that can change anything (a permission whose verb is not read / list /
 * check) or holds `*`, and for staff-auditors (they read every person, session and the audit log — the
 * owner's call, 2026-10-02); OFF for a read-only group and for staff-viewers. The legacy list (`second_factor_groups`, set
 * through the settings screen before the switch existed) counts as explicit ON for every group it named.
 *
 * Only a super admin changes it (routes.ts); every change is audited.
 */

export const SECOND_FACTOR_FLAGS_KEY = 'second_factor_group_flags'
/** Legacy: the list the settings screen stored before the per-group switch. Read, never written. */
export const SECOND_FACTOR_KEY = 'second_factor_groups'
/** Group names as the rest of jinbe writes them (staff-ops, fleet-org-admins, super_admins). */
export const GROUP_NAME = /^[a-z][a-z0-9_-]{0,63}$/
export const MAX_GROUPS = 200

/** Read-only by the owner's decision, whatever their roles say: 2FA off by default. (staff-viewers is gone.) */
export const READ_ONLY_GROUPS: readonly string[] = []
/** 2FA on by default by the owner's decision, whatever their roles say. (staff-auditors is gone.) */
export const REQUIRED_GROUPS: readonly string[] = []
const READ_VERBS = new Set(['read', 'list', 'check'])

export interface GroupFlag {
  required: boolean
  /** Stored (a super admin's choice, the migration's pinned default, or the legacy list); false = computed default. */
  explicit: boolean
  /** What the default would be. */
  default: boolean
}

const TTL_MS = 5_000
let cached: { at: number; flags: Map<string, GroupFlag> } | null = null

/** Test seam. */
export function resetSecondFactorSettingsCache(): void {
  cached = null
}

/** A stored legacy list as a clean list, or null when it is not one. */
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

/** Stored flags; anything malformed is dropped (that group falls back to its default). */
export function parseFlags(raw: string | undefined): Record<string, boolean> {
  if (raw === undefined) return {}
  try {
    const v = JSON.parse(raw) as unknown
    if (!v || typeof v !== 'object' || Array.isArray(v)) return {}
    return Object.fromEntries(Object.entries(v).filter(([k, b]) => GROUP_NAME.test(k) && typeof b === 'boolean')) as Record<string, boolean>
  } catch {
    return {}
  }
}

/** The default: on for a group that can change anything or holds `*` (and REQUIRED_GROUPS), off for a read-only one. */
export function defaultRequired(name: string, definition: GroupDefinition | undefined, roles: RolesByScope): boolean {
  if (REQUIRED_GROUPS.includes(name)) return true
  if (READ_ONLY_GROUPS.includes(name)) return false
  return flatten(groupGrants(definition, roles)).some((p) => !READ_VERBS.has(p.split(':')[1] ?? ''))
}

async function compute(): Promise<{ flags: Map<string, GroupFlag>; stored: Record<string, boolean> }> {
  const [config, defs] = await Promise.all([redisRbacRepository.getConfig(), redisRbacRepository.getGroups()])
  const stored = parseFlags(config[SECOND_FACTOR_FLAGS_KEY])
  const legacy = parseGroups(config[SECOND_FACTOR_KEY]) ?? []
  const roles = await loadRoles(new Set(Object.values(defs).flatMap((d) => Object.keys(d ?? {}))))
  const flags = new Map<string, GroupFlag>()
  const locked = staffGroupsRequiringSecondFactor()
  for (const name of Object.keys(defs).sort()) {
    const dflt = defaultRequired(name, defs[name], roles)
    // A staff group whose role needs a recent second factor always requires one (policy/roles.ts).
    if (locked.has(name)) flags.set(name, { required: true, explicit: name in stored || legacy.includes(name), default: true })
    else if (name in stored) flags.set(name, { required: stored[name], explicit: true, default: dflt })
    else if (legacy.includes(name)) flags.set(name, { required: true, explicit: true, default: dflt })
    else flags.set(name, { required: dflt, explicit: false, default: dflt })
  }
  return { flags, stored }
}

/**
 * Every existing group's switch. Throws when Redis cannot be read: the OPAL route answers 503.
 * `fresh` skips the short cache — the OPAL feed, refetched right after a group is created or changed.
 */
export async function getGroupSecondFactorFlags(opts: { fresh?: boolean } = {}): Promise<Map<string, GroupFlag>> {
  if (!opts.fresh && cached && Date.now() - cached.at < TTL_MS) return cached.flags
  const { flags } = await compute()
  cached = { at: Date.now(), flags }
  return flags
}

/** The groups switched on — data.second_factor.groups. */
export async function getSecondFactorGroups(opts: { fresh?: boolean } = {}): Promise<string[]> {
  return [...(await getGroupSecondFactorFlags(opts)).entries()].filter(([, f]) => f.required).map(([n]) => n)
}

/** The groups switched on, and whether every group's value is stored rather than defaulted. */
export async function getSecondFactorSetting(): Promise<{ groups: string[]; explicit: boolean }> {
  const flags = await getGroupSecondFactorFlags()
  return {
    groups: [...flags.entries()].filter(([, f]) => f.required).map(([n]) => n),
    explicit: [...flags.values()].every((f) => f.explicit),
  }
}

/** The groups whose default is on (what `defaultGroups` means now). */
export async function getDefaultSecondFactorGroups(): Promise<string[]> {
  return [...(await getGroupSecondFactorFlags()).entries()].filter(([, f]) => f.default).map(([n]) => n)
}

async function writeFlags(mutate: (stored: Record<string, boolean>, flags: Map<string, GroupFlag>) => void): Promise<Record<string, boolean>> {
  return withRedisLock('second-factor-flags', async () => {
    const { flags, stored } = await compute()
    const next = { ...stored }
    mutate(next, flags)
    if (JSON.stringify(next) === JSON.stringify(stored)) return next
    await redisRbacRepository.setConfig(SECOND_FACTOR_FLAGS_KEY, JSON.stringify(next))
    cached = null
    opalPublisher.schedule('second_factor')
    return next
  })
}

/** One group's switch. Returns the value before (effective) and after. */
export async function setGroupSecondFactor(name: string, required: boolean): Promise<{ before: GroupFlag | null; after: boolean }> {
  if (!required && staffGroupsRequiringSecondFactor().has(name)) {
    throw Object.assign(new Error(`'${name}' always requires two-step sign-in: its role includes actions that need a recent second factor`), { statusCode: 409, code: 'second_factor_locked' })
  }
  let before: GroupFlag | null = null
  await writeFlags((next, flags) => {
    before = flags.get(name) ?? null
    next[name] = required
  })
  return { before, after: required }
}

/** The settings screen's full list: these groups on, every other existing group off. */
export async function setSecondFactorGroups(groups: string[]): Promise<string[]> {
  const on = new Set(groups)
  await writeFlags((next, flags) => {
    for (const name of flags.keys()) next[name] = on.has(name)
  })
  return getSecondFactorGroups()
}

/**
 * Boot migration: write down the value of every group that has none stored (its legacy ON or its
 * default), so a later role change never flips a group's 2FA silently. Stored values are kept.
 */
export async function migrateSecondFactorFlags(logger: { info: (o: object, m: string) => void }): Promise<{ pinned: string[] }> {
  const pinned: string[] = []
  await writeFlags((next, flags) => {
    for (const [name, f] of flags) {
      if (name in next) continue
      next[name] = f.required
      pinned.push(name)
    }
  })
  if (pinned.length) logger.info({ pinned }, 'second factor: pinned the per-group "members must use 2FA" defaults')
  return { pinned }
}
