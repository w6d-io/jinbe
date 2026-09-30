import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { ROLES, STAFF_ROLES, globalRoleDefinitions, roleProblems } from '../policy/roles.js'
import type { BootstrapLogger } from './types.js'

/**
 * The staff roles and their groups (policy/roles.ts, staff-rbac-proposal §2).
 *
 * Roles are CODE: every run writes each staff role into `roles.global` exactly as roles.ts defines it,
 * overwriting a runtime edit of that name (nobody can redefine a role they hold). Other global roles
 * (`admin`, an operator's own) are left as they are — retiring `global.admin` is the owner's call.
 *
 * Groups are created when missing, `{ global: [<role>] }`, flagged system so only a super admin may
 * change them, and EMPTY: who belongs to which is decided per person by the owner (W3). An existing
 * group of that name bound to something else is left untouched and reported.
 */
export async function seedStaffRoles(logger: BootstrapLogger): Promise<{ roles: string[]; groups: string[]; conflicts: string[] }> {
  const problems = roleProblems()
  if (problems.length > 0) throw new Error(`Staff roles refer to permissions outside the catalogue: ${problems.join('; ')}`)

  await unshadowStaffRoles(logger)

  if (!(await redisRbacRepository.serviceExists('global'))) await redisRbacRepository.addService('global')
  const current = (await redisRbacRepository.getRoles('global')) ?? {}
  const wanted = globalRoleDefinitions()
  const changedRoles = STAFF_ROLES.filter((r) => JSON.stringify(current[r] ?? null) !== JSON.stringify(wanted[r]))
  if (changedRoles.length > 0) await redisRbacRepository.setRoles('global', { ...current, ...wanted })

  const createdGroups: string[] = []
  const conflicts: string[] = []
  for (const role of STAFF_ROLES) {
    const { group, label } = ROLES[role]
    const existing = await redisRbacRepository.getGroup(group)
    if (!existing) {
      await redisRbacRepository.setGroup(group, { global: [role] })
      await redisRbacRepository.setGroupMetadata(group, { system: true, description: label, createdBy: 'bootstrap', createdAt: new Date().toISOString() })
      createdGroups.push(group)
    } else if (!(existing.global ?? []).includes(role)) {
      conflicts.push(`${group} exists without global:${role}`)
    }
  }

  if (changedRoles.length > 0 || createdGroups.length > 0) {
    await redisRbacRepository.invalidateBundleEtag()
    logger.info({ roles: changedRoles, groups: createdGroups }, '[seed-staff] staff roles written, missing groups created')
  }
  if (conflicts.length > 0) logger.warn({ conflicts }, '[seed-staff] a staff group name is taken by another binding — left as is')
  return { roles: changedRoles, groups: createdGroups, conflicts }
}

/** What a jinbe role named like a staff role is renamed to. */
export const LEGACY_PREFIX = 'legacy_'

/** The service whose roles decide jinbe's own API (authz/opa.ts JINBE_APP). */
const JINBE_APP = 'jinbe'

/**
 * The policy resolves a person's roles by NAME across scopes (rbac.rego `user_permissions` reads
 * `roles.global[name]` and `roles.jinbe[name]` for every name they hold): a jinbe role named like a
 * staff role is handed to every holder of that staff role, and the staff role to every holder of the
 * jinbe one. The old support seed made `jinbe.support` (with users:update_email), so staff-support
 * could change sign-in addresses (e2e R-S5).
 *
 * Each such jinbe role is renamed `legacy_<name>`, same permissions, and the groups binding it under
 * `jinbe` follow: who held it keeps exactly that, and nothing more. The new name is added before the
 * groups move and the old one removed after, so no step leaves a binding pointing at nothing.
 */
export async function unshadowStaffRoles(logger: BootstrapLogger): Promise<Record<string, string>> {
  const roles = await redisRbacRepository.getRoles(JINBE_APP)
  const shadowing = STAFF_ROLES.filter((r) => roles?.[r] !== undefined)
  if (!roles || shadowing.length === 0) return {}

  const renamed: Record<string, string> = {}
  for (const role of shadowing) {
    let name = `${LEGACY_PREFIX}${role}`
    for (let n = 2; roles[name] !== undefined || (STAFF_ROLES as string[]).includes(name); n++) name = `${LEGACY_PREFIX}${role}_${n}`
    renamed[role] = name
  }

  const moved = Object.fromEntries(shadowing.map((r) => [renamed[r], roles[r]]))
  await redisRbacRepository.setRoles(JINBE_APP, { ...roles, ...moved })
  const groups = await redisRbacRepository.getGroups()
  const rebound: string[] = []
  for (const [group, def] of Object.entries(groups)) {
    const held = def[JINBE_APP]
    if (!held?.some((r) => renamed[r])) continue
    await redisRbacRepository.setGroup(group, { ...def, [JINBE_APP]: held.map((r) => renamed[r] ?? r) })
    rebound.push(group)
  }
  const kept = Object.fromEntries(Object.entries(roles).filter(([r]) => !renamed[r]))
  await redisRbacRepository.setRoles(JINBE_APP, { ...kept, ...moved })

  await redisRbacRepository.invalidateBundleEtag()
  logger.warn({ renamed, groups: rebound }, '[seed-staff] jinbe roles named like staff roles renamed — the policy would have merged them')
  return renamed
}
