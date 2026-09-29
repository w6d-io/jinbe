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
