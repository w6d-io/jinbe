import { orgPermissionsByOrg } from '../authz/opa.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { JINBE } from '../policy/roles.js'

/**
 * The holding rule for org roles (authz-v2-design §2.5, `can_assign`): to hand somebody an org role
 * in org X, the actor holds `org.members:write` IN X and every permission of the role IN X, for the
 * role's service; the org is entitled to that service. A removal needs `org.members:write` alone
 * (the route). What the actor holds is OPA's answer (`rbac.org_permissions_by_org`); what a role
 * carries is the published definition (rbac:org_roles:{svc}).
 */

export interface OrgRoleView {
  role: string
  permissions: string[]
  assignable: boolean
}

export type OrgRoleRefusal = { role: string; reason: 'unknown_role' | 'org_not_entitled' | 'grant_permission_missing' | 'grant_exceeds_own'; missing?: string[] }

/** Every org role this org may hold (jinbe's, and its entitled sites'), with the definitions. */
async function rolesOf(org: string): Promise<Array<{ svc: string; name: string; permissions: string[] }>> {
  const entitled = [JINBE, ...((await redisRbacRepository.getOrgSites())[org] ?? [])]
  const out: Array<{ svc: string; name: string; permissions: string[] }> = []
  for (const svc of [...new Set(entitled)]) {
    for (const [name, permissions] of Object.entries((await redisRbacRepository.getOrgRoles(svc)) ?? {})) out.push({ svc, name, permissions })
  }
  return out.sort((a, b) => `${a.svc}:${a.name}`.localeCompare(`${b.svc}:${b.name}`))
}

/** The org roles of `org`, each marked with whether `actor` may assign it. Throws when OPA cannot tell. */
export async function orgRolesFor(actor: string, org: string): Promise<OrgRoleView[]> {
  const roles = await rolesOf(org)
  const held = new Map<string, string[]>()
  const heldIn = async (svc: string) => {
    if (!held.has(svc)) held.set(svc, (await orgPermissionsByOrg(actor, svc))[org] ?? [])
    return held.get(svc)!
  }
  const mayGrant = (await heldIn(JINBE)).includes('org.members:write')
  const out: OrgRoleView[] = []
  for (const r of roles) {
    const mine = await heldIn(r.svc)
    out.push({ role: `${r.svc}:${r.name}`, permissions: r.permissions, assignable: mayGrant && r.permissions.every((p) => mine.includes(p)) })
  }
  return out
}

/** Why each of `roles` may not be handed out by `actor` in `org` (empty: all may). */
export async function orgRoleRefusals(actor: string, org: string, roles: readonly string[]): Promise<OrgRoleRefusal[]> {
  if (roles.length === 0) return []
  const views = new Map((await orgRolesFor(actor, org)).map((v) => [v.role, v]))
  const jinbeHeld = (await orgPermissionsByOrg(actor, JINBE))[org] ?? []
  const out: OrgRoleRefusal[] = []
  for (const role of roles) {
    const view = views.get(role)
    if (!view) {
      const [svc] = role.split(':')
      const known = svc && (await redisRbacRepository.getOrgRoles(svc))?.[role.split(':')[1] ?? '']
      out.push({ role, reason: known ? 'org_not_entitled' : 'unknown_role' })
    } else if (!jinbeHeld.includes('org.members:write')) {
      out.push({ role, reason: 'grant_permission_missing', missing: ['org.members:write'] })
    } else if (!view.assignable) {
      const svc = role.split(':')[0]
      const mine = (await orgPermissionsByOrg(actor, svc))[org] ?? []
      out.push({ role, reason: 'grant_exceeds_own', missing: view.permissions.filter((p) => !mine.includes(p)) })
    }
  }
  return out
}
