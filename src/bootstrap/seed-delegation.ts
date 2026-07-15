import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * Services that get the delegated org-admin model. Org admins are scoped to
 * their own service; add a service here to enable delegation for it.
 */
const DELEGATED_SERVICES = ['kuma', 'jinbe'] as const

/**
 * Fine-grained user-management permissions an org admin holds. Deliberately NOT
 * `admin:*` / `*` — an org admin may only manage users and assign a bounded set
 * of groups within their own org, nothing else.
 */
const ORG_ADMIN_USER_PERMS = [
  'org:manage_users',
  'users:read',
  'users:create',
  'users:assign_group',
] as const

/**
 * Seed the delegated org-admin RBAC model for each delegated service:
 *   - role  `org_admin`        = user-mgmt perms ∪ the service's `viewer` perms
 *   - group `<svc>-org-admins` = { <svc>: [org_admin] }   (the delegatable co-admin group)
 *   - group `<svc>-viewers`    = { <svc>: [viewer] }       (the read-only default)
 *
 * `org_admin` unions the viewer perms so that delegation CONTAINMENT lets an org
 * admin grant the read-only `<svc>-viewers` group (they must hold every perm a
 * group confers). They can also grant `<svc>-org-admins` (their own group,
 * containment trivially equal).
 *
 * Idempotent + additive: never overwrites an existing role or group, so operator
 * customizations and unrelated roles/groups survive re-runs. A service that does
 * not exist yet is skipped (no delegation model without the service).
 */
export async function seedDelegation(logger: BootstrapLogger): Promise<{ seeded: string[] }> {
  const seeded: string[] = []

  for (const svc of DELEGATED_SERVICES) {
    if (!(await redisRbacRepository.serviceExists(svc))) {
      logger.warn({ svc }, '[seed-delegation] service absent — skipping delegation seed')
      continue
    }

    const roles = (await redisRbacRepository.getRoles(svc)) ?? {}

    if (!roles['org_admin']) {
      // Union the service's viewer perms so containment lets an org admin grant
      // <svc>-viewers. Defensively drop any "*" — an org admin must never become
      // a wildcard even if the viewer role is misconfigured with one (that would
      // make requireManageableOrg treat them as unrestricted and can_grant tier B
      // let them grant anything single-service).
      const viewerPerms = (Array.isArray(roles['viewer']) ? roles['viewer'] : []).filter(
        (p) => p !== '*',
      )
      roles['org_admin'] = Array.from(new Set([...ORG_ADMIN_USER_PERMS, ...viewerPerms]))
      await redisRbacRepository.setRoles(svc, roles)
      seeded.push(`role:${svc}.org_admin`)
    }

    const orgAdminsGroup = `${svc}-org-admins`
    if (!(await redisRbacRepository.getGroup(orgAdminsGroup))) {
      await redisRbacRepository.setGroup(orgAdminsGroup, { [svc]: ['org_admin'] })
      seeded.push(`group:${orgAdminsGroup}`)
    }

    const viewersGroup = `${svc}-viewers`
    if (!(await redisRbacRepository.getGroup(viewersGroup))) {
      await redisRbacRepository.setGroup(viewersGroup, { [svc]: ['viewer'] })
      seeded.push(`group:${viewersGroup}`)
    }
  }

  if (seeded.length > 0) {
    await redisRbacRepository.invalidateBundleEtag()
    logger.info({ seeded }, '[seed-delegation] delegated org-admin model seeded')
  } else {
    logger.debug('[seed-delegation] delegation model already present — no work')
  }

  return { seeded }
}
