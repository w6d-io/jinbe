import { orgGrantsRepository } from './org-grants.repository.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { queryOpa } from './opa-client.js'

/**
 * The org layer, as jinbe needs it for its own decisions.
 *
 * WHO MAY GRANT is never decided here: `can_grant` and `assignable_groups` are asked of OPA
 * (opal-policies delegation.rego), with its token, so the mutation gate and the picker are the very
 * rule the gateway enforces. Only a `true` answer grants; anything else — false, undefined, a string —
 * is a refusal, and an unconfigured or silent OPA throws (503/502), never allows.
 */

/** `data.rbac.delegation.can_grant` — may ACTOR put GROUP into org_grants[ORG][GRANTEE]? */
export async function canGrant(actorEmail: string, targetOrg: string, granteeEmail: string, group: string): Promise<boolean> {
  const result = await queryOpa<unknown>('rbac/delegation/can_grant', {
    actor: { email: actorEmail.toLowerCase() },
    target_group: group,
    target_org: targetOrg,
    grantee: { email: granteeEmail.toLowerCase() },
  })
  return result === true
}

/**
 * `data.rbac.delegation.assignable_groups` for the actor. `target_org` is sent so the policy can
 * scope the answer to this org; today it answers across every org the actor administers, which is
 * why the caller also keeps only groups inside this org's bundle.
 */
export async function assignableGroupNames(actorEmail: string, targetOrg: string): Promise<string[]> {
  const result = await queryOpa<unknown>('rbac/delegation/assignable_groups', {
    actor: { email: actorEmail.toLowerCase() },
    target_org: targetOrg,
  })
  return Array.isArray(result) ? result.filter((g): g is string => typeof g === 'string') : []
}

/**
 * Permissions org_grants[org] confers on `email` — mirror of `org_permissions` in org.rego: the
 * granted groups' SERVICE roles only (a group's `global` roles never flow through an org grant), and
 * only in the org that holds the grant.
 */
export async function orgGrantPermissions(email: string, organizationId: string): Promise<string[]> {
  const granted = await orgGrantsRepository.getForMember(organizationId, email.toLowerCase())
  if (granted.length === 0) return []

  const groups = await redisRbacRepository.getGroups()
  const permissions = new Set<string>()
  for (const group of granted) {
    for (const [service, roles] of Object.entries(groups[group] ?? {})) {
      if (service === 'global') continue
      const defined = (await redisRbacRepository.getRoles(service)) ?? {}
      for (const role of roles) for (const p of defined[role] ?? []) permissions.add(p)
    }
  }
  return [...permissions].sort()
}
