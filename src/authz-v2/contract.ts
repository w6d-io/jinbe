import { CATALOG_V2 } from './catalogue.js'
import { JINBE, everyOrgDefinitions, orgRoleDefinitions, platformRoleDefinitions, staffGroupsV2 } from './roles.js'
import { GENERATED_ROUTE_MAP_V2 } from './route-map.generated.js'
import type { RouteRule } from '../services/redis-rbac.repository.js'

/**
 * policy-contract.json (authz-v2-design §3.5): what jinbe's v2 model says, for opal-policies CI to
 * test `rbacv2` against. Each route row lists exactly who must reach it:
 *
 *   platform row   the platform roles holding its permission (through the group binding them)
 *   org row        the org roles holding it (assigned in that org, to a member, org entitled) and the
 *                  platform roles whose every-org entry holds it
 *   no permission  `public` or `signed-in`
 *
 * and, by omission, that nobody else does. Deterministic: sorted keys, no timestamp.
 */

export interface ContractRow extends RouteRule {
  reach:
    | { kind: 'public' | 'signed-in' }
    | { kind: 'platform'; roles: string[]; groups: string[] }
    | { kind: 'org'; orgRoles: string[]; everyOrg: string[] }
}

export interface PolicyContract {
  version: 1
  app: string
  catalogue: Record<string, { scope: 'platform' | 'org'; step_up: boolean; delegable: 'direct' | 'never'; four_eyes: 'prod' | false }>
  roles: Record<string, Record<string, string[]>>
  groups: Record<string, Record<string, string[]>>
  org_roles: Record<string, Record<string, string[]>>
  every_org: Record<string, Record<string, string[]>>
  route_map: Record<string, { rules: ContractRow[] }>
}

const holding = (defs: Record<string, string[]>, p: string) => Object.entries(defs).filter(([, ps]) => ps.includes(p)).map(([r]) => r).sort()

export function policyContract(): PolicyContract {
  const roles = platformRoleDefinitions()
  const groups = staffGroupsV2()
  const orgRoles = orgRoleDefinitions()
  const everyOrg = everyOrgDefinitions()
  const rows: ContractRow[] = GENERATED_ROUTE_MAP_V2.map((r) => {
    if (!r.permission) return { ...r, reach: { kind: r.public ? 'public' : 'signed-in' } }
    if (r.org_param) return { ...r, reach: { kind: 'org', orgRoles: holding(orgRoles, r.permission), everyOrg: holding(everyOrg, r.permission) } }
    const rs = holding(roles, r.permission)
    const gs = Object.entries(groups).filter(([, def]) => (def[JINBE] ?? []).some((x) => rs.includes(x))).map(([g]) => g).sort()
    return { ...r, reach: { kind: 'platform', roles: rs, groups: gs } }
  })
  const catalogue: PolicyContract['catalogue'] = {}
  for (const [name, s] of Object.entries(CATALOG_V2)) catalogue[name] = { scope: s.scope, step_up: s.stepUp, delegable: s.delegable, four_eyes: s.fourEyes }
  return {
    version: 1,
    app: JINBE,
    catalogue,
    roles: { [JINBE]: roles },
    groups,
    org_roles: { [JINBE]: orgRoles },
    every_org: { [JINBE]: everyOrg },
    route_map: { [JINBE]: { rules: rows } },
  }
}

export function renderPolicyContract(): string {
  return `${JSON.stringify(policyContract(), null, 2)}\n`
}
