import { CATALOG } from './catalog.js'
import { JINBE, everyOrgDefinitions, orgRoleDefinitions, roleDefinitions, staffGroups } from './roles.js'
import { GENERATED_ROUTE_MAP } from './route-map.generated.js'
import type { RouteRule } from '../services/redis-rbac.repository.js'
import type { DirectBinding } from '../services/direct-grants.repository.js'
import type { PolicyData } from '../authz/model/resolve.js'
import { orgPermissions, platformPermissions } from '../authz/model/resolve.js'

/**
 * policy-contract.json (authz-v2-design §3.5): what jinbe's model says, for opal-policies CI to test
 * `package rbac` against. Each route row lists exactly who must reach it:
 *
 *   platform row   the platform roles holding its permission (through the group binding them)
 *   org row        the org roles holding it (assigned in that org, to a member, org entitled) and the
 *                  platform roles whose every-org entry holds it
 *   no permission  `public` or `signed-in`
 *
 * and, by omission, that nobody else does. Deterministic: sorted keys, no timestamp.
 *
 * `direct_grants` carries worked examples of per-person grants (data.bindings.direct): for each, the
 * bindings to load and what the person must then hold in jinbe, platform-wide and per org — computed
 * by the same resolver the plan uses, for opal-policies to replay against `package rbac`.
 */

export interface DirectGrantExample {
  name: string
  email: string
  bindings: { direct: Record<string, DirectBinding>; user_organizations: Record<string, string[]> }
  expect: { platform: string[]; orgs: Record<string, string[]> }
}

export interface ContractRow extends RouteRule {
  reach:
    | { kind: 'public' | 'signed-in' }
    | { kind: 'platform'; roles: string[]; groups: string[] }
    | { kind: 'org'; orgRoles: string[]; everyOrg: string[] }
    /** scope any_org: held in some org — an org role assigned to a member there, or the every-org map. */
    | { kind: 'any_org'; orgRoles: string[]; everyOrg: string[] }
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
  direct_grants: { examples: DirectGrantExample[] }
}

const holding = (defs: Record<string, string[]>, p: string) => Object.entries(defs).filter(([, ps]) => ps.includes(p)).map(([r]) => r).sort()

export function policyContract(): PolicyContract {
  const roles: Record<string, string[]> = roleDefinitions()
  const groups = staffGroups()
  const orgRoles = orgRoleDefinitions()
  const everyOrg = everyOrgDefinitions()
  const rows: ContractRow[] = GENERATED_ROUTE_MAP.map((r) => {
    if (!r.permission) return { ...r, reach: { kind: r.public ? 'public' : 'signed-in' } }
    if (r.scope === 'any_org') return { ...r, reach: { kind: 'any_org', orgRoles: holding(orgRoles, r.permission), everyOrg: holding(everyOrg, r.permission) } }
    if (r.org_param) return { ...r, reach: { kind: 'org', orgRoles: holding(orgRoles, r.permission), everyOrg: holding(everyOrg, r.permission) } }
    const rs = holding(roles, r.permission)
    const gs = Object.entries(groups).filter(([, def]) => (def[JINBE] ?? []).some((x) => rs.includes(x))).map(([g]) => g).sort()
    return { ...r, reach: { kind: 'platform', roles: rs, groups: gs } }
  })
  const catalogue: PolicyContract['catalogue'] = {}
  for (const [name, s] of Object.entries(CATALOG)) catalogue[name] = { scope: s.scope, step_up: s.stepUp, delegable: s.delegable, four_eyes: s.fourEyes }
  return {
    version: 1,
    app: JINBE,
    catalogue,
    roles: { [JINBE]: roles },
    groups,
    org_roles: { [JINBE]: orgRoles },
    every_org: { [JINBE]: everyOrg },
    route_map: { [JINBE]: { rules: rows } },
    direct_grants: { examples: directGrantExamples(roles, orgRoles, everyOrg) },
  }
}

const ORG = 'org-example'

/** Per-person grant cases, each resolved like the policy must (exact names; membership; entitlement). */
function directGrantExamples(roles: Record<string, string[]>, orgRoles: Record<string, string[]>, everyOrg: Record<string, string[]>): DirectGrantExample[] {
  const slot = (r: string[] = [], p: string[] = []) => ({ roles: r.map((name) => ({ name })), permissions: p.map((name) => ({ name })) })
  const cases: Array<Omit<DirectGrantExample, 'expect'>> = [
    { name: 'a platform permission, alone', email: 'perm@example.com', bindings: { direct: { 'perm@example.com': { platform: { [JINBE]: slot([], ['users:read']) } } }, user_organizations: {} } },
    { name: 'a platform role', email: 'role@example.com', bindings: { direct: { 'role@example.com': { platform: { [JINBE]: slot(['developer']) } } }, user_organizations: {} } },
    { name: 'an org role, for a member', email: 'member@example.com', bindings: { direct: { 'member@example.com': { orgs: { [ORG]: { [JINBE]: slot(['viewer']) } } } }, user_organizations: { 'member@example.com': [ORG] } } },
    { name: 'an org permission, for a member', email: 'orgperm@example.com', bindings: { direct: { 'orgperm@example.com': { orgs: { [ORG]: { [JINBE]: slot([], ['org.keys:read']) } } } }, user_organizations: { 'orgperm@example.com': [ORG] } } },
    { name: 'an expired grant counts for nothing (the policy checks expires_at too)', email: 'expired@example.com', bindings: { direct: { 'expired@example.com': { platform: { [JINBE]: { roles: [], permissions: [{ name: 'users:read', expires_at: '2000-01-01T00:00:00Z' }] } } } }, user_organizations: {} } },
    { name: 'a direct role carries its every-org reach', email: 'support@example.com', bindings: { direct: { 'support@example.com': { platform: { [JINBE]: slot(['security']) } } }, user_organizations: {} } },
    { name: 'an org grant without membership counts for nothing', email: 'outsider@example.com', bindings: { direct: { 'outsider@example.com': { orgs: { [ORG]: { [JINBE]: slot(['owner']) } } } }, user_organizations: {} } },
  ]
  return cases.map((c) => {
    const d: PolicyData = {
      roles: { [JINBE]: roles }, groups: {}, group_membership: {}, user_organizations: c.bindings.user_organizations,
      org_roles: { [JINBE]: orgRoles }, org_assignments: {}, direct: c.bindings.direct, every_org: { [JINBE]: everyOrg },
      org_sites: { [ORG]: [JINBE] }, route_map: {},
    }
    const inOrg = orgPermissions(d, c.email, ORG, JINBE)
    const orgs: Record<string, string[]> = inOrg.length ? { [ORG]: inOrg } : {}
    return { ...c, expect: { platform: platformPermissions(d, c.email, JINBE), orgs } }
  })
}

export function renderPolicyContract(): string {
  return `${JSON.stringify(policyContract(), null, 2)}\n`
}
