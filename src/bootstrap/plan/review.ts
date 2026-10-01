import { canonicalHash } from '../hash.js'
import { CATALOG, isCatalogPermission } from '../../policy/catalog.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'
import { buildPolicyData, type StoredModel } from '../../authz/model/dataset.js'
import { orgPermissions, platformPermissions, type PolicyData } from '../../authz/model/resolve.js'
import { JINBE, everyOrgDefinitions, isStaffGroup, orgRoleDefinitions, qualified, roleDefinitions, staffGroups } from '../../policy/roles.js'
import { QUALIFIED_ROLE } from '../../services/org-roles.repository.js'
import type { Inventory } from './inventory.js'
import { beforeHoldings, holdingsIn, legacyName, renamedTo } from './v1-model.js'
import { ORG_ROLE_RENAMES, migrationOf, siteOrgRoleOf, type Migration } from './migration.js'

/**
 * The review list (authz-v2-design §3.3): what the store holds today, what the model will decide once
 * `--apply` has wiped and reseeded it (code + the applied sites + the migration map), and for each
 * person what they gain and lose. Pure over the inventory, so a fixture tests it and the same live
 * state always gives the same `planHash` — which `--apply --expect` checks before writing anything.
 */

export interface RuleRow {
  service: string
  method: string
  path: string
  class: 'public' | 'signed-in' | 'platform' | 'org'
  permission: string | null
  /** Roles carrying it: platform `app:role`, org `svc:role`, every-org `app:role (every org)`. */
  roles: string[]
  groups: string[]
  holders: { count: number; emails: string[] }
  stepUp: boolean
  fourEyes: boolean
  delegable: 'direct' | 'never' | null
}

export interface PersonDiff {
  email: string
  before: { platform: string[]; org: Record<string, string[]> }
  after: { platform: string[]; org: Record<string, string[]> }
  gains: string[]
  losses: string[]
}

export interface Plan {
  version: 1
  generatedAt: string
  planHash: string
  unavailable: string[]
  before: {
    services: Array<{ name: string; roles: number; rows: number; wildcardRoles: string[] }>
    jinbeRows: { total: number; catalogue: number; alias: number; dead: number; noPermission: number; other: number }
    /** Rows in Redis no built-in produces: dead routes (F5), stale renames (F4), operator rows. */
    staleJinbeRows: Array<{ method: string; path: string; permission: string | null; reason: string }>
    groups: Array<{ name: string; bindings: Record<string, string[]>; members: number; system: boolean; kept: boolean }>
    roster: Record<string, string[]>
    orgServiceMap: Record<string, string[]>
    orgGrants: Record<string, Record<string, string[]>>
    customOathkeeperRules: string[]
    marker: Inventory['marker']
    /** Applied sites whose intent could not be rendered: the apply leaves them unpublished. */
    siteFailures: Inventory['siteFailures']
    /** Sites whose stored intent holds a wildcard: the apply saves each a new version, made explicit. */
    sitesMadeExplicit: string[]
  }
  rules: RuleRow[]
  people: PersonDiff[]
  /**
   * The losses to approve, by group: what EVERY member of a group loses (e.g. D1 — staff-ops losing
   * org.keys:* in every org). Shown first in the review so a model decision is read as one line, not
   * scattered over each person. `everyOrg`: the part that was reach into every organisation (`@*`).
   */
  lossesByGroup: Array<{ group: string; members: string[]; losses: string[]; everyOrg: string[] }>
  orphans: {
    memberships: Array<{ email: string; group: string }>
    orgRoles: Array<{ email: string; org: string; role: string; why: string }>
    roster: Array<{ org: string; email: string; member: boolean }>
    orgGrants: Array<{ org: string; email: string; groups: string[] }>
    /** owner: org id, or the person's identity id; ownerEmail: that person's address when known. */
    clients: Array<{ clientId: string; kind: string; owner: string | null; ownerEmail: string | null; registeredAt?: string | null; scopes: string[]; retired: string[]; proposed: 'keep' | 'rescope' | 'revoke'; rescopedTo: string[] }>
  }
  migration: {
    /** Org roles the apply writes, and where each comes from. */
    orgRoles: Migration['added']
    orgRoleRenames: Array<{ email: string; org: string; from: string; to: string | null }>
    groups: Array<{ before: string; after: string | null }>
    orgSites: Record<string, string[]>
  }
}

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()
const routeKey = (r: { method: string; path: string; permission?: string | null }) => `${r.method} ${r.path} ${r.permission ?? ''}`

/** The class of a v2 row: who the policy lets through. */
function classOf(r: { permission?: string; org_param?: string; public?: boolean }): RuleRow['class'] {
  if (!r.permission) return r.public ? 'public' : 'signed-in'
  return r.org_param ? 'org' : 'platform'
}

function rulesOf(d: PolicyData, people: readonly string[]): RuleRow[] {
  const out: RuleRow[] = []
  for (const [service, map] of Object.entries(d.route_map)) {
    for (const r of map.rules) {
      const spec = r.permission && isCatalogPermission(r.permission) ? CATALOG[r.permission] : undefined
      const roles: string[] = []
      const groups: string[] = []
      if (r.permission) {
        const carrying = r.org_param ? d.every_org[service] ?? {} : d.roles[service] ?? {}
        for (const [role, perms] of Object.entries(carrying)) if (perms.includes(r.permission)) roles.push(r.org_param ? `${service}:${role} (every org)` : `${service}:${role}`)
        if (r.org_param) for (const [svc, rs] of Object.entries(d.org_roles)) for (const [role, perms] of Object.entries(rs)) if (perms.includes(r.permission)) roles.push(qualified(svc, role))
        const bound = Object.entries(carrying).filter(([, perms]) => perms.includes(r.permission!)).map(([role]) => role)
        for (const [g, def] of Object.entries(d.groups)) if ((def[service] ?? []).some((role) => bound.includes(role))) groups.push(g)
      }
      const holders = !r.permission ? [] : people.filter((e) => r.org_param
        ? Object.keys(d.org_sites).some((o) => orgPermissions(d, e, o, service).includes(r.permission!))
        : platformPermissions(d, e, service).includes(r.permission!))
      out.push({
        service, method: r.method, path: r.path, class: classOf(r), permission: r.permission ?? null,
        roles: sorted(roles), groups: sorted(groups),
        holders: { count: holders.length, emails: holders },
        stepUp: spec?.stepUp ?? false, fourEyes: spec?.fourEyes === 'prod', delegable: spec?.delegable ?? null,
      })
    }
  }
  return out.sort((a, b) => a.service.localeCompare(b.service) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
}

/** `p` and `org:p` names, for a flat gains/losses list. */
function flat(h: { platform: string[]; org: Record<string, string[]> }): string[] {
  return sorted([...h.platform, ...Object.entries(h.org).flatMap(([o, ps]) => ps.map((p) => `${p}@${o}`))])
}

/** Where a permission held in one org is also covered by `*@every org`. */
function covered(name: string, set: Set<string>): boolean {
  if (set.has(name)) return true
  const at = name.lastIndexOf('@')
  return at > 0 && set.has(`${name.slice(0, at)}@*`)
}

/**
 * What the store holds once `--apply` has run: jinbe's code-owned model, each applied site's own
 * definitions (its applied intent rendered, wildcards made explicit — what the reseed writes), and
 * the migration map. Groups that
 * neither code nor a site defines are gone; their memberships stay on the identity (D4).
 */
export function afterModel(inv: Inventory, migration: Migration): StoredModel & { assignments: Migration['assignments'] } {
  const sites = Object.entries(inv.siteModels)
  const bySite = <T>(pick: (m: Inventory['siteModels'][string]) => T) => Object.fromEntries(sites.map(([svc, m]) => [svc, pick(m)]))
  // The staff groups, then each site's column in the groups its intent names (what its publish writes).
  const groups: Record<string, Record<string, string[]>> = { ...staffGroups() }
  for (const [svc, m] of sites) {
    for (const [g, roles] of Object.entries(m.groups)) if (!isStaffGroup(g)) groups[g] = { ...(groups[g] ?? {}), [svc]: roles }
  }
  return {
    roles: { ...bySite((m) => m.roles), [JINBE]: roleDefinitions() },
    groups,
    orgRoles: { ...bySite((m) => m.orgRoles), [JINBE]: orgRoleDefinitions() },
    everyOrg: { ...bySite((m) => m.everyOrg), [JINBE]: everyOrgDefinitions() },
    routeMap: { ...bySite((m) => ({ rules: m.routeMap })), [JINBE]: { rules: [...GENERATED_ROUTE_MAP] } },
    orgSites: migration.orgSites,
    assignments: migration.assignments,
  }
}

export function buildPlan(inv: Inventory, now = new Date()): Plan {
  const migration = migrationOf(inv)
  const model = afterModel(inv, migration)
  // Direct grants are people's data: kept by the apply, so they count after it as before.
  const d = buildPolicyData(model, inv.identities, model.assignments, inv.organisations, inv.directGrants)
  const emails = [...inv.identities.keys()].sort()

  // ── today ──
  const services = sorted([...Object.keys(inv.roles), ...inv.services]).map((name) => ({
    name,
    roles: Object.keys(inv.roles[name] ?? {}).length,
    rows: (inv.routeMaps[name] ?? []).length,
    wildcardRoles: Object.entries(inv.roles[name] ?? {}).filter(([, ps]) => ps.includes('*')).map(([r]) => r).sort(),
  }))
  const jinbeRows = inv.routeMaps[JINBE] ?? []
  const count = { total: jinbeRows.length, catalogue: 0, alias: 0, dead: 0, noPermission: 0, other: 0 }
  for (const r of jinbeRows) {
    if (!r.permission) count.noPermission++
    else if (isCatalogPermission(r.permission)) count.catalogue++
    else if (legacyName(r.permission) === 'alias') count.alias++
    else if (legacyName(r.permission) === 'dead') count.dead++
    else count.other++
  }
  const generated = new Set(GENERATED_ROUTE_MAP.map(routeKey))
  const generatedPaths = new Set(GENERATED_ROUTE_MAP.map((r) => `${r.method} ${r.path}`))
  const staleJinbeRows = jinbeRows.filter((r) => !generated.has(routeKey(r))).map((r) => ({
    method: r.method, path: r.path, permission: r.permission ?? null,
    reason: generatedPaths.has(`${r.method} ${r.path}`) ? 'a permission the route no longer declares (alias, rename, F4) or an operator row' : 'no route behind it (F5) or an operator row',
  }))
  const memberCount = (g: string) => emails.filter((e) => (inv.identities.get(e)?.groups ?? []).includes(g)).length
  const groups = Object.entries(inv.groups).sort(([a], [b]) => a.localeCompare(b)).map(([name, bindings]) => ({
    name, bindings, members: memberCount(name), system: inv.systemGroups.includes(name), kept: name in d.groups,
  }))

  // ── people ──
  const people: PersonDiff[] = []
  for (const email of emails) {
    const before = beforeHoldings(inv, email)
    const after = holdingsIn(d, email)
    const b = flat(before)
    const a = flat(after)
    if (b.length === 0 && a.length === 0) continue
    const aSet = new Set(a)
    const bSet = new Set(b)
    people.push({ email, before, after, gains: a.filter((p) => !covered(p, bSet)), losses: b.filter((p) => !covered(p, aSet)) })
  }

  // ── losses shared by a whole group (what the owner approves as a decision) ──
  const lossesByGroup: Plan['lossesByGroup'] = []
  const losing = new Map(people.filter((p) => p.losses.length).map((p) => [p.email, p.losses]))
  const groupNames = sorted([...Object.keys(inv.groups), ...Object.keys(staffGroups())])
  for (const group of groupNames) {
    const members = emails.filter((e) => (inv.identities.get(e)?.groups ?? []).includes(group))
    if (members.length === 0 || !members.every((e) => losing.has(e))) continue
    const shared = members.map((e) => losing.get(e)!).reduce((acc, l) => acc.filter((p) => l.includes(p)))
    if (shared.length === 0) continue
    lossesByGroup.push({ group, members, losses: shared, everyOrg: shared.filter((p) => p.endsWith('@*')) })
  }
  lossesByGroup.sort((a, b) => b.members.length - a.members.length || a.group.localeCompare(b.group))

  // ── orphans ──
  const memberships: Plan['orphans']['memberships'] = []
  const orgRoles: Plan['orphans']['orgRoles'] = []
  const orgRoleRenames: Plan['migration']['orgRoleRenames'] = []
  for (const email of emails) {
    const f = inv.identities.get(email)!
    for (const g of f.groups) if (!(g in d.groups) && g !== 'users') memberships.push({ email, group: g })
    for (const [org, roles] of Object.entries(f.organizationRoles)) {
      const member = f.organizations.includes(org)
      for (const role of roles) {
        const to = QUALIFIED_ROLE.test(role) ? role : ORG_ROLE_RENAMES[role] ?? null
        if (!member) orgRoles.push({ email, org, role, why: 'not a member of the org' })
        else if (!to) orgRoles.push({ email, org, role, why: 'no org role it maps to' })
        if (member && !QUALIFIED_ROLE.test(role)) orgRoleRenames.push({ email, org, from: role, to })
      }
    }
  }
  for (const [org, members] of Object.entries(inv.orgAssignments)) {
    for (const id of Object.keys(members)) {
      const who = [...inv.identities.entries()].find(([, f]) => f.id === id)
      if (!who) orgRoles.push({ email: `(id ${id})`, org, role: members[id].join(','), why: 'no such identity' })
      else if (!who[1].organizations.includes(org)) orgRoles.push({ email: who[0], org, role: members[id].join(','), why: 'not a member of the org' })
    }
  }
  const roster: Plan['orphans']['roster'] = []
  for (const [org, admins] of Object.entries(inv.orgAdmins)) {
    for (const email of admins) {
      const id = [...inv.identities.keys()].find((e) => e.toLowerCase() === email.toLowerCase())
      roster.push({ org, email, member: !!id && (inv.identities.get(id)?.organizations ?? []).includes(org) })
    }
  }
  // Org grants the migration does not carry (no site org role behind the group).
  const orgGrants = Object.entries(inv.orgGrants).flatMap(([org, byEmail]) =>
    Object.entries(byEmail).map(([email, gs]) => ({ org, email, groups: sorted(gs.filter((g) => !siteOrgRoleOf(inv, g))) })).filter((g) => g.groups.length))
  const emailOf = new Map([...inv.identities.entries()].filter(([, f]) => f.id).map(([email, f]) => [f.id as string, email]))
  const clients = (inv.clients ?? []).map((c) => {
    const retired = c.scopes.filter((s) => legacyName(s) !== null)
    const rescopedTo = sorted(c.scopes.flatMap((s) => {
      if (legacyName(s) === null) return [s]
      const renamed = renamedTo(s)
      return renamed ? [renamed] : []
    }))
    // An MCP client nobody ever consented to (no bound person) is not re-scoped: it is revoked.
    const unboundMcp = c.kind === 'mcp' && !c.owner
    const proposed: 'keep' | 'rescope' | 'revoke' = retired.length === 0 ? 'keep' : unboundMcp ? 'revoke' : rescopedTo.length > 0 ? 'rescope' : 'revoke'
    const ownerEmail = c.kind === 'personal' || c.kind === 'mcp' ? (c.owner ? emailOf.get(c.owner) ?? null : null) : null
    return {
      clientId: c.clientId, kind: c.kind, owner: c.owner, ownerEmail, ...(c.registeredAt !== undefined ? { registeredAt: c.registeredAt } : {}),
      scopes: c.scopes, retired, proposed, rescopedTo: unboundMcp ? [] : rescopedTo,
    }
  }).filter((c) => c.proposed !== 'keep')

  const body: Omit<Plan, 'generatedAt' | 'planHash'> = {
    version: 1,
    unavailable: inv.unavailable,
    before: {
      services, jinbeRows: count, staleJinbeRows, groups,
      roster: inv.orgAdmins, orgServiceMap: inv.orgServices, orgGrants: inv.orgGrants,
      customOathkeeperRules: inv.oathkeeperRuleIds, marker: inv.marker, siteFailures: inv.siteFailures,
      sitesMadeExplicit: inv.sitesMadeExplicit ?? [],
    },
    rules: rulesOf(d, emails),
    people,
    lossesByGroup,
    orphans: { memberships, orgRoles, roster, orgGrants, clients },
    migration: {
      orgRoles: migration.added,
      orgRoleRenames,
      groups: Object.keys(inv.groups).sort().map((g) => ({ before: g, after: g in d.groups ? g : null })),
      orgSites: migration.orgSites,
    },
  }
  return { ...body, generatedAt: now.toISOString(), planHash: canonicalHash(body) }
}
