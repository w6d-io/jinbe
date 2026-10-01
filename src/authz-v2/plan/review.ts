import { canonicalHash } from '../../bootstrap/hash.js'
import { JINBE_BUILT_IN_ROUTES } from '../../bootstrap/build-route-map.js'
import { isCatalogPermission } from '../../policy/catalog.js'
import { CATALOG_V2, PLATFORM_RENAMES, isV2Permission } from '../catalogue.js'
import { buildDataV2, isQualifiedOrgRole } from '../dataset.js'
import { everyOrgPermissions, orgPermissions, platformPermissions, type DataV2 } from '../resolve.js'
import { JINBE, qualified } from '../roles.js'
import type { V2Keys } from '../dataset.js'
import type { V1Inventory } from './inventory.js'
import { isV1Catalogue, legacyName, v1Holdings } from './v1-model.js'

/**
 * The review list (authz-v2-design §3.3): what v1 holds today, what v2 will decide, and for each
 * person what they gain and lose. Pure over the inventory and the v2 keys, so a fixture tests it and
 * the same live state always gives the same `planHash`.
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
  v1: {
    services: Array<{ name: string; roles: number; rows: number; wildcardRoles: string[] }>
    jinbeRows: { total: number; catalogue: number; alias: number; dead: number; noPermission: number; other: number }
    /** Rows in Redis no built-in produces: dead routes (F5), stale renames (F4), operator rows. */
    staleJinbeRows: Array<{ method: string; path: string; permission: string | null; reason: string }>
    groups: Array<{ name: string; bindings: Record<string, string[]>; members: number; system: boolean; inV2: boolean }>
    roster: Record<string, string[]>
    orgServiceMap: Record<string, string[]>
    orgGrants: Record<string, Record<string, string[]>>
    customOathkeeperRules: string[]
    marker: V1Inventory['marker']
  }
  rules: RuleRow[]
  people: PersonDiff[]
  orphans: {
    memberships: Array<{ email: string; group: string }>
    orgRoles: Array<{ email: string; org: string; role: string; why: string }>
    roster: Array<{ org: string; email: string; member: boolean }>
    orgGrants: Array<{ org: string; email: string; groups: string[] }>
    clients: Array<{ clientId: string; kind: string; owner: string | null; scopes: string[]; retired: string[]; proposed: 'keep' | 'rescope' | 'revoke'; rescopedTo: string[] }>
  }
  migration: {
    rosterToOwner: Array<{ org: string; email: string; assign: string }>
    orgRoleRenames: Array<{ email: string; org: string; from: string; to: string | null }>
    groups: Array<{ v1: string; v2: string | null }>
  }
}

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()
const routeKey = (r: { method: string; path: string; permission?: string | null }) => `${r.method} ${r.path} ${r.permission ?? ''}`

/** The class of a v2 row: who the policy lets through. */
function classOf(r: { permission?: string; org_param?: string; public?: boolean }): RuleRow['class'] {
  if (!r.permission) return r.public ? 'public' : 'signed-in'
  return r.org_param ? 'org' : 'platform'
}

function rulesOf(d: DataV2, people: readonly string[]): RuleRow[] {
  const out: RuleRow[] = []
  for (const [service, map] of Object.entries(d.route_map)) {
    for (const r of map.rules) {
      const spec = r.permission ? CATALOG_V2[r.permission] : undefined
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

function v2Holdings(d: DataV2, email: string): { platform: string[]; org: Record<string, string[]> } {
  const org: Record<string, string[]> = {}
  const everyOrg = everyOrgPermissions(d, email, JINBE)
  if (everyOrg.length) org['*'] = everyOrg
  for (const o of Object.keys(d.org_sites)) {
    const here = orgPermissions(d, email, o, JINBE).filter((p) => !everyOrg.includes(p))
    if (here.length) org[o] = here
  }
  return { platform: platformPermissions(d, email, JINBE), org }
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

/** v1 org role names on identities and what they become (owner decision; default: unmapped). */
const ORG_ROLE_RENAMES: Record<string, string> = { admin: 'jinbe:owner', owner: 'jinbe:owner', org_admin: 'jinbe:owner' }

export function buildPlan(inv: V1Inventory, keys: V2Keys, now = new Date()): Plan {
  const d = buildDataV2(keys, inv.identities, inv.organisations)
  const emails = [...inv.identities.keys()].sort()

  // ── v1 summary ──
  const services = sorted(['global', ...inv.services]).map((name) => ({
    name,
    roles: Object.keys(inv.roles[name] ?? {}).length,
    rows: (inv.routeMaps[name] ?? []).length,
    wildcardRoles: Object.entries(inv.roles[name] ?? {}).filter(([, ps]) => ps.includes('*')).map(([r]) => r).sort(),
  }))
  const jinbeRows = inv.routeMaps.jinbe ?? []
  const count = { total: jinbeRows.length, catalogue: 0, alias: 0, dead: 0, noPermission: 0, other: 0 }
  for (const r of jinbeRows) {
    if (!r.permission) count.noPermission++
    else if (isCatalogPermission(r.permission)) count.catalogue++
    else if (legacyName(r.permission) === 'alias') count.alias++
    else if (legacyName(r.permission) === 'dead') count.dead++
    else count.other++
  }
  const builtIn = new Set(JINBE_BUILT_IN_ROUTES.map(routeKey))
  const builtInPaths = new Set(JINBE_BUILT_IN_ROUTES.map((r) => `${r.method} ${r.path}`))
  const staleJinbeRows = jinbeRows.filter((r) => !builtIn.has(routeKey(r))).map((r) => ({
    method: r.method, path: r.path, permission: r.permission ?? null,
    reason: builtInPaths.has(`${r.method} ${r.path}`) ? 'stale permission on a live route (F4) or an operator row' : 'no route behind it (F5) or an operator row',
  }))
  const memberCount = (g: string) => emails.filter((e) => (inv.identities.get(e)?.groups ?? []).includes(g)).length
  const groups = Object.entries(inv.groups).sort(([a], [b]) => a.localeCompare(b)).map(([name, bindings]) => ({
    name, bindings, members: memberCount(name), system: inv.systemGroups.includes(name), inV2: name in d.groups,
  }))

  // ── people ──
  const people: PersonDiff[] = []
  for (const email of emails) {
    const v1 = v1Holdings(inv, email)
    const before = { platform: v1.platform, org: v1.org }
    const after = v2Holdings(d, email)
    const b = flat(before)
    const a = flat(after)
    if (b.length === 0 && a.length === 0) continue
    const aSet = new Set(a)
    const bSet = new Set(b)
    people.push({ email, before, after, gains: a.filter((p) => !covered(p, bSet)), losses: b.filter((p) => !covered(p, aSet)) })
  }

  // ── orphans ──
  const memberships: Plan['orphans']['memberships'] = []
  const orgRoles: Plan['orphans']['orgRoles'] = []
  const orgRoleRenames: Plan['migration']['orgRoleRenames'] = []
  for (const email of emails) {
    const f = inv.identities.get(email)!
    for (const g of f.groups) if (!(g in d.groups) && g !== 'users') memberships.push({ email, group: g })
    for (const [org, roles] of Object.entries(f.organizationRoles)) {
      for (const role of roles) {
        const member = f.organizations.includes(org)
        if (isQualifiedOrgRole(role) && member) continue
        orgRoles.push({ email, org, role, why: !member ? 'not a member of the org' : 'not a qualified svc:role' })
        if (member && !isQualifiedOrgRole(role)) orgRoleRenames.push({ email, org, from: role, to: ORG_ROLE_RENAMES[role] ?? null })
      }
    }
  }
  const roster: Plan['orphans']['roster'] = []
  const rosterToOwner: Plan['migration']['rosterToOwner'] = []
  for (const [org, admins] of Object.entries(inv.orgAdmins)) {
    for (const email of admins) {
      const id = [...inv.identities.keys()].find((e) => e.toLowerCase() === email.toLowerCase())
      const member = !!id && (inv.identities.get(id)?.organizations ?? []).includes(org)
      roster.push({ org, email, member })
      if (member) rosterToOwner.push({ org, email: id!, assign: qualified(JINBE, 'owner') })
    }
  }
  const orgGrants = Object.entries(inv.orgGrants).flatMap(([org, byEmail]) =>
    Object.entries(byEmail).filter(([, gs]) => gs.length).map(([email, gs]) => ({ org, email, groups: sorted(gs) })))
  const clients = (inv.clients ?? []).map((c) => {
    const retired = c.scopes.filter((s) => legacyName(s) !== null || (isV1Catalogue(s) && !isV2Permission(s)))
    const rescopedTo = sorted(c.scopes.flatMap((s) => {
      if (legacyName(s) === null && !(isV1Catalogue(s) && !isV2Permission(s))) return [s]
      const renamed = PLATFORM_RENAMES[s as keyof typeof PLATFORM_RENAMES]
      return renamed ? [renamed] : []
    }))
    const proposed: 'keep' | 'rescope' | 'revoke' = retired.length === 0 ? 'keep' : rescopedTo.length > 0 ? 'rescope' : 'revoke'
    return { clientId: c.clientId, kind: c.kind, owner: c.owner, scopes: c.scopes, retired, proposed, rescopedTo }
  }).filter((c) => c.proposed !== 'keep')

  const migrationGroups = Object.keys(inv.groups).sort().map((g) => ({ v1: g, v2: g in d.groups ? g : null }))

  const body: Omit<Plan, 'generatedAt' | 'planHash'> = {
    version: 1,
    unavailable: inv.unavailable,
    v1: {
      services, jinbeRows: count, staleJinbeRows, groups,
      roster: inv.orgAdmins, orgServiceMap: inv.orgServices, orgGrants: inv.orgGrants,
      customOathkeeperRules: inv.oathkeeperRuleIds, marker: inv.marker,
    },
    rules: rulesOf(d, emails),
    people,
    orphans: { memberships, orgRoles, roster, orgGrants, clients },
    migration: { rosterToOwner, orgRoleRenames, groups: migrationGroups },
  }
  return { ...body, generatedAt: now.toISOString(), planHash: canonicalHash(body) }
}
