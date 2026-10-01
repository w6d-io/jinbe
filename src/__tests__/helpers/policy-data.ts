import type { PolicyData } from '../../authz/model/resolve.js'
import { buildPolicyData, type IdentityFacts } from '../../authz/model/dataset.js'
import type { OrgAssignments } from '../../services/org-roles.repository.js'
import { everyOrgDefinitions, orgRoleDefinitions, roleDefinitions, staffGroups } from '../../policy/roles.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'

/** The policy data jinbe's code alone defines, over these people (org roles given by identity id). */
export function jinbeData(
  people: Record<string, { id?: string; groups?: string[]; organizations?: string[] }>,
  assignments: OrgAssignments = {},
  orgs: string[] = ['acme', 'globex'],
): PolicyData {
  const identities = new Map<string, IdentityFacts>(Object.entries(people).map(([email, f]) => [email, {
    id: f.id ?? email, groups: f.groups ?? [], organizations: f.organizations ?? [],
  }]))
  return buildPolicyData({
    roles: { jinbe: roleDefinitions() },
    groups: staffGroups(),
    orgRoles: { jinbe: orgRoleDefinitions() },
    everyOrg: { jinbe: everyOrgDefinitions() },
    routeMap: { jinbe: { rules: [...GENERATED_ROUTE_MAP] } },
    orgSites: {},
  }, identities, assignments, orgs)
}

/** A Redis double for the commands the store code uses. */
export function fakeRedis() {
  const strings = new Map<string, string>()
  const hashes = new Map<string, Map<string, string>>()
  const sets = new Map<string, Set<string>>()
  const redis = {
    strings, hashes, sets,
    async get(k: string) { return strings.get(k) ?? null },
    async set(k: string, v: string) { strings.set(k, v); return 'OK' },
    async hget(k: string, f: string) { return hashes.get(k)?.get(f) ?? null },
    async hset(k: string, f: string, v: string) { if (!hashes.has(k)) hashes.set(k, new Map()); hashes.get(k)!.set(f, v); return 1 },
    async sismember(k: string, m: string) { return sets.get(k)?.has(m) ? 1 : 0 },
    async sadd(k: string, m: string) { if (!sets.has(k)) sets.set(k, new Set()); sets.get(k)!.add(m); return 1 },
    multi() {
      const ops: Array<() => void> = []
      const tx = {
        set(k: string, v: string) { ops.push(() => strings.set(k, v)); return tx },
        hset(k: string, f: string, v: string) { ops.push(() => { if (!hashes.has(k)) hashes.set(k, new Map()); hashes.get(k)!.set(f, v) }); return tx },
        sadd(k: string, m: string) { ops.push(() => { if (!sets.has(k)) sets.set(k, new Set()); sets.get(k)!.add(m) }); return tx },
        discard() { ops.length = 0 },
        async exec() { for (const op of ops) op(); return ops.map(() => [null, 'OK']) },
      }
      return tx
    },
  }
  return redis
}
