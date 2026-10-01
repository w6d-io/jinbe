import type { DataV2 } from '../../authz-v2/resolve.js'
import { buildDataV2, type IdentityFacts } from '../../authz-v2/dataset.js'
import { everyOrgDefinitions, orgRoleDefinitions, platformRoleDefinitions, staffGroupsV2 } from '../../authz-v2/roles.js'
import { GENERATED_ROUTE_MAP_V2 } from '../../authz-v2/route-map.generated.js'

/** data.v2 as jinbe's code alone defines it, over these people. */
export function jinbeData(people: Record<string, Partial<IdentityFacts>>, orgs: string[] = ['acme', 'globex']): DataV2 {
  const identities = new Map(Object.entries(people).map(([email, f]) => [email, {
    groups: f.groups ?? [], organizations: f.organizations ?? [], organizationRoles: f.organizationRoles ?? {},
  }]))
  return buildDataV2({
    apps: ['jinbe'],
    roles: { jinbe: platformRoleDefinitions() },
    groups: staffGroupsV2(),
    orgRoles: { jinbe: orgRoleDefinitions() },
    everyOrg: { jinbe: everyOrgDefinitions() },
    routeMap: { jinbe: { rules: [...GENERATED_ROUTE_MAP_V2] } },
  }, identities, orgs)
}

/** A Redis double for the commands store.ts uses: get, set, mget, multi (set, discard, exec). */
export function fakeRedis() {
  const data = new Map<string, string>()
  const redis = {
    data,
    async get(k: string) { return data.get(k) ?? null },
    async set(k: string, v: string) { data.set(k, v); return 'OK' },
    async mget(...ks: string[]) { return ks.map((k) => data.get(k) ?? null) },
    multi() {
      const ops: Array<[string, string]> = []
      const tx = {
        set(k: string, v: string) { ops.push([k, v]); return tx },
        discard() { ops.length = 0 },
        async exec() { for (const [k, v] of ops) data.set(k, v); return ops.map(() => [null, 'OK']) },
      }
      return tx
    },
  }
  return redis
}
