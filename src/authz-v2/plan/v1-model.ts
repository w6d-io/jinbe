import { ALIASES, CATALOG, EVERYTHING, PERMISSIONS, effectivePermissions } from '../../policy/catalog.js'
import { ORG_ADMIN_PERMISSIONS } from '../../services/org-admin.js'
import { ORG_PERMISSIONS, platformNameOf } from '../catalogue.js'
import type { V1Inventory } from './inventory.js'

/**
 * What a person holds in jinbe under v1, recomputed from the live inventory, in v2 NAMES so the two
 * models compare permission by permission. It mirrors jinbe's own app layer (what the guards allow),
 * which is wider than the v1 gateway on org routes (finding F1):
 *
 *   platform  groups → roles under `global` and `jinbe` → permissions; `*` and the legacy aliases
 *             expanded (catalog.effectivePermissions)
 *   org X     `*` → every org permission (super_admin, and kuma's `admin: *` through
 *             org_service_map, F3); a platform holder of an org permission → it in every org;
 *             roster admin of X who is a member → the org-management set; org grants in X → the
 *             roles those groups bind under X's services, expanded the same way
 *
 * `--opa` checks the platform part against OPA's own `rbac.user_info`, person by person.
 */

export interface V1Holdings {
  /** v2 platform names. */
  platform: string[]
  /** org → v2 org names; `*` key = in every org. */
  org: Record<string, string[]>
  /** Raw names held that are neither catalogue leaves nor aliases (dead, or a site's). */
  unknown: string[]
  wildcard: boolean
}

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort()
const orgSet = new Set<string>(ORG_PERMISSIONS)

function rolePermissions(inv: V1Inventory, groups: readonly string[], services: readonly string[]): string[] {
  const out: string[] = []
  for (const g of groups) {
    const def = inv.groups[g] ?? {}
    for (const svc of services) for (const role of def[svc] ?? []) out.push(...(inv.roles[svc]?.[role] ?? []))
  }
  return out
}

/** v1 catalogue names held → their v2 platform names, and the org ones kept apart. */
function split(held: readonly string[]): { platform: string[]; org: string[] } {
  const eff = effectivePermissions(held)
  return {
    platform: sorted(eff.map(platformNameOf).filter((p): p is string => p !== null)),
    org: sorted(eff.filter((p) => orgSet.has(p))),
  }
}

export function v1Holdings(inv: V1Inventory, email: string): V1Holdings {
  const facts = inv.identities.get(email)
  const groups = facts?.groups ?? []
  const raw = rolePermissions(inv, groups, ['global', 'jinbe'])
  const wildcard = raw.includes(EVERYTHING)
  const { platform, org: globalOrg } = split(raw)
  const known = new Set<string>([...PERMISSIONS, ...Object.keys(ALIASES), EVERYTHING])
  const unknown = sorted(raw.filter((p) => !known.has(p)))

  const org: Record<string, string[]> = {}
  if (wildcard) org['*'] = [...ORG_PERMISSIONS].sort()
  else if (globalOrg.length) org['*'] = globalOrg

  const lower = email.toLowerCase()
  const memberOf = facts?.organizations ?? []
  for (const o of memberOf) {
    const here: string[] = []
    // F3: a member of an org mapped to a service where they hold `*` holds everything there.
    const services = inv.orgServices[o] ?? []
    const viaServices = rolePermissions(inv, groups, services)
    if (viaServices.includes(EVERYTHING)) here.push(...ORG_PERMISSIONS)
    else here.push(...split(viaServices).org)
    if ((inv.orgAdmins[o] ?? []).some((a) => a.toLowerCase() === lower)) {
      here.push(...split([...ORG_ADMIN_PERMISSIONS]).org, 'org.audit:read')
    }
    const granted = Object.entries(inv.orgGrants[o] ?? {}).find(([e]) => e.toLowerCase() === lower)?.[1] ?? []
    const viaGrants = rolePermissions(inv, granted, services.length ? services : ['jinbe'])
    if (viaGrants.includes(EVERYTHING)) here.push(...ORG_PERMISSIONS)
    else here.push(...split(viaGrants).org)
    const all = sorted(here.filter((p) => !(org['*'] ?? []).includes(p)))
    if (all.length) org[o] = all
  }
  return { platform, org, unknown, wildcard }
}

/** The legacy name a scope or a role still carries, if any (alias, dead `admin:*`, `*`). */
export function legacyName(name: string): 'wildcard' | 'alias' | 'dead' | null {
  if (name === EVERYTHING) return 'wildcard'
  if (Object.prototype.hasOwnProperty.call(ALIASES, name)) return 'alias'
  if (/^admin:(create|update|delete)$/.test(name) || name === 'rbac:write_system' || name === 'read') return 'dead'
  return null
}

export function isV1Catalogue(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(CATALOG, name)
}
