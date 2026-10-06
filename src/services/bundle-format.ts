import type { GroupDefinition, FlatRolesMap, RouteMap, OathkeeperRule } from './redis-rbac.repository.js'
import type { DirectGrant } from './direct-grants.repository.js'
import type { OrgAssignments } from './org-roles.repository.js'
import { JINBE, isStaffGroup } from '../policy/roles.js'
import { STORE_SECTIONS, storeProblems, type StoreSection, type StoreSections } from './bundle-stores.js'

/**
 * The snapshot format. 1: the RBAC model and the gateway rules. 2: the RBAC model, people's org roles
 * and direct grants, and the stores beside it (bundle-stores.ts); no gateway rules — built-in rules
 * come from the running release's code, site rules from the published sites. A format-1 file still
 * restores: what it lacks is left as it is, its gateway rules are ignored.
 */
export const BUNDLE_VERSION = '2'
export const READABLE_VERSIONS: readonly string[] = ['1', '2']

export interface AuthBundle {
  version: string
  exportedAt: string
  rbac: StoreSections & {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    /** Format 1 only: read, never restored (the rules come from code and the published sites). */
    oathkeeperRules?: OathkeeperRule[]
    /** Org → the sites it is entitled to (rbac:org_sites). */
    orgSites?: Record<string, string[]>
    /** Org → identity id → org roles (rbac:org_assignments): people's org roles, backed up with the rest. */
    orgAssignments?: OrgAssignments
    /** Identity id → direct grants (rbac:direct_grants): people's per-person roles and permissions. */
    directGrants?: Record<string, DirectGrant[]>
    /** Service → org roles; service → every-org map (with the roles section). */
    orgRoles?: Record<string, FlatRolesMap>
    everyOrg?: Record<string, FlatRolesMap>
    /** A bundle exported before org entitlements: read as orgSites on import, jinbe and kuma left out. */
    orgServiceMap?: Record<string, string[]>
  }
}

type RbacSection = 'services' | 'groups' | 'roles' | 'routeMaps' | 'orgSites' | 'orgAssignments' | 'directGrants'
export type BundleSection = RbacSection | StoreSection
export const ALL_BUNDLE_SECTIONS: BundleSection[] = ['services', 'groups', 'roles', 'routeMaps', 'orgSites', 'orgAssignments', 'directGrants', ...STORE_SECTIONS]

/** A full restore: no sections named, or all of them. Anything less is additive. */
export const isFullImport = (sections?: BundleSection[]) => !sections || sections.length === 0 || ALL_BUNDLE_SECTIONS.every((s) => sections.includes(s))

/** Why a file is not a snapshot this release can restore (400), or null. */
export function bundleProblem(bundle: AuthBundle | undefined): string | null {
  if (!bundle?.version || !bundle?.rbac) return 'Invalid bundle format — missing version or rbac fields.'
  if (!READABLE_VERSIONS.includes(String(bundle.version))) return `Unsupported bundle version: ${bundle.version} (this release reads ${READABLE_VERSIONS.join(', ')})`
  const r = bundle.rbac as unknown as Record<string, unknown>
  if (!Array.isArray(r.services) || !r.groups || !r.roles || !r.routeMaps) {
    return 'Incomplete bundle — a restore requires a full snapshot (services, groups, roles, routeMaps).'
  }
  const problems = storeProblems(bundle.rbac)
  return problems.length ? `Invalid bundle: ${problems.join('; ')}` : null
}

/**
 * What an import may never write: what jinbe defines in code (its roles, route map, org roles,
 * every-org map, the staff groups) — the next boot would converge it back anyway, and an import is
 * not a way around "defined in code". A bundle from before the in-place model is read too: its
 * `global` roles and `kuma` service are dropped, its org → service map becomes org entitlements.
 * A section the file does not carry stays absent: absent means "leave as it is", never "empty".
 */
export function withoutOwned(bundle: AuthBundle): AuthBundle {
  const r = bundle.rbac
  // `global` and `kuma` were services of the previous model; neither exists now.
  const drop = (svc: string) => svc === JINBE || svc === 'global' || svc === 'kuma'
  const keep = <T>(m: Record<string, T> | undefined) => Object.fromEntries(Object.entries(m ?? {}).filter(([svc]) => !drop(svc)))
  const orgSites = r.orgSites ?? (r.orgServiceMap ? Object.fromEntries(Object.entries(r.orgServiceMap)
    .map(([org, svcs]) => [org, (Array.isArray(svcs) ? svcs : [svcs as unknown as string]).filter((svc) => !drop(svc))] as const)
    .filter(([, svcs]) => svcs.length > 0)) : undefined)
  return {
    ...bundle,
    rbac: {
      services: (r.services ?? []).filter((svc) => !drop(svc)),
      groups: Object.fromEntries(Object.entries(r.groups ?? {})
        .filter(([name]) => !isStaffGroup(name))
        .map(([name, def]) => [name, Object.fromEntries(Object.entries(def).filter(([svc]) => !drop(svc)))])),
      roles: keep(r.roles),
      routeMaps: keep(r.routeMaps),
      orgSites,
      orgAssignments: r.orgAssignments,
      directGrants: r.directGrants,
      orgRoles: keep(r.orgRoles),
      everyOrg: keep(r.everyOrg),
      sites: r.sites,
      settings: r.settings,
      organizations: r.organizations,
      signup: r.signup,
      metadata: r.metadata,
    },
  }
}

/** What a restore of this file leaves out, in words for the result and the console. */
export function importNotes(incoming: AuthBundle, want: (s: BundleSection) => boolean): string[] {
  const notes: string[] = []
  const rules = incoming.rbac.oathkeeperRules?.length ?? 0
  if (rules > 0) {
    notes.push(`The file's ${rules} gateway ${rules === 1 ? 'rule was' : 'rules were'} not restored: built-in rules come from this release's code, site rules from the published sites.`)
  }
  const lacking = ALL_BUNDLE_SECTIONS.filter((s) => want(s) && s !== 'orgSites' && !(s in incoming.rbac) && !['services', 'groups', 'roles', 'routeMaps'].includes(s))
  if (want('orgSites') && !incoming.rbac.orgSites && !incoming.rbac.orgServiceMap) lacking.unshift('orgSites')
  if (lacking.length) notes.push(`The file (format ${incoming.version}) has no ${lacking.join(', ')}: left as they are.`)
  return notes
}
