import { getRedisClient } from './redis-client.service.js'
import { sitesRepository, type SiteRecord, type SiteVersion } from '../sites/repository.js'
import { SITE_NAME_PATTERN } from '../sites/schemas.js'
import { dropOrganisationCaches } from './organisation-store/registry.js'
import { JINBE, isStaffGroup } from '../policy/roles.js'

/**
 * The parts of a snapshot (format 2) beside the RBAC model: what people configured that no code and no
 * site intent can give back.
 *
 *   sites          rbac:sites + rbac:sites:versions:<name>    site intents and their history
 *   settings       rbac:config                                 platform settings (sign-in, 2FA, MCP…)
 *   organizations  rbac:organisations                          the organization records
 *                  jinbe:org_invitations                       pending invitations into them
 *   signup         rbac:signup:org_sites, rbac:org_domains     orgs made by a sign-up, domain claims
 *   metadata       rbac:services:meta, rbac:groups:meta        descriptions, who created what
 *
 * Hashes travel as their raw field values, so a restore writes back exactly what was read. What jinbe
 * defines in code (jinbe's service metadata, the staff groups' metadata) is neither exported nor restored.
 *
 * A restore never deletes an organization: one created after the snapshot (a customer who signed up)
 * still has members on their identities. Everything scoped to an org is restored exactly for the orgs
 * the snapshot has (orgsInSnapshot) and left untouched for every other.
 */

export interface SitesSection {
  records: SiteRecord[]
  versions: Record<string, SiteVersion[]>
}
export interface StoreSections {
  sites?: SitesSection
  settings?: Record<string, string>
  /** A file from before this rule may carry `deployments` too: ignored (they grant nothing). */
  organizations?: { registry: Record<string, string>; invitations?: Record<string, string> }
  signup?: { orgSites: Record<string, string>; domains: Record<string, string> }
  metadata?: { services: Record<string, string>; groups: Record<string, string> }
}
export type StoreSection = keyof StoreSections
export const STORE_SECTIONS: StoreSection[] = ['sites', 'settings', 'organizations', 'signup', 'metadata']

/** What a restore did to the stores: the sites written back, the ones left as they are, and counts. */
export interface StoresResult {
  sites?: { restored: string[]; kept: string[] }
  settings?: number
  organizations?: number
  signup?: number
  metadata?: number
}

const CONFIG = 'rbac:config'
const REGISTRY = 'rbac:organisations'
const INVITATIONS = 'jinbe:org_invitations'
const SIGNUP_ORG_SITES = 'rbac:signup:org_sites'
const ORG_DOMAINS = 'rbac:org_domains'
const SERVICES_META = 'rbac:services:meta'
const GROUPS_META = 'rbac:groups:meta'

const redis = () => getRedisClient()
const ownedServiceMeta = (field: string) => field === JINBE
const ownedGroupMeta = (field: string) => isStaffGroup(field)
const without = (h: Record<string, string>, owned: (f: string) => boolean) => Object.fromEntries(Object.entries(h).filter(([f]) => !owned(f)))

export async function exportStores(): Promise<Required<StoreSections>> {
  const r = redis()
  const records = await sitesRepository.list()
  const versions = Object.fromEntries(await Promise.all(records.map(async (rec) => [rec.site.name, await sitesRepository.versions(rec.site.name)] as const)))
  const [settings, registry, invitations, orgSites, domains, services, groups] = await Promise.all(
    [CONFIG, REGISTRY, INVITATIONS, SIGNUP_ORG_SITES, ORG_DOMAINS, SERVICES_META, GROUPS_META].map(async (k) => (await r.hgetall(k)) ?? {}),
  )
  return {
    sites: { records, versions },
    settings,
    organizations: { registry, invitations },
    signup: { orgSites, domains },
    metadata: { services: without(services, ownedServiceMeta), groups: without(groups, ownedGroupMeta) },
  }
}

const isStringMap = (v: unknown): v is Record<string, string> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((x) => typeof x === 'string')

/** Every problem with the store sections a file carries — checked before anything is written. */
export function storeProblems(s: StoreSections): string[] {
  const problems: string[] = []
  const maps: Array<[string, unknown]> = []
  if (s.settings !== undefined) maps.push(['settings', s.settings])
  if (s.organizations !== undefined) maps.push(['organizations.registry', s.organizations?.registry])
  if (s.organizations?.invitations !== undefined) maps.push(['organizations.invitations', s.organizations.invitations])
  if (s.signup !== undefined) maps.push(['signup.orgSites', s.signup?.orgSites], ['signup.domains', s.signup?.domains])
  if (s.metadata !== undefined) maps.push(['metadata.services', s.metadata?.services], ['metadata.groups', s.metadata?.groups])
  for (const [where, m] of maps) if (!isStringMap(m)) problems.push(`${where}: must map each name to a string`)
  if (s.sites !== undefined) {
    const { records, versions } = s.sites ?? ({} as SitesSection)
    if (!Array.isArray(records) || !versions || typeof versions !== 'object') return [...problems, 'sites: needs records (a list) and versions (by site)']
    for (const rec of records) {
      const name = rec?.site?.name
      if (typeof name !== 'string' || !SITE_NAME_PATTERN.test(name)) { problems.push(`sites: a record has no valid site name (${String(name)})`); continue }
      const history = versions[name]
      if (!Array.isArray(history) || history.length === 0) { problems.push(`sites.${name}: no versions`); continue }
      if (!Number.isInteger(rec.version) || history[history.length - 1]?.v !== rec.version) problems.push(`sites.${name}: version ${rec.version} is not its last saved version`)
      if (rec.applied && !history.some((v) => v?.v === rec.applied!.version)) problems.push(`sites.${name}: applied version ${rec.applied.version} is not in its history`)
    }
  }
  return problems
}

/**
 * The organizations a snapshot has: its registry, or for a file without one (format 1) every org its
 * org-scoped sections name. Org data is restored exactly for these, and only these.
 */
export function orgsInSnapshot(r: StoreSections & { orgSites?: Record<string, unknown>; orgAssignments?: Record<string, unknown>; directGrants?: Record<string, Array<{ scope?: string }>> }): Set<string> {
  if (r.organizations?.registry) return new Set(Object.keys(r.organizations.registry))
  const grantOrgs = Object.values(r.directGrants ?? {}).flatMap((gs) => (Array.isArray(gs) ? gs : []).map((g) => g?.scope)).filter((o): o is string => !!o && o !== 'platform')
  return new Set([...Object.keys(r.orgSites ?? {}), ...Object.keys(r.orgAssignments ?? {}), ...grantOrgs])
}

/** The org a domain claim (rbac:org_domains) or an invitation (jinbe:org_invitations) names, or null for an unreadable one. */
function claimOrg(raw: string): string | null {
  try {
    const org = (JSON.parse(raw) as { org?: unknown }).org
    return typeof org === 'string' ? org : null
  } catch {
    return null
  }
}

/**
 * A hash brought to `entries`, within the fields `inScope` (by field and value) says it may touch:
 * the file's in-scope entries are written, unless the field there now is out of scope (it belongs to
 * someone else); on `replace` every in-scope field the file lacks is removed. Out of scope is left alone.
 */
async function writeHash(key: string, entries: Record<string, string>, replace: boolean, inScope: (f: string, v: string) => boolean = () => true): Promise<number> {
  const r = redis()
  const current = (await r.hgetall(key)) ?? {}
  const mine = Object.fromEntries(Object.entries(entries).filter(([f, v]) => inScope(f, v) && (!(f in current) || inScope(f, current[f]))))
  if (replace) {
    for (const [field, value] of Object.entries(current)) {
      if (!(field in mine) && inScope(field, value)) await r.hdel(key, field)
    }
  }
  for (const [field, value] of Object.entries(mine)) await r.hset(key, field, value)
  return Object.keys(mine).length
}

/**
 * Writes the store sections asked for. `replace` (a full restore): each hash becomes exactly the
 * file's — org-scoped ones only within `orgs` (the snapshot's organizations). Organization records are
 * written, never removed (`progress.addedOrgs`: those new to this store, for a failed import to take
 * back). Sites are never replaced: a site that exists is left as it is — its intent, history and
 * applied marker say what the gateway serves now — and a site the file has that is gone now is
 * written back with its history (`progress.restoredSites`).
 */
export async function applyStores(
  s: StoreSections, want: (section: StoreSection) => boolean, replace: boolean, progress: ImportProgress, orgs: ReadonlySet<string>,
): Promise<StoresResult> {
  const out: StoresResult = {}
  if (want('sites') && s.sites) {
    const restored: string[] = []
    const kept: string[] = []
    for (const rec of s.sites.records) {
      const name = rec.site.name
      if (await sitesRepository.get(name)) { kept.push(name); continue }
      await sitesRepository.put(rec, s.sites.versions[name] ?? [])
      progress.restoredSites.push(name)
      restored.push(name)
    }
    out.sites = { restored, kept }
  }
  if (want('settings') && s.settings) out.settings = await writeHash(CONFIG, s.settings, replace)
  if (want('organizations') && s.organizations) {
    const existing = (await redis().hgetall(REGISTRY)) ?? {}
    progress.addedOrgs.push(...Object.keys(s.organizations.registry).filter((id) => !(id in existing)))
    out.organizations = await writeHash(REGISTRY, s.organizations.registry, false)
    await dropOrganisationCaches()
    // Invitations are org-scoped: exactly the file's for the snapshot's orgs, every other org's untouched.
    // A file from before them carries none: nothing is touched.
    const invitations = s.organizations.invitations
    if (invitations) await writeHash(INVITATIONS, invitations, replace, (_id, inv) => orgs.has(claimOrg(inv) ?? ''))
  }
  if (want('signup') && s.signup) {
    out.signup = await writeHash(SIGNUP_ORG_SITES, s.signup.orgSites, replace, (org) => orgs.has(org))
      + await writeHash(ORG_DOMAINS, s.signup.domains, replace, (_domain, claim) => orgs.has(claimOrg(claim) ?? ''))
  }
  if (want('metadata') && s.metadata) {
    out.metadata = await writeHash(SERVICES_META, s.metadata.services, replace, (f) => !ownedServiceMeta(f))
      + await writeHash(GROUPS_META, s.metadata.groups, replace, (f) => !ownedGroupMeta(f))
  }
  return out
}

/** What an import wrote that was not there before: a failed import takes it back. */
export interface ImportProgress { restoredSites: string[]; addedOrgs: string[] }
export const newProgress = (): ImportProgress => ({ restoredSites: [], addedOrgs: [] })

/** Takes back the sites and organization records a failed import added (the rest is put back by the snapshot). */
export async function takeBack(progress: ImportProgress): Promise<void> {
  for (const name of progress.restoredSites) await sitesRepository.purge(name)
  for (const id of progress.addedOrgs) await redis().hdel(REGISTRY, id)
  if (progress.addedOrgs.length) await dropOrganisationCaches()
}
