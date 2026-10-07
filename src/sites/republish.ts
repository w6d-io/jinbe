import { explicitWildcards, render, stableStringify, type Rendered } from './render.js'
import { nestingContext } from './nesting.js'
import { liveAddresses } from './address.js'
import { auditSite } from './audit.js'
import { explicitOrganizations } from './organizations.js'
import type { Site } from './schemas.js'
import type { SiteRecord } from './repository.js'
import { sitesRepository } from './repository.js'
import { loadPlatform } from './platform.js'
import { publishPermissions } from './publish.js'
import { pinnedHostsOf } from './checks.js'
import { siteLoginStore } from './login-store.js'
import { siteLoginOf } from './login.js'
import type { AuditActorInput } from '../services/audit-event.service.js'

/** What each applied site's applied version renders to — the definitions the reseed writes. */
export interface AppliedSiteModel {
  site: Site
  rendered: Rendered
}

/**
 * Every applied site rendered from its applied version, with a wildcard stored before they were
 * refused made explicit (explicitWildcards). The plan reads this to show what the apply will write;
 * the reseed writes exactly this.
 */
export async function renderAppliedSites(): Promise<{ models: AppliedSiteModel[]; failed: Array<{ site: string; error: string }>; records: SiteRecord[] }> {
  const records = await sitesRepository.list()
  const platform = await loadPlatform()
  const models: AppliedSiteModel[] = []
  const failed: Array<{ site: string; error: string }> = []
  // Each site leaves out the sites nested under it on its host (nesting.ts), from one read of the addresses.
  const live = await liveAddresses(records)
  for (const record of records) {
    if (!record.applied) continue
    try {
      const version = await sitesRepository.version(record.site.name, record.applied.version)
      if (!version) throw new Error(`applied version ${record.applied.version} is gone`)
      // Explicit roles: a `*` stored before wildcards were refused becomes the permissions it stood for;
      // and organizations used before their switch existed stay on.
      const site = explicitOrganizations(explicitWildcards({ ...version.site, state: record.site.state }))
      models.push({ site, rendered: render(site, platform, await nestingContext(site, records, [], live)) })
    } catch (err) {
      failed.push({ site: record.site.name, error: (err as Error).message })
    }
  }
  return { models, failed, records }
}

/**
 * Every applied site's permissions written again from its applied version — the reseed half of the
 * bootstrap's wipe (bootstrap/apply.ts): after the stored RBAC is cleared, nothing exists unless code
 * or a site intent declares it. The gateway rules (Site CRs) are not touched: they never left.
 *
 * One site failing does not stop the others; the list of failures is returned for the plan output.
 */
export async function republishAppliedSites(actor: AuditActorInput): Promise<{ published: string[]; failed: Array<{ site: string; error: string }> }> {
  const { models, failed, records } = await renderAppliedSites()
  const published: string[] = []
  for (const { site, rendered } of models) {
    try {
      await publishPermissions(site.name, rendered, { description: site.description ?? site.displayName, pinnedHosts: pinnedHostsOf(records, site), actor })
      await siteLoginStore.set(site.name, siteLoginOf(site))
      published.push(site.name)
    } catch (err) {
      failed.push({ site: site.name, error: (err as Error).message })
    }
  }
  return { published, failed }
}

/** The note on the version that makes a stored wildcard explicit. */
export const EXPLICIT_ROLES_NOTE = "roles made explicit by the authz release (was '*')"

/**
 * The sites whose stored intent still holds a wildcard (`*` or `resource:*`) — saved before wildcards
 * were refused. Each would refuse every edit (wildcard_permission) until made explicit.
 */
export function sitesWithWildcards(records: readonly SiteRecord[]): string[] {
  return records.filter((r) => stableStringify(explicitOrganizations(explicitWildcards(r.site))) !== stableStringify(r.site)).map((r) => r.site.name).sort()
}

/**
 * Saves, for every site whose stored intent holds a wildcard, a new version with the wildcard made
 * explicit (the permissions it stood for: explicitWildcards, the same expansion the reseed publishes),
 * noted and audited — so the first edit after the release saves. What is published does not change:
 * the new version renders exactly as the applied one already did. When the stored intent WAS the
 * applied version, the new version is marked applied in its place (same rules). Idempotent.
 */
export async function persistExplicitRoles(actor: AuditActorInput): Promise<Array<{ site: string; from: number; to: number; applied: boolean }>> {
  const out: Array<{ site: string; from: number; to: number; applied: boolean }> = []
  for (const record of await sitesRepository.list()) {
    const explicit = explicitOrganizations(explicitWildcards(record.site))
    if (stableStringify(explicit) === stableStringify(record.site)) continue
    const saved = await sitesRepository.save(explicit, { by: actor.email ?? 'bootstrap', note: EXPLICIT_ROLES_NOTE, ifMatch: record.etag })
    const wasApplied = record.applied?.version === record.version
    if (wasApplied && record.applied) await sitesRepository.setApplied(record.site.name, { ...record.applied, version: saved.version })
    auditSite('roles_made_explicit', record.site.name, actor, EXPLICIT_ROLES_NOTE, { from: record.version, to: saved.version, applied: wasApplied })
    out.push({ site: record.site.name, from: record.version, to: saved.version, applied: wasApplied })
  }
  return out
}
