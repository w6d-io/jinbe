import { explicitWildcards, render, type Rendered } from './render.js'
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
  for (const record of records) {
    if (!record.applied) continue
    try {
      const version = await sitesRepository.version(record.site.name, record.applied.version)
      if (!version) throw new Error(`applied version ${record.applied.version} is gone`)
      // Explicit roles: a `*` stored before wildcards were refused becomes the permissions it stood for.
      const site = explicitWildcards({ ...version.site, state: record.site.state })
      models.push({ site, rendered: render(site, platform) })
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
