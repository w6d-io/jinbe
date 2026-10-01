import { render } from './render.js'
import { sitesRepository } from './repository.js'
import { loadPlatform } from './platform.js'
import { publishPermissions } from './publish.js'
import { pinnedHostsOf } from './checks.js'
import { siteLoginStore } from './login-store.js'
import { siteLoginOf } from './login.js'
import type { AuditActorInput } from '../services/audit-event.service.js'

/**
 * Every applied site's permissions written again from its applied version — the reseed half of the
 * bootstrap's wipe (bootstrap/apply.ts): after the stored RBAC is cleared, nothing exists unless code
 * or a site intent declares it. The gateway rules (Site CRs) are not touched: they never left.
 *
 * One site failing does not stop the others; the list of failures is returned for the plan output.
 */
export async function republishAppliedSites(actor: AuditActorInput): Promise<{ published: string[]; failed: Array<{ site: string; error: string }> }> {
  const records = await sitesRepository.list()
  const platform = await loadPlatform()
  const published: string[] = []
  const failed: Array<{ site: string; error: string }> = []
  for (const record of records) {
    if (!record.applied) continue
    try {
      const version = await sitesRepository.version(record.site.name, record.applied.version)
      if (!version) throw new Error(`applied version ${record.applied.version} is gone`)
      const site = { ...version.site, state: record.site.state }
      const rendered = render(site, platform)
      await publishPermissions(site.name, rendered, { description: site.description ?? site.displayName, pinnedHosts: pinnedHostsOf(records, site), actor })
      await siteLoginStore.set(site.name, siteLoginOf(site))
      published.push(site.name)
    } catch (err) {
      failed.push({ site: record.site.name, error: (err as Error).message })
    }
  }
  return { published, failed }
}
