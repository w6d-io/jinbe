import * as sources from '../sources.js'
import { ensureLabels, person } from '../labels.js'
import type { SitesSummary, SourceDetail } from '../types.js'
import { CONNECT, ok, probe, src, type ModuleDef } from './common.js'

/**
 * The sites summary (home-data §3.5 sites): counts, pending requests, CR readiness (J2, one LIST) and
 * the migration phase. Platform readers get every site; an org admin a read-only list of the sites
 * whose `orgs` include one of theirs, without drafts, requests or the migration.
 */

const TOP = 12
const PROBE_MS = 250

type Row = SitesSummary['list'][number]

export const sitesModule: ModuleDef<SitesSummary> = {
  name: 'sites',
  tier: 'inline',
  freshMs: 30_000,
  timeoutMs: 500,
  async compute(ctx) {
    const srcs: Record<string, SourceDetail> = {}
    const platform = ctx.view.kind === 'platform'
    const [rows, records] = await Promise.all([sources.siteRows(), platform ? Promise.resolve(null) : sources.siteRecords(), ensureLabels().catch(() => {})])
    srcs.sites = src('ok')

    let visible = rows
    if (ctx.view.kind === 'orgs') {
      const mine = new Set(ctx.view.orgs)
      const allowed = new Set((records ?? []).filter((r) => r.site.orgs.some((o) => mine.has(o))).map((r) => r.site.name))
      visible = rows.filter((r) => allowed.has(r.name) && r.status !== 'draft')
    }

    let ready = new Map<string, boolean>()
    let unhealthy: number | null = null
    if (sources.kubeMode() === 'off') {
      srcs.kube = src('not_configured', CONNECT.kube)
    } else {
      const crs = await probe(() => sources.siteCrs(), PROBE_MS)
      srcs.kube = src(crs.ok ? 'ok' : crs.state)
      if (crs.ok && crs.value) {
        ready = new Map(crs.value.map((cr) => [cr.metadata.name, (cr.status?.conditions ?? []).some((c) => c.type === 'Ready' && c.status === 'True')]))
        unhealthy = visible.filter((r) => ready.get(r.name) === false).length
      }
    }

    const counts = { live: 0, attention: 0, draft: 0, paused: 0, deleted: 0 }
    for (const r of visible) counts[r.status]++
    let pendingRequests = 0
    let migration: SitesSummary['migration']
    if (platform) {
      const [deleted, requests, mig] = await Promise.all([
        probe(() => sources.deletedSites(), PROBE_MS),
        probe(() => sources.pendingRequests(), PROBE_MS),
        probe(() => sources.migration(), PROBE_MS),
      ])
      counts.deleted = deleted.ok ? deleted.value : 0
      pendingRequests = requests.ok ? requests.value.length : 0
      if (mig.ok && mig.value.state && mig.value.state !== 'not-started' && mig.value.state !== 'done') {
        migration = {
          phase: mig.value.state,
          regressions: mig.value.dualrun?.regressions.length ?? 0,
          rollbackUntil: mig.value.rollbackUntil ?? null,
        }
      }
    }

    const list: Row[] = visible
      .map((r) => ({
        name: r.name,
        displayName: r.displayName,
        host: r.host ?? null,
        status: r.status,
        ready: ready.has(r.name) ? ready.get(r.name)! : null,
        version: r.version,
        appliedVersion: r.appliedVersion,
        appliedAt: r.appliedAt,
        appliedBy: r.appliedBy ? person(r.appliedBy) : null,
        draftAt: platform ? r.draft?.at ?? null : null,
        orgs: r.orgs,
      }))
      .sort((a, b) => Number(b.status === 'attention') - Number(a.status === 'attention') || (b.appliedAt ?? '').localeCompare(a.appliedAt ?? ''))
      .slice(0, TOP)

    return ok({ counts, pendingRequests, unhealthy, list, ...(migration ? { migration } : {}) }, srcs)
  },
}
