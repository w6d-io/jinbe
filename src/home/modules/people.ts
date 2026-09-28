import * as sources from '../sources.js'
import { ensureLabels, isActive } from '../labels.js'
import { readJob } from '../jobs.js'
import type { People, SourceDetail } from '../types.js'
import { iso, ok, probe, src, unavailable, type ModuleDef } from './common.js'

/**
 * Directory counts (home-data §3.5 people). Platform: the `rbac:stats` walk already cached in Redis,
 * plus MFA coverage from the access-review job (J3). Support: totals only. Org admin: its orgs'
 * members from the organisation store (every membership, not just the Kratos primary org).
 */

const BY_ORG_TOP = 20
const BY_GROUP_TOP = 8
const PROBE_MS = 250

const top = <T>(list: T[], n: number, key: (t: T) => number) => [...list].sort((a, b) => key(b) - key(a)).slice(0, n)

export const peopleModule: ModuleDef<People> = {
  name: 'people',
  tier: 'inline',
  freshMs: 30_000,
  timeoutMs: 400,
  async compute(ctx) {
    const srcs: Record<string, SourceDetail> = {}

    if (ctx.view.kind === 'orgs') {
      const orgs = ctx.view.orgs
      const [names, members] = await Promise.all([
        sources.orgNames(orgs),
        Promise.all(orgs.map((o) => sources.orgMembers(o))),
        ensureLabels(),
      ])
      srcs.organisations = src('ok')
      const everyone = new Set(members.flat())
      const active = [...everyone].filter((id) => isActive(id) === true).length
      const byOrg = top(orgs.map((orgId, i) => ({ orgId, name: names[orgId] ?? orgId, members: members[i].length })), BY_ORG_TOP, (o) => o.members)
      return ok({ identities: everyone.size, active, inactive: everyone.size - active, byOrg, orgsTotal: orgs.length }, srcs)
    }

    const stats = await sources.directoryStats()
    if (!stats) return unavailable('warming', { directory: src('warming') })
    srcs.directory = src('ok')
    const s = stats.stats
    const base = { identities: s.total, active: s.active, inactive: s.total - s.active }
    // TODO(HOME-later, J6): `sessionsActive` from a background walk of Kratos /admin/sessions?active=true.
    if (ctx.view.kind === 'self') return ok(base, srcs)

    const out: People = {
      ...base,
      fullAccess: s.fullAccess,
      unassigned: s.unassigned,
      byGroup: top(Object.entries(s.perGroup).map(([group, members]) => ({ group, members })), BY_GROUP_TOP, (g) => g.members),
    }
    const perOrg = Object.entries(s.perOrg)
    if (perOrg.length > 0) {
      const topOrgs = top(perOrg.map(([orgId, members]) => ({ orgId, members })), BY_ORG_TOP, (o) => o.members)
      const names = await probe(() => sources.orgNames(topOrgs.map((o) => o.orgId)), PROBE_MS)
      srcs.organisations = src(names.ok ? 'ok' : names.state)
      out.byOrg = topOrgs.map((o) => ({ ...o, name: (names.ok ? names.value[o.orgId] : undefined) ?? o.orgId }))
      out.orgsTotal = perOrg.length
    }
    const review = await probe(() => readJob('accessReview', ctx.now), PROBE_MS)
    const stored = review.ok ? review.value : null
    srcs.access_review = src(!review.ok ? review.state : !stored ? 'warming' : stored.result.status === 'ok' ? 'ok' : 'down')
    const mfa = stored?.result.status === 'ok' ? stored.result.data.mfa : undefined
    if (mfa) out.mfa = { enrolled: mfa.enrolled, of: mfa.identities, asOf: stored?.result.status === 'ok' ? stored.result.data.computedAt : iso(ctx.now) }
    return ok(out, srcs)
  },
}
