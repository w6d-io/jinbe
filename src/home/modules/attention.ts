import { createHash } from 'node:crypto'
import * as sources from '../sources.js'
import { ensureLabels, person } from '../labels.js'
import { peek, type ModuleResult } from '../cache.js'
import { readJob, CERT_CRITICAL_DAYS, CERT_WARNING_DAYS, STALE_DRAFT_MS } from '../jobs.js'
import { scopeKeyOf } from '../scope.js'
import type { Activity, Attention, AttentionItem, Severity, SourceDetail } from '../types.js'
import { platformFacts, type PlatformFacts } from './health.js'
import { CONNECT, DAY, HOUR, MINUTE, ago, iso, ok, probe, src, type ModuleContext, type ModuleDef } from './common.js'

/**
 * The needs-attention queue (home-data §3.5 attention table). Items come from STATE, not from
 * notifications: they leave when the condition clears. Count-type findings about people are one item
 * with a count, never one per person, and no title or label ever carries an address.
 *
 * Cached per scope (shared by every platform reader, or every admin of one org set); finished per
 * caller: four-eyes hides your own apply requests, `actionable` follows your `sites:apply`, super-admin
 * items are dropped for everyone else, and your own recertification inbox is added live.
 */

const MAX_ITEMS = 50
const PROBE_MS = 250
const INBOX_MS = 150
/** The info item shows once the capped outbox (no archiver) is this full. */
const OUTBOX_NEAR_CAP = 0.9

/** A cached item: the public shape plus what only the per-caller pass may read (stripped before sending). */
type Staged = AttentionItem & { _requester?: string; _audience?: 'super_admin'; _approval?: boolean }
type StagedAttention = { items: Staged[] }

const hashOf = (email: string) => createHash('sha1').update(email.trim().toLowerCase()).digest('hex')
const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 }

function item(i: Omit<Staged, 'actionable'> & { actionable?: boolean }): Staged {
  return { actionable: true, ...i }
}

function platformBroken(f: PlatformFacts): Staged[] {
  const out: Staged[] = []
  const g = f.gateway
  if (g.kind === 'ok') {
    const since = g.since ? Date.parse(g.since) : f.now
    if (g.phase === 'Failed' || g.phase === 'RolledBack' || (!g.settled && f.now - since > 10 * MINUTE)) {
      out.push(item({
        id: 'gateway_rollout:gateway', kind: 'gateway_rollout', severity: 'critical',
        title: g.phase === 'Failed' ? 'Gateway rollout failed' : g.phase === 'RolledBack' ? 'Gateway rollout was rolled back' : `Gateway rollout stuck for ${ago(f.now - since)}`,
        ...(g.message ? { detail: g.message.slice(0, 200) } : {}),
        subject: { type: 'component', id: 'gateway', label: 'Gateway' },
        since: iso(since), target: { page: 'gateway', params: {} },
      }))
    }
  }
  const e = f.engines
  if (e.reporting > 0 && e.serving && e.current < e.reporting && e.since !== null && f.now - e.since > 2 * MINUTE) {
    out.push(item({
      id: 'engines_out_of_sync:opa', kind: 'engines_out_of_sync', severity: 'critical',
      title: `Policy engines out of sync — ${e.reporting - e.current} of ${e.reporting} behind`,
      detail: `serving ${e.serving.slice(0, 8)} for ${ago(f.now - e.since)}`,
      subject: { type: 'component', id: 'opa', label: 'Policy engine' },
      since: iso(e.since), target: { page: 'gateway', params: {}, anchor: 'engines' },
    }))
  }
  if (f.opal.oldestMs !== null && f.now - f.opal.oldestMs >= 10 * MINUTE) {
    out.push(item({
      id: 'opal_data_stale:opal', kind: 'opal_data_stale', severity: 'critical',
      title: `Policy sync is stale — last update ${ago(f.now - f.opal.oldestMs)} ago`,
      subject: { type: 'component', id: 'opal_data', label: 'Policy sync' },
      since: iso(f.opal.oldestMs), target: { page: 'gateway', params: {}, anchor: 'opal' },
    }))
  }
  if (f.rules && f.rules.compileErrors > 0) {
    out.push(item({
      id: 'rule_compile_errors:gateway', kind: 'rule_compile_errors', severity: 'critical',
      title: `${f.rules.compileErrors} gateway rule${f.rules.compileErrors === 1 ? '' : 's'} will not compile`,
      subject: { type: 'component', id: 'gateway_rules', label: 'Gateway rules' },
      since: iso(f.rules.at), target: { page: 'gateway', params: {} }, metrics: { count: f.rules.compileErrors },
    }))
  }
  if (f.certs.state === 'ok') {
    for (const c of f.certs.certs) {
      if (c.ready && c.daysLeft >= CERT_WARNING_DAYS) continue
      out.push(item({
        id: `cert_expiring:${c.name}`, kind: 'cert_expiring',
        severity: !c.ready || c.daysLeft < CERT_CRITICAL_DAYS ? 'critical' : 'warning',
        title: c.ready ? `Certificate ${c.name} expires in ${Math.max(0, Math.floor(c.daysLeft))} days` : `Certificate ${c.name} is not ready`,
        subject: { type: 'component', id: `certificate:${c.name}`, label: c.name },
        since: iso(f.now), target: { page: 'sites', params: {} }, metrics: { daysLeft: c.daysLeft },
      }))
    }
  }
  // Lag means something only when an archiver is meant to drain the outbox. Without one the outbox is
  // capped, so what is worth knowing is that the oldest events are about to be dropped.
  if (!sources.archiveEnabled()) {
    const cap = sources.outboxMaxLen()
    if (f.outbox && f.outbox.length >= OUTBOX_NEAR_CAP * cap) {
      out.push(item({
        id: 'audit_outbox_near_cap:outbox', kind: 'audit_outbox_near_cap', severity: 'info',
        title: `Audit outbox holds ${f.outbox.length} of ${cap} events — the oldest are dropped past the cap`,
        detail: 'no archiver is configured (AUDIT_ARCHIVE_ENABLED); the audit log in Loki is unaffected',
        since: iso(f.outbox.oldestMs ?? f.now), target: { page: 'audit', params: {} }, metrics: { count: f.outbox.length, cap }, _audience: 'super_admin',
      }))
    }
  } else if (f.outbox?.oldestMs && f.now - f.outbox.oldestMs >= HOUR) {
    const age = f.now - f.outbox.oldestMs
    out.push(item({
      id: 'audit_archive_lag:outbox', kind: 'audit_archive_lag', severity: age >= DAY ? 'critical' : 'warning',
      title: `Audit archive is ${ago(age)} behind`, detail: `${f.outbox.length} events waiting`,
      since: iso(f.outbox.oldestMs), target: { page: 'audit', params: {} }, metrics: { count: f.outbox.length }, _audience: 'super_admin',
    }))
  }
  if (f.auditFailures > 0) {
    out.push(item({
      id: 'audit_emit_failures:sink', kind: 'audit_emit_failures', severity: 'critical',
      title: `${f.auditFailures} audit event${f.auditFailures === 1 ? '' : 's'} could not be stored in the last hour`,
      since: iso(f.now - HOUR), target: { page: 'audit', params: {} }, metrics: { count: f.auditFailures }, _audience: 'super_admin',
    }))
  }
  if (f.notificationsDead > 0) {
    out.push(item({
      id: 'notifications_dead_letter:http', kind: 'notifications_dead_letter', severity: 'warning',
      title: `${f.notificationsDead} notification${f.notificationsDead === 1 ? '' : 's'} could not be delivered`,
      detail: 'kept in the Redis stream notifications:dead with the reason; see the jinbe logs "notification dead-lettered"',
      subject: { type: 'component', id: 'notifications', label: 'Notifications' },
      since: iso(f.now), target: { page: 'dashboard', params: {} }, metrics: { count: f.notificationsDead }, _audience: 'super_admin',
    }))
  }
  return out
}

async function siteItems(f: PlatformFacts, srcs: Record<string, SourceDetail>): Promise<Staged[]> {
  const out: Staged[] = []
  const [rows, requests] = await Promise.all([sources.siteRows(), sources.pendingRequests()])
  srcs.sites = src('ok')
  const names = new Map(rows.map((r) => [r.name, r.displayName]))
  for (const r of requests) {
    const age = f.now - Date.parse(r.requestedAt)
    const who = person(r.requestedBy)
    out.push(item({
      id: `site_request_pending:${r.id}`, kind: 'site_request_pending',
      severity: r.risk.level === 'high' && age > DAY ? 'critical' : 'warning',
      title: `Apply request for ${names.get(r.site) ?? r.site} v${r.version}`,
      detail: [`requested by ${who.label}`, `risk ${r.risk.level}`, ...(r.needsSecondApprover ? ['needs a second approver'] : [])].join(' · '),
      subject: { type: 'request', id: r.id, label: names.get(r.site) ?? r.site },
      since: r.requestedAt, target: { page: 'sites', params: { view: 'requests', id: r.id } },
      _requester: hashOf(r.requestedBy), _approval: true,
    }))
  }
  for (const s of rows) {
    if (s.status === 'attention') {
      out.push(item({
        id: `site_unapplied:${s.name}`, kind: 'site_unapplied', severity: 'info',
        title: `${s.displayName} has saved changes that aren't applied`, detail: `v${s.version} saved · v${s.appliedVersion} live`,
        subject: { type: 'site', id: s.name, label: s.displayName },
        since: s.appliedAt ?? iso(f.now), target: { page: 'sites', params: { name: s.name } },
      }))
    }
    const draftAt = s.draft?.at ? Date.parse(s.draft.at) : NaN
    if (Number.isFinite(draftAt) && f.now - draftAt > STALE_DRAFT_MS) {
      out.push(item({
        id: `site_draft_stale:${s.name}`, kind: 'site_draft_stale', severity: 'info',
        title: `${s.displayName} has a draft untouched for ${ago(f.now - draftAt)}`,
        subject: { type: 'site', id: s.name, label: s.displayName },
        since: iso(draftAt), target: { page: 'sites', params: { name: s.name, tab: 'draft' } },
      }))
    }
  }

  if (sources.kubeMode() === 'off') {
    srcs.kube = src('not_configured', CONNECT.kube)
  } else {
    const crs = await probe(() => sources.siteCrs(), PROBE_MS)
    srcs.kube = src(crs.ok ? 'ok' : crs.state)
    for (const cr of crs.ok ? crs.value ?? [] : []) {
      const bad = (cr.status?.conditions ?? []).filter((c) => ['Ready', 'RulesLoaded', 'CertificateReady', 'IngressReady'].includes(c.type) && c.status !== 'True')
      if (bad.length === 0) continue
      const worst = bad.find((c) => c.type === 'Ready' || c.type === 'RulesLoaded') ?? bad[0]
      const name = cr.metadata.name
      out.push(item({
        id: `site_condition:${name}`, kind: 'site_condition',
        severity: worst.type === 'Ready' || worst.type === 'RulesLoaded' ? 'critical' : 'warning',
        title: `${names.get(name) ?? name}: ${worst.type} is ${worst.status}`,
        ...(worst.reason ? { detail: worst.reason } : {}),
        subject: { type: 'site', id: name, label: names.get(name) ?? name },
        since: worst.lastTransitionTime ?? iso(f.now), target: { page: 'sites', params: { name, tab: 'status' } },
      }))
    }
    const drift = await probe(() => readJob('drift', f.now), PROBE_MS)
    const stored = drift.ok ? drift.value : null
    srcs.drift = src(!drift.ok ? drift.state : !stored ? 'warming' : stored.result.status === 'ok' ? 'ok' : 'down')
    if (stored?.result.status === 'ok') {
      for (const d of stored.result.data.drifted) {
        out.push(item({
          id: `site_drift:${d.site}`, kind: 'site_drift', severity: 'warning',
          title: `${names.get(d.site) ?? d.site} drifted from what was applied`,
          detail: `${d.items} difference${d.items === 1 ? '' : 's'}`,
          subject: { type: 'site', id: d.site, label: names.get(d.site) ?? d.site },
          since: d.checkedAt, target: { page: 'sites', params: { name: d.site, tab: 'drift' } }, metrics: { count: d.items },
        }))
      }
    }
  }

  const mig = await probe(() => sources.migration(), PROBE_MS)
  if (mig.ok) {
    const regressions = mig.value.dualrun?.regressions.length ?? 0
    const until = mig.value.rollbackUntil ? Date.parse(mig.value.rollbackUntil) : NaN
    const closing = Number.isFinite(until) && until > f.now && until - f.now < DAY
    if (regressions > 0 || closing) {
      out.push(item({
        id: 'migration_regressions:migration', kind: 'migration_regressions', severity: 'warning',
        title: regressions > 0 ? `Migration dual run found ${regressions} regression${regressions === 1 ? '' : 's'}` : `Migration rollback window closes in ${ago(until - f.now)}`,
        since: mig.value.dualrun?.startedAt ?? iso(f.now), target: { page: 'sites', params: { view: 'migration' } },
        ...(regressions > 0 ? { metrics: { count: regressions } } : {}),
      }))
    }
  }
  return out
}

async function postureItems(now: number, srcs: Record<string, SourceDetail>): Promise<Staged[]> {
  const out: Staged[] = []
  const review = await probe(() => readJob('accessReview', now), PROBE_MS)
  const stored = review.ok ? review.value : null
  srcs.access_review = src(!review.ok ? review.state : !stored ? 'warming' : stored.result.status === 'ok' ? 'ok' : 'down')
  if (stored?.result.status === 'ok') {
    const s = stored.result.data
    const since = s.computedAt
    const count = (id: string, kind: Staged['kind'], severity: Severity, n: number, title: string, filter: string) => {
      if (n > 0) out.push(item({ id, kind, severity, title, since, target: { page: 'access-review', params: { filter } }, metrics: { count: n } }))
    }
    count('privileged_no_mfa:all', 'privileged_no_mfa', 'warning', s.noMfa, `${s.noMfa} ${s.noMfa === 1 ? 'person' : 'people'} with full access have no second factor`, 'no-mfa')
    count('privileged_self_granted:all', 'privileged_self_granted', 'warning', s.selfGranted, `${s.selfGranted} privileged ${s.selfGranted === 1 ? 'grant was' : 'grants were'} self-granted`, 'self-granted')
    count('privileged_dormant:all', 'privileged_dormant', 'info', s.dormant, `${s.dormant} privileged ${s.dormant === 1 ? 'account has' : 'accounts have'} been inactive for 30 days`, 'dormant')
  }
  const stats = await probe(() => sources.directoryStats(), PROBE_MS)
  srcs.directory = src(stats.ok ? (stats.value ? 'ok' : 'warming') : stats.state)
  if (stats.ok && stats.value && stats.value.stats.unassigned > 0) {
    const n = stats.value.stats.unassigned
    out.push(item({
      id: 'unassigned_users:all', kind: 'unassigned_users', severity: 'info',
      title: `${n} ${n === 1 ? 'person is' : 'people are'} in no group and can reach nothing`,
      since: stats.value.stats.computedAt, target: { page: 'users', params: { filter: 'unassigned' } }, metrics: { count: n },
    }))
  }
  const camps = await probe(() => sources.campaigns(), PROBE_MS)
  srcs.recert = src(camps.ok ? 'ok' : camps.state)
  for (const c of camps.ok ? camps.value : []) {
    if (c.status !== 'active' || Date.parse(c.deadline) >= now) continue
    const left = c.itemCount - c.decidedCount
    out.push(item({
      id: `recert_overdue:${c.id}`, kind: 'recert_overdue', severity: 'warning',
      title: `${c.name} is overdue · ${left} decision${left === 1 ? '' : 's'} left`,
      subject: { type: 'campaign', id: c.id, label: c.name },
      since: c.deadline, target: { page: 'recertification', params: { id: c.id } }, metrics: { count: left },
    }))
  }
  return out
}

/** `login_failure_spike` from the activity module's last result for the same scope (never recomputed here). */
async function spikeItems(ctx: ModuleContext): Promise<Staged[]> {
  const stored = await peek('activity', scopeKeyOf(ctx.view, ctx.scope.subject), '24h').catch(() => null)
  if (stored?.result.status !== 'ok') return []
  const a = stored.result.data as Activity
  const spike = a.signIns.failedSpike
  if (!spike) return []
  const last = a.series[a.series.length - 1]
  return [item({
    id: 'login_failure_spike:24h', kind: 'login_failure_spike', severity: 'warning',
    title: `Failed sign-ins are ${spike.factor}× usual`,
    since: last?.t ?? iso(ctx.now), target: { page: 'audit', params: { event: 'auth.login.failed', window: '24h' } },
    metrics: spike,
  })]
}

export const attentionModule: ModuleDef<StagedAttention> = {
  name: 'attention',
  tier: 'inline',
  freshMs: 30_000,
  timeoutMs: 600,
  async compute(ctx) {
    const srcs: Record<string, SourceDetail> = {}
    const items: Staged[] = []
    if (ctx.view.kind === 'platform') {
      await ensureLabels().catch(() => { srcs.directory_labels = src('down') })
      const facts = await platformFacts(ctx.now)
      Object.assign(srcs, facts.sources)
      items.push(...platformBroken(facts), ...(await siteItems(facts, srcs)), ...(await postureItems(ctx.now, srcs)))
    }
    if (ctx.view.kind !== 'self') items.push(...(await spikeItems(ctx)))
    // TODO(HOME-later): `recert_overdue` for org admins once a campaign's scope carries an org;
    // `site_members_no_mfa` (J12 reach × MFA join) and `apikey_unused` (90 d of `apikey.used` in Loki).
    return ok({ items }, srcs)
  },
  async personalise(result, ctx): Promise<ModuleResult<Attention>> {
    if (result.status !== 'ok') return result
    const me = hashOf(ctx.scope.email)
    const srcs = { ...result.sources }
    const items: Staged[] = result.data.items
      .filter((i) => i._audience !== 'super_admin' || ctx.scope.superAdmin)
      .filter((i) => i._requester !== me) // four-eyes: nobody reviews their own request
      .map((i) => (i._approval ? { ...i, actionable: ctx.scope.canApply } : i))

    const inbox = await probe(() => sources.inbox(ctx.scope.email), INBOX_MS)
    srcs.recert_inbox = src(inbox.ok ? 'ok' : inbox.state)
    if (inbox.ok && inbox.value.length > 0) {
      const soonest = Math.min(...inbox.value.map((i) => Date.parse(i.deadline)))
      const n = inbox.value.length
      items.push(item({
        id: 'recert_inbox:me', kind: 'recert_inbox', severity: soonest - ctx.now < 48 * HOUR ? 'warning' : 'info',
        title: `${n} access review${n === 1 ? '' : 's'} waiting on you`,
        detail: `due ${new Date(soonest).toISOString().slice(0, 10)}`,
        since: iso(ctx.now), target: { page: 'recertification', params: { view: 'inbox' } }, metrics: { count: n },
      }))
    }

    items.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.since.localeCompare(b.since))
    const counts = { critical: 0, warning: 0, info: 0 }
    for (const i of items) counts[i.severity]++
    const shown = items.slice(0, MAX_ITEMS).map(({ _requester, _audience, _approval, ...pub }) => pub)
    return ok({ items: shown, counts, truncated: items.length > MAX_ITEMS }, srcs)
  },
}
