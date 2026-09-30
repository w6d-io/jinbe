import * as sources from '../sources.js'
import { readJob, CERT_CRITICAL_DAYS, CERT_WARNING_DAYS, type Certificate } from '../jobs.js'
import type { ComponentState, Health, HealthComponent, SourceDetail } from '../types.js'
import { CONNECT, HOUR, MINUTE, ago, iso, ok, probe, src, type ModuleDef } from './common.js'

/**
 * The health strip (home-data §3.5 health table): is the request path alive, in the order a request
 * and a change travel. Thresholds live here, never in the UI. Every probe has its own budget, and a
 * source that cannot be read turns ITS component `unknown`/`not_deployed` — never the whole strip.
 */

const PROBE_MS = 250

export interface PlatformFacts {
  now: number
  gateway: { kind: 'off' } | { kind: 'down' } | { kind: 'unmanaged' } | { kind: 'ok'; settled: boolean; phase: string; since: string | null; message: string | null }
  /** OPA's /health, asked only when OPA_URL is set. */
  opaDirect: 'ok' | 'down' | null
  opal: { entries: number; oldestMs: number | null }
  rules: { at: number; count: number; compileErrors: number } | null
  outbox: { length: number; oldestMs: number | null } | null
  auditFailures: number
  notificationsDead: number
  certs: { state: 'ok'; certs: Certificate[] } | { state: 'not_configured' | 'warming' | 'down' }
  sources: Record<string, SourceDetail>
}

/** The raw facts behind both the strip and the platform items of the attention queue. */
export async function platformFacts(now = Date.now()): Promise<PlatformFacts> {
  const sourcesOut: Record<string, SourceDetail> = {}
  const kubeOff = sources.kubeMode() === 'off'
  const [rollout, opal, rules, outbox, failures, certJob, dead, opaUp] = await Promise.all([
    kubeOff ? Promise.resolve(null) : probe(() => sources.gatewayRollout(), PROBE_MS),
    probe(() => sources.opalLastSuccess(), PROBE_MS),
    probe(() => sources.rulesServed(), PROBE_MS),
    sources.auditSink() === 'legacy' ? Promise.resolve(null) : probe(() => sources.outbox(), PROBE_MS),
    probe(() => sources.auditFailures(now), PROBE_MS),
    sources.prom() ? probe(() => readJob('certificates', now), PROBE_MS) : Promise.resolve(null),
    probe(() => sources.notificationsDeadLettered(), PROBE_MS),
    sources.opaConfigured() ? sources.opaHealthy(PROBE_MS) : Promise.resolve(null),
  ])

  let gateway: PlatformFacts['gateway']
  if (kubeOff) {
    gateway = { kind: 'off' }
    sourcesOut.kube = src('not_configured', CONNECT.kube)
  } else if (!rollout?.ok) {
    gateway = { kind: 'down' }
    sourcesOut.kube = src(rollout?.state ?? 'down')
  } else {
    sourcesOut.kube = src('ok')
    const r = rollout.value
    gateway = r.managed
      ? { kind: 'ok', settled: r.settled, phase: r.rollout?.phase ?? 'Pending', since: r.rollout?.since ?? null, message: r.rollout?.message ?? null }
      : { kind: 'unmanaged' }
  }

  const opalValues = opal.ok ? Object.values(opal.value) : []
  let certs: PlatformFacts['certs']
  if (certJob === null) certs = { state: 'not_configured' }
  else if (!certJob.ok || !certJob.value) certs = { state: certJob.ok ? 'warming' : 'down' }
  else if (certJob.value.result.status === 'ok') certs = { state: 'ok', certs: certJob.value.result.data.certs }
  else certs = { state: certJob.value.result.reason === 'not_configured' ? 'not_configured' : 'down' }
  sourcesOut.prometheus = certs.state === 'ok' ? src('ok') : certs.state === 'not_configured' ? src('not_configured', CONNECT.prometheus) : src(certs.state)
  if (!sources.lokiConfigured()) sourcesOut.loki = src('not_configured', CONNECT.loki)

  return {
    now,
    gateway,
    opaDirect: opaUp === null ? null : opaUp ? 'ok' : 'down',
    opal: { entries: opalValues.length, oldestMs: opalValues.length ? Math.min(...opalValues) : null },
    rules: rules.ok ? rules.value : null,
    outbox: outbox?.ok ? outbox.value : null,
    auditFailures: failures.ok ? failures.value : 0,
    notificationsDead: dead.ok ? dead.value : 0,
    certs,
    sources: sourcesOut,
  }
}

const component = (id: HealthComponent['id'], state: ComponentState, summary: string, extra: Partial<HealthComponent> = {}): HealthComponent =>
  ({ id, state, summary, ...extra })

export function gatewayComponent(f: PlatformFacts): HealthComponent {
  const link = { page: 'gateway' }
  const g = f.gateway
  if (g.kind === 'off') return component('gateway', 'not_deployed', 'not connected', { link })
  if (g.kind === 'down') return component('gateway', 'unknown', 'cluster did not answer', { link })
  if (g.kind === 'unmanaged') return component('gateway', 'not_deployed', 'no Gateway resource', { link })
  const since = g.since ? { since: g.since } : {}
  if (g.phase === 'Failed' || g.phase === 'RolledBack') return component('gateway', 'down', g.phase === 'Failed' ? 'rollout failed' : 'rolled back', { link, ...since })
  if (!g.settled || g.phase !== 'Complete') return component('gateway', 'degraded', 'rolling out', { link, ...since })
  return component('gateway', 'ok', 'rollout settled', { link, ...since })
}

export function rulesComponent(f: PlatformFacts): HealthComponent {
  const link = { page: 'gateway' }
  if (!f.rules) return component('gateway_rules', 'unknown', 'never served', { link })
  const age = f.now - f.rules.at
  if (f.rules.compileErrors > 0) return component('gateway_rules', 'degraded', `${f.rules.compileErrors} compile error${f.rules.compileErrors === 1 ? '' : 's'}`, { link })
  if (age > 5 * MINUTE) return component('gateway_rules', 'down', `not served for ${ago(age)}`, { link, since: iso(f.rules.at) })
  if (age > MINUTE) return component('gateway_rules', 'degraded', `served ${ago(age)} ago`, { link })
  return component('gateway_rules', 'ok', `served ${ago(age)} ago`, { link })
}

export function opaComponent(f: PlatformFacts): HealthComponent {
  const link = { page: 'gateway', anchor: 'engines' }
  // OPAL feeds OPA its policy and data; whether it is alive is asked of OPA itself.
  if (f.opaDirect === 'ok') return component('opa', 'ok', 'reachable (OPAL-managed)', { link })
  if (f.opaDirect === 'down') return component('opa', 'down', 'OPA did not answer', { link })
  return component('opa', 'unknown', 'not connected', { link })
}

export function opalComponent(f: PlatformFacts): HealthComponent {
  const link = { page: 'gateway', anchor: 'opal' }
  if (f.opal.oldestMs === null) return component('opal_data', 'unknown', 'never fetched', { link })
  const age = f.now - f.opal.oldestMs
  const state: ComponentState = age < 10 * MINUTE ? 'ok' : age < 30 * MINUTE ? 'degraded' : 'down'
  return component('opal_data', state, `${ago(age)} ago`, { link, ...(state !== 'ok' ? { since: iso(f.opal.oldestMs) } : {}) })
}

export function archiveComponent(f: PlatformFacts): HealthComponent {
  const link = { page: 'audit' }
  if (sources.auditSink() === 'legacy') return component('audit_archive', 'not_deployed', 'audit/v1 is off', { link })
  if (!sources.archiveEnabled()) return component('audit_archive', 'not_deployed', 'no archiver configured', { link })
  if (!f.outbox) return component('audit_archive', 'unknown', 'outbox not readable', { link })
  if (f.outbox.oldestMs === null) return component('audit_archive', 'ok', 'up to date', { link })
  const age = f.now - f.outbox.oldestMs
  const state: ComponentState = age < HOUR ? 'ok' : age < 24 * HOUR ? 'degraded' : 'down'
  return component('audit_archive', state, `archive ${ago(age)} behind`, { link, since: iso(f.outbox.oldestMs) })
}

export function certificatesComponent(f: PlatformFacts): HealthComponent {
  const grafana = sources.grafanaUrl()
  const link = grafana ? { grafana } : undefined
  const extra = link ? { link } : {}
  const c = f.certs
  if (c.state === 'not_configured') return component('certificates', 'unknown', 'not connected', extra)
  if (c.state === 'warming') return component('certificates', 'unknown', 'checking', extra)
  if (c.state === 'down') return component('certificates', 'unknown', 'Prometheus did not answer', extra)
  if (c.state !== 'ok') return component('certificates', 'unknown', 'unknown', extra)
  if (c.certs.length === 0) return component('certificates', 'unknown', 'no certificates found', extra)
  const soonest = c.certs[0]
  const notReady = c.certs.filter((x) => !x.ready).length
  const summary = `${c.certs.length} cert${c.certs.length === 1 ? '' : 's'}, soonest ${Math.floor(soonest.daysLeft)} d`
  if (notReady > 0 || soonest.daysLeft < CERT_CRITICAL_DAYS) return component('certificates', 'down', notReady > 0 ? `${notReady} not ready` : summary, extra)
  if (soonest.daysLeft < CERT_WARNING_DAYS) return component('certificates', 'degraded', summary, extra)
  return component('certificates', 'ok', summary, extra)
}

/**
 * Edge protection: the live sites behind the WAF (a zone on a Gateway whose Coraza policy is in force,
 * no Ingress left). Any site without it is `degraded` — reachable around the WAF, or with no WAF at all.
 */
export function wafComponent(w: { total: number; waf: number; unknown: number; unprotectedHosts: number } | null): HealthComponent {
  const link = { page: 'settings', anchor: 'zones' }
  if (!w) return component('waf', 'unknown', 'could not be read', { link })
  // Unprotected sites next to their distinct hosts: several sites can share one host.
  const metrics = { total: w.total, waf: w.waf, unknown: w.unknown, unprotected: w.total - w.waf - w.unknown, unprotectedHosts: w.unprotectedHosts }
  if (w.total === 0) return component('waf', 'ok', 'no live sites', { link, metrics })
  const summary = `${w.waf}/${w.total} sites behind the WAF`
  if (w.unknown > 0) return component('waf', 'unknown', summary, { link, metrics })
  return component('waf', w.waf === w.total ? 'ok' : 'degraded', summary, { link, metrics })
}

export const healthModule: ModuleDef<Health> = {
  name: 'health',
  tier: 'inline',
  freshMs: 15_000,
  timeoutMs: 400,
  async compute() {
    const [facts, redisOk, kratos, lokiOk, waf] = await Promise.all([
      platformFacts(),
      sources.redisHealthy(),
      sources.kratosReady(PROBE_MS),
      sources.lokiConfigured() ? sources.lokiReady(PROBE_MS) : Promise.resolve(null),
      sources.kubeMode() === 'off' ? Promise.resolve(null) : probe(() => sources.wafCoverage(), PROBE_MS),
    ])
    const ready = sources.bootstrapReady()
    const sha = sources.commitSha()
    const components: HealthComponent[] = [
      ...(waf ? [wafComponent(waf.ok ? waf.value : null)] : []),
      gatewayComponent(facts),
      rulesComponent(facts),
      opaComponent(facts),
      opalComponent(facts),
      component('kratos', kratos === 'ok' ? 'ok' : kratos === 'slow' ? 'degraded' : 'down', kratos === 'ok' ? 'ready' : kratos === 'slow' ? 'slow' : 'not answering', { link: { page: 'users' } }),
      component('jinbe', ready ? 'ok' : 'down', ready ? `ready · ${sha.slice(0, 7)}` : 'starting'),
      component('redis', redisOk ? 'ok' : 'down', redisOk ? 'ok' : 'not answering'),
      lokiOk === null
        ? component('audit_store', 'unknown', 'not connected', { link: { page: 'audit' } })
        : component('audit_store', lokiOk ? 'ok' : 'down', lokiOk ? 'ok' : 'Loki did not answer', { link: { page: 'audit' } }),
      archiveComponent(facts),
      certificatesComponent(facts),
    ]
    const sourcesOut: Record<string, SourceDetail> = {
      ...facts.sources,
      kratos: src(kratos === 'ok' ? 'ok' : kratos === 'slow' ? 'timeout' : 'down'),
      redis: src(redisOk ? 'ok' : 'down'),
      ...(lokiOk === null ? {} : { loki: src(lokiOk ? 'ok' : 'down') }),
      grafana: sources.grafanaUrl() ? src('ok') : src('not_configured', CONNECT.grafana),
    }
    return ok({ environment: sources.environment(), components }, sourcesOut)
  },
}
