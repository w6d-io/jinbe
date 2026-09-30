import { env } from '../config/env.js'
import { DERIVED_MAX_AGE_MS } from '../cache/swr.js'
import { isBootstrapReady } from '../bootstrap/ready-state.js'
import { redisClientService, getRedisClient } from '../services/redis-client.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { rbacService, type DirectoryStats } from '../services/rbac.service.js'
import { accessReviewService, type AccessReviewSummary } from '../services/access-review.service.js'
import { recertService } from '../services/recert.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { kratosService } from '../services/kratos.service.js'
import { buildOpalDatasourceEntries, opalEntryName } from '../services/opal-datasource.js'
import { membersOf, organisationStoreConfigured, organisationsById } from '../services/organisation-store.js'
import { sitesConfig } from '../sites/config.js'
import { listSites, protectionLookup } from '../sites/sites.service.js'
import { sitesRepository } from '../sites/repository.js'
import { listRequests } from '../sites/requests.js'
import { getMigration } from '../sites/migration/migration.service.js'
import { drift } from '../sites/status.js'
import { kubeSites, type SiteCrObject } from '../sites/kube-sites.js'
import { rollout } from '../gateway/service.js'
import { HttpLokiClient, lokiClient, type LokiClient } from '../audit/query/loki.js'
import { promClient, type PromClient } from '../telemetry/prom-query.js'
import { OPAL_KEY, RULES_KEY, auditFailuresKey } from './runtime.js'
import { DEAD_LETTER_KEY } from '../services/notifications/notifier.js'
import { adminAuthHeaders } from '../services/admin-auth.js'

/**
 * Every source the Home reads, behind one seam: the modules compute from these, the tests replace
 * this file. Each function is a thin wrapper over the service that owns the data — the Home keeps no
 * second copy of a rule, it only asks. Sources that can hang carry their own timeout here.
 */

export type { DirectoryStats, AccessReviewSummary, SiteCrObject, LokiClient, PromClient }

export const bootstrapReady = () => isBootstrapReady()
export const commitSha = () => env.COMMIT_SHA || 'unknown'
export const redisHealthy = () => redisClientService.isHealthy().catch(() => false)

/** Kratos admin readiness: `ok` under the budget, `slow` past it, `down` on an error answer. */
export async function kratosReady(timeoutMs: number): Promise<'ok' | 'slow' | 'down'> {
  try {
    const res = await fetch(`${env.KRATOS_ADMIN_URL.replace(/\/$/, '')}/admin/health/ready`, {
      headers: adminAuthHeaders(env.KRATOS_ADMIN_TOKEN),
      signal: AbortSignal.timeout(timeoutMs),
    })
    return res.ok ? 'ok' : 'down'
  } catch (err) {
    return (err as Error)?.name === 'TimeoutError' ? 'slow' : 'down'
  }
}

export function environment(): { name: string; production: boolean } {
  const cfg = sitesConfig()
  return { name: cfg.SITES_ENV ?? env.NODE_ENV ?? 'unknown', production: cfg.SITES_PRODUCTION }
}

export const kubeMode = () => sitesConfig().SITES_KUBE
/** The namespace this release runs in (the certificates it owns live there). */
export const releaseNamespace = () => env.LOKI_NAMESPACE ?? sitesConfig().namespace

export const gatewayRollout = () => rollout()

/** Every Site CR, or null when this build of the kube client cannot list. Throws KubeUnavailable. */
export async function siteCrs(): Promise<SiteCrObject[] | null> {
  const k = kubeSites()
  return k.list ? k.list() : null
}

export const siteDrift = (name: string) => drift(name)

/**
 * Last successful fetch per entry of the CURRENT manifest. Anything else in the hash — an entry a past
 * manifest listed (a per-service entry, a deleted service), which lingers for the hash's TTL — is not
 * what OPA refreshes today and must not age the component.
 */
export async function opalLastSuccess(): Promise<Record<string, number>> {
  const [raw, entries] = await Promise.all([getRedisClient().hgetall(OPAL_KEY), buildOpalDatasourceEntries()])
  const current = new Set(entries.map((e) => opalEntryName(e.url)))
  return Object.fromEntries(Object.entries(raw ?? {}).filter(([k]) => current.has(k)).map(([k, v]) => [k, Number(v)]).filter(([, v]) => Number.isFinite(v)))
}

export async function rulesServed(): Promise<{ at: number; count: number; compileErrors: number } | null> {
  const raw = await getRedisClient().get(RULES_KEY)
  return raw ? JSON.parse(raw) : null
}

export const auditSink = () => env.AUDIT_SINK
/** An archiver drains the outbox (AUD-7). Off: nothing does, and the outbox is capped instead. */
export const archiveEnabled = () => env.AUDIT_ARCHIVE_ENABLED
export const outboxMaxLen = () => env.AUDIT_OUTBOX_MAX_LEN

export const opaConfigured = () => !!env.OPA_URL
/**
 * OPA's own liveness (`GET /health`, open without a token in system_authz.rego). OPA gets its policy
 * and data from the OPAL server, so this is the engine's health as the Home can see it.
 */
export async function opaHealthy(timeoutMs: number): Promise<boolean> {
  if (!env.OPA_URL) return false
  try {
    const res = await fetch(`${env.OPA_URL.replace(/\/$/, '')}/health`, { signal: AbortSignal.timeout(timeoutMs) })
    return res.ok
  } catch {
    return false
  }
}

/** The audit/v1 outbox: backlog size and the age of its oldest entry (stream ids are ms-based). */
export async function outbox(): Promise<{ length: number; oldestMs: number | null }> {
  const redis = getRedisClient()
  const [length, first] = await Promise.all([
    redis.xlen(env.AUDIT_OUTBOX_STREAM),
    redis.xrange(env.AUDIT_OUTBOX_STREAM, '-', '+', 'COUNT', 1),
  ])
  const id = first?.[0]?.[0]
  return { length, oldestMs: id ? Number(id.split('-')[0]) : null }
}

/** Entity notifications no notifier could deliver, waiting in the dead-letter stream. */
export async function notificationsDeadLettered(): Promise<number> {
  return getRedisClient().xlen(DEAD_LETTER_KEY)
}

/** audit/v1 sink failures in the current and previous hour (J7). */
export async function auditFailures(now = Date.now()): Promise<number> {
  const hour = Math.floor(now / 3_600_000)
  const values = await getRedisClient().mget(auditFailuresKey(hour), auditFailuresKey(hour - 1))
  return values.reduce((a, v) => a + (Number(v) || 0), 0)
}

export const lokiConfigured = () => !!env.LOKI_URL
export const lokiNamespace = () => env.LOKI_NAMESPACE
/** Refreshers use a 5 s budget, not the 30 s LOKI_TIMEOUT_MS of the audit page (home-data §3.6). */
export const LOKI_HOME_TIMEOUT_MS = 5_000
export const loki = (): LokiClient => (env.LOKI_URL ? new HttpLokiClient(env.LOKI_URL, LOKI_HOME_TIMEOUT_MS) : lokiClient())

/**
 * Loki answers through the path every read takes. Not `/ready`: that is a per-component endpoint the
 * loki-gateway does not proxy (404), while `/loki/api/v1/*` is routed to the query frontend.
 */
export async function lokiReady(timeoutMs: number): Promise<boolean> {
  if (!env.LOKI_URL) return false
  try {
    const res = await fetch(`${env.LOKI_URL.replace(/\/$/, '')}/loki/api/v1/status/buildinfo`, { signal: AbortSignal.timeout(timeoutMs) })
    return res.ok
  } catch {
    return false
  }
}

export const prom = (): PromClient | null => promClient()
export const grafanaUrl = () => env.GRAFANA_URL ?? null

/**
 * The directory counts as last computed (`rbac:stats`), read raw so a request never waits on the
 * walk; a cold or stale value starts the SWR refresh rbacService already owns.
 */
export async function directoryStats(): Promise<{ stats: DirectoryStats; computedAt: number } | null> {
  const raw = await redisRbacRepository.getStats()
  void rbacService.getDirectoryStats().catch(() => {}) // SWR: refreshes only when stale or cold
  return raw ? (JSON.parse(raw) as { stats: DirectoryStats; computedAt: number }) : null
}

export const accessReviewSummary = async (): Promise<AccessReviewSummary> => (await accessReviewService.getAccessReview()).summary

export const siteRows = () => listSites()
/**
 * Live (applied) sites behind the WAF, from the zones and the Gateways discovered (cached 30 s).
 * `unprotectedHosts` counts the distinct hosts of the sites that are not: several sites can share one.
 */
export const wafCoverage = async () => {
  const [records, lookup] = await Promise.all([sitesRepository.list(), protectionLookup()])
  const live = records.filter((r) => r.applied).map((r) => ({ host: r.site.address.host, p: lookup(r.site.address.host) }))
  const unprotected = live.filter((s) => s.p && s.p.state !== 'waf')
  return {
    total: live.length,
    waf: live.filter((s) => s.p?.state === 'waf').length,
    unknown: live.filter((s) => !s.p).length,
    unprotectedHosts: new Set(unprotected.map((s) => s.host.toLowerCase())).size,
  }
}
export const siteRecords = () => sitesRepository.list()
export const deletedSites = async () => (await sitesRepository.deleted()).length
export const pendingRequests = () => listRequests({ state: 'pending' })
export interface MigrationView { state: string; dualrun?: { startedAt: string; regressions: unknown[] }; rollbackUntil?: string }
export const migration = async (): Promise<MigrationView> => (await getMigration()) as MigrationView
export const campaigns = () => recertService.listCampaigns()
export const inbox = (email: string) => recertService.getInbox(email)
export const legacyChanges = (limit: number) => auditEventService.query({ kind: 'change', limit })

/** Legacy audit stream rows since `sinceMs`, newest first, bounded. */
export async function legacyRows(sinceMs: number, count = 20_000): Promise<Array<[string, string[]]>> {
  return getRedisClient().xrevrange(env.REDIS_AUDIT_STREAM, '+', `${sinceMs}-0`, 'COUNT', String(count))
}

export async function orgNames(ids: readonly string[]): Promise<Record<string, string>> {
  if (!organisationStoreConfigured() || ids.length === 0) return {}
  return Object.fromEntries((await organisationsById(ids)).map((o) => [o.id, o.name]))
}

export async function orgMembers(orgId: string): Promise<string[]> {
  if (!organisationStoreConfigured()) return []
  return [...new Set((await membersOf(orgId)).map((m) => m.subjectId))]
}

/** email → {id, name, active}: the light directory walk (the shared kratos.directory cache). */
export async function identityDirectory(): Promise<Map<string, { id: string; name: string | null; active: boolean }>> {
  const bindings = await kratosService.getAllIdentitiesWithBindings({ maxAgeMs: DERIVED_MAX_AGE_MS })
  return new Map([...bindings].map(([email, b]) => [email, { id: b.id, name: b.name, active: b.active }]))
}
