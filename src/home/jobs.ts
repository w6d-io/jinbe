import type { FastifyBaseLogger } from 'fastify'
import { getRedisClient } from '../services/redis-client.service.js'
import { quote } from '../audit/query/logql.js'
import { isFresh, readMany, refresh, type ModuleResult, type Stored } from './cache.js'
import * as sources from './sources.js'
import { CONNECT, DAY, MINUTE, ok, src, unavailable } from './modules/common.js'

/**
 * Background jobs (tier C, home-data §3.6): slow computations no request ever waits on. Each writes
 * its result to Redis (`home:v1:job:<name>`, through the same SWR cache as the modules); a module
 * reads the last result, and a missing or stale one starts a refresh off the request.
 *
 * A leader loop (one replica, Redis lock) also keeps the platform-scope jobs and modules warm, so the
 * first administrator of the day does not meet `warming` everywhere.
 */

export interface Certificate { name: string; daysLeft: number; ready: boolean }
export interface CertificatesJob { certs: Certificate[] }
export interface DriftJob { drifted: Array<{ site: string; items: number; checkedAt: string }> }
export type AccessReviewJob = sources.AccessReviewSummary

interface JobDef<T> { freshMs: number; compute: () => Promise<ModuleResult<T>> }

export const JOBS = {
  /** J5: cert-manager expiry from Prometheus (label `exported_namespace` is the cert's own). */
  certificates: {
    freshMs: 10 * MINUTE,
    async compute(): Promise<ModuleResult<CertificatesJob>> {
      const prom = sources.prom()
      if (!prom) return unavailable('not_configured', { prometheus: src('not_configured', CONNECT.prometheus) }, CONNECT.prometheus)
      const ns = quote(sources.releaseNamespace())
      const [days, notReady] = await Promise.all([
        prom.instant(`min by (name) ((certmanager_certificate_expiration_timestamp_seconds{exported_namespace=${ns}} - time()) / 86400)`),
        prom.instant(`max by (name) (certmanager_certificate_ready_status{exported_namespace=${ns}, condition="True"}) == 0`),
      ])
      const down = new Set(notReady.map((s) => s.metric.name))
      const certs = days
        .filter((s) => s.metric.name && Number.isFinite(s.value))
        .map((s) => ({ name: s.metric.name, daysLeft: Math.floor(s.value * 10) / 10, ready: !down.has(s.metric.name) }))
        .sort((a, b) => a.daysLeft - b.daysLeft)
      return ok({ certs }, { prometheus: src('ok') })
    },
  } satisfies JobDef<CertificatesJob>,

  /** Access review summary (privileged no-MFA / self-granted / dormant, J3 MFA coverage): a Kratos credential walk. */
  accessReview: {
    freshMs: 5 * MINUTE,
    async compute(): Promise<ModuleResult<AccessReviewJob>> {
      return ok(await sources.accessReviewSummary(), { kratos: src('ok') })
    },
  } satisfies JobDef<AccessReviewJob>,

  /** Drift sweep of live sites, every 5 minutes (kube GET + route map reads per site: never inline). */
  drift: {
    freshMs: 5 * MINUTE,
    async compute(): Promise<ModuleResult<DriftJob>> {
      if (sources.kubeMode() === 'off') return unavailable('not_configured', { kube: src('not_configured', CONNECT.kube) }, CONNECT.kube)
      const live = (await sources.siteRows()).filter((s) => s.appliedVersion !== null && s.status !== 'paused')
      const drifted: DriftJob['drifted'] = []
      for (const site of live) {
        const d = await sources.siteDrift(site.name)
        if (d.items.length > 0) drifted.push({ site: site.name, items: d.items.length, checkedAt: d.checkedAt })
      }
      return ok({ drifted }, { kube: src('ok') })
    },
  } satisfies JobDef<DriftJob>,
}

export type JobName = keyof typeof JOBS
type JobData = { certificates: CertificatesJob; accessReview: AccessReviewJob; drift: DriftJob }

const jobKey = (name: JobName) => `home:v1:job:${name}`

/** The last result of a job (null when it never ran), starting a refresh when it is stale or missing. */
export async function readJob<N extends JobName>(name: N, now = Date.now()): Promise<Stored<JobData[N]> | null> {
  const def = JOBS[name] as JobDef<JobData[N]>
  const [stored] = await readMany([jobKey(name)])
  if (!stored || !isFresh(stored, now)) void refresh(jobKey(name), def.freshMs, def.compute).catch(() => {})
  return stored as Stored<JobData[N]> | null
}

/** Runs a job now (the leader loop, tests). */
export function runJob<N extends JobName>(name: N): Promise<Stored<JobData[N]> | null> {
  const def = JOBS[name] as JobDef<JobData[N]>
  return refresh(jobKey(name), def.freshMs, def.compute)
}

// ─── Leader loop ─────────────────────────────────────────────────────────────

const LEADER_KEY = 'home:v1:leader'
const TICK_MS = MINUTE

let timer: NodeJS.Timeout | null = null
/** Set by service.ts: warms the platform-scope modules (kept here to avoid an import cycle). */
let warmPlatform: (() => Promise<void>) | null = null

export function onLeaderTick(fn: () => Promise<void>): void {
  warmPlatform = fn
}

async function tick(log: FastifyBaseLogger): Promise<void> {
  const leader = await getRedisClient().set(LEADER_KEY, process.pid.toString(), 'PX', TICK_MS - 5_000, 'NX').catch(() => null)
  if (leader !== 'OK') return
  for (const name of Object.keys(JOBS) as JobName[]) await readJob(name)
  await warmPlatform?.().catch((err) => log.debug({ err: (err as Error).message }, '[home] warming the platform modules failed'))
}

/** Started once the bootstrap marker is seen. Unref'd: it never holds the process open. */
export function startHomeBackground(log: FastifyBaseLogger): void {
  if (timer) return
  const run = () => void tick(log).catch((err) => log.debug({ err: (err as Error).message }, '[home] background tick failed'))
  setTimeout(run, 5_000).unref()
  timer = setInterval(run, TICK_MS)
  timer.unref()
}

export function stopHomeBackground(): void {
  if (timer) clearInterval(timer)
  timer = null
}

export const CERT_WARNING_DAYS = 21
export const CERT_CRITICAL_DAYS = 7
export const STALE_DRAFT_MS = 7 * DAY
