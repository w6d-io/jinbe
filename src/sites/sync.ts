import type { FastifyBaseLogger } from 'fastify'
import { withRedisLock } from '../services/redis-lock.js'
import type { SiteCr } from './render.js'
import { sitesRepository } from './repository.js'
import { kubeSites } from './kube-sites.js'
import { runningApply } from './applies.js'
import { expectedOf, specDiff } from './status.js'
import { sitesConfig } from './config.js'
import { auditSite, type Actor } from './audit.js'
import { dualrunTick, migratedCrs, stepCutover } from './migration/migration.service.js'

/**
 * The sync loop: Redis holds the intent (the source of truth); a Site CR that is missing, or whose
 * spec no longer matches what was applied, is written again. The operator already self-heals its
 * children; this heals the Site CR itself (deleted by hand, edited with kubectl, lost with a cluster).
 *
 * Rate limited twice: at most SITES_SYNC_MAX_PER_TICK writes per tick, and a site rewritten less
 * than COOLDOWN_MS ago waits (a writer fighting the loop is not answered in a tight loop). One
 * replica at a time (a Redis lock it does not wait for). A site with an apply in progress is left
 * to its apply.
 */

const COOLDOWN_MS = 5 * 60_000
const lastWrite = new Map<string, number>()
const SYNC_ACTOR: Actor = { id: null, email: 'jinbe (sync)', ip: null, ua: null, sessionId: null, requestId: null }

/** Test seam. */
export function resetSyncCooldown(): void {
  lastWrite.clear()
}

export interface SyncResult { recreated: string[]; rewritten: string[]; deferred: string[]; errors: string[] }

export async function syncOnce(): Promise<SyncResult> {
  const out: SyncResult = { recreated: [], rewritten: [], deferred: [], errors: [] }
  const kube = kubeSites()
  const max = sitesConfig().SITES_SYNC_MAX_PER_TICK
  const now = Date.now()

  const wanted: Array<{ name: string; cr: SiteCr; version: number | null }> = []
  for (const record of await sitesRepository.list()) {
    if (!record.applied || (await runningApply(record.site.name))) continue
    const expected = await expectedOf(record)
    if (expected) wanted.push({ name: record.site.name, cr: expected.cr, version: record.applied.version })
  }
  for (const cr of await migratedCrs()) wanted.push({ name: cr.metadata.name, cr, version: null })

  for (const { name, cr, version } of wanted) {
    try {
      const live = await kube.get(name)
      const differs = live ? specDiff(cr.spec, live.spec, 'spec') : []
      if (live && differs.length === 0) continue
      if (out.recreated.length + out.rewritten.length >= max || now - (lastWrite.get(name) ?? 0) < COOLDOWN_MS) {
        out.deferred.push(name)
        continue
      }
      await kube.apply(cr)
      lastWrite.set(name, now)
      ;(live ? out.rewritten : out.recreated).push(name)
      auditSite('sync', name, SYNC_ACTOR, live ? 'Site CR rewritten from the applied intent' : 'missing Site CR re-created from the applied intent', {
        version, ...(live ? { fields: differs.map((d) => d.field).slice(0, 20) } : {}),
      })
    } catch {
      out.errors.push(name)
    }
  }
  return out
}

/** One background tick: sync, then the migration's dual run and a cut-over in progress. */
export async function sitesTick(log?: FastifyBaseLogger): Promise<void> {
  try {
    await withRedisLock('sites:sync', async () => {
      const r = await syncOnce()
      if (r.recreated.length + r.rewritten.length + r.errors.length > 0) log?.info({ ...r }, '[sites] sync')
      await dualrunTick()
      await stepCutover()
    }, { waitMs: 0, ttlMs: 60_000 })
  } catch (err) {
    if ((err as { statusCode?: number }).statusCode !== 503) log?.warn({ err }, '[sites] background tick failed')
  }
}

let timer: NodeJS.Timeout | null = null

export function startSitesBackground(log: FastifyBaseLogger): void {
  const cfg = sitesConfig()
  if (cfg.SITES_KUBE === 'off' || cfg.SITES_SYNC_INTERVAL_MS <= 0 || timer) return
  timer = setInterval(() => void sitesTick(log), cfg.SITES_SYNC_INTERVAL_MS)
  timer.unref()
  log.info({ everyMs: cfg.SITES_SYNC_INTERVAL_MS }, '[sites] sync loop started')
}
