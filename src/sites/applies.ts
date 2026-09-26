import { randomUUID } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { render, type SiteCr } from './render.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { loadPlatform } from './platform.js'
import { kubeSites, type SiteCondition, type SiteCrObject } from './kube-sites.js'
import { publishPermissions, unpublishPermissions } from './publish.js'
import { pinnedHostsOf, siteError } from './checks.js'
import { siteLoginStore } from './login-store.js'
import { siteLoginOf } from './login.js'
import { sitesConfig } from './config.js'
import { auditSite, type Actor } from './audit.js'

/**
 * The apply timeline (site-ux §9.2): a live view of the Site CR's conditions after jinbe wrote it.
 *
 *   Saved → Permissions published → Site accepted → Rules synced → Rules loaded
 *         → Address (Ingress) → HTTPS (Certificate) — vanity sites only → Verified (Ready)
 *
 * Each apply is a record in Redis (`rbac:sites:applies:<site>`, the last 20 kept), so any replica
 * can answer GET/SSE; the replica that wrote the CR watches it. When the rules are not loaded
 * within SITES_RULES_LOADED_TIMEOUT_MS the site goes back to the version the gateway had before
 * (or, on a first apply, the Site CR and its permissions are removed): `rules_not_loaded`.
 */

export type StageId = 'saved' | 'permissions' | 'accepted' | 'rules-synced' | 'rules-loaded' | 'ingress' | 'certificate' | 'verified'
export type StageState = 'pending' | 'running' | 'done' | 'failed' | 'skipped'
export interface Stage { id: StageId; label: string; state: StageState; startedAt?: string; endedAt?: string; detail?: string }
export type ApplyState = 'running' | 'succeeded' | 'failed' | 'rolled-back'

export interface ApplyRecord {
  id: string
  site: string
  version: number
  by: string
  startedAt: string
  endedAt?: string
  state: ApplyState
  code?: string
  message?: string
  /** metadata.generation of the Site CR jinbe wrote; conditions of older generations are ignored. */
  generation?: number
  /** What the gateway had before, to go back to. */
  previous: SiteRecord['applied'] | null
  stages: Stage[]
}

const LABELS: Record<StageId, string> = {
  saved: 'Saved',
  permissions: 'Permissions published',
  accepted: 'Site accepted',
  'rules-synced': 'Rules synced',
  'rules-loaded': 'Rules loaded',
  ingress: 'Address',
  certificate: 'HTTPS',
  verified: 'Verified',
}
/** The operator condition each stage after "accepted" waits for. */
const CONDITION: Partial<Record<StageId, string>> = {
  'rules-synced': 'RulesSynced',
  'rules-loaded': 'RulesLoaded',
  ingress: 'IngressReady',
  certificate: 'CertificateReady',
  verified: 'Ready',
}
const KEEP = 20
const key = (site: string) => `rbac:sites:applies:${site}`
const latestKey = (site: string) => `rbac:sites:applies:${site}:latest`

export const terminal = (a: ApplyRecord) => a.state !== 'running'

export function withVersion(cr: SiteCr, version: number): SiteCr {
  return { ...cr, metadata: { ...cr.metadata, annotations: { ...cr.metadata.annotations, 'auth.w6d.io/version': String(version) } } }
}

// ── store ─────────────────────────────────────────────────────

export async function saveApply(a: ApplyRecord): Promise<void> {
  await getRedisClient().hset(key(a.site), a.id, JSON.stringify(a))
}

export async function getApply(site: string, id: string): Promise<ApplyRecord | null> {
  const raw = await getRedisClient().hget(key(site), id)
  return raw ? (JSON.parse(raw) as ApplyRecord) : null
}

export async function requireApply(site: string, id: string): Promise<ApplyRecord> {
  const a = await getApply(site, id)
  if (!a) throw siteError(404, 'not_found', `No apply ${id} for ${site}`)
  return a
}

/** The site's apply still in progress, if any (the sync loop leaves such a site alone). */
export async function runningApply(site: string): Promise<ApplyRecord | null> {
  const id = await getRedisClient().get(latestKey(site))
  const a = id ? await getApply(site, id) : null
  return a && !terminal(a) ? a : null
}

async function prune(site: string): Promise<void> {
  const all = Object.values(await getRedisClient().hgetall(key(site))).map((raw) => JSON.parse(raw) as ApplyRecord)
  const old = all.sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(KEEP)
  for (const a of old) await getRedisClient().hdel(key(site), a.id)
}

// ── stages (pure) ─────────────────────────────────────────────

export function setStage(a: ApplyRecord, id: StageId, state: StageState, detail?: string, at = new Date().toISOString()): void {
  const s = a.stages.find((x) => x.id === id)!
  if (state !== 'pending' && !s.startedAt) s.startedAt = at
  if ((state === 'done' || state === 'failed') && !s.endedAt) s.endedAt = at
  s.state = state
  if (detail !== undefined) s.detail = detail
  else if (state === 'done') delete s.detail
}

function finish(a: ApplyRecord, state: ApplyState, at: string, code?: string, message?: string): void {
  a.state = state
  a.endedAt = at
  if (code) a.code = code
  if (message) a.message = message
}

const describe = (c: SiteCondition | undefined) => (c ? [c.reason, c.message].filter(Boolean).join(': ') : 'waiting for the operator')

/**
 * One look at the Site CR: move the stages forward. Pure. `rollback` is true when the rules were
 * not loaded in time and the caller must put the previous version back.
 */
export function advance(a: ApplyRecord, cr: SiteCrObject | null, now: Date, timeoutMs: number): { rollback: boolean } {
  if (terminal(a)) return { rollback: false }
  const at = now.toISOString()
  const gen = a.generation ?? cr?.metadata.generation
  const cond = (type: string) => cr?.status?.conditions?.find((c) => c.type === type && (gen === undefined || c.observedGeneration === undefined || c.observedGeneration >= gen))

  const accepted = a.stages.find((s) => s.id === 'accepted')!
  if (accepted.state !== 'done' && cr) {
    const observed = cr.status?.observedGeneration ?? 0
    const validated = cond('Validated')
    if (gen !== undefined && observed >= gen && validated?.status === 'False') {
      setStage(a, 'accepted', 'failed', describe(validated), at)
      finish(a, 'failed', at, 'site_invalid', `The site operator refused this version (${describe(validated)}). Nothing was changed on the gateway.`)
      return { rollback: false }
    }
    if ((gen === undefined || observed >= gen) && validated?.status === 'True') setStage(a, 'accepted', 'done', undefined, at)
  }

  let previousDone = accepted.state === 'done'
  for (const s of a.stages) {
    const type = CONDITION[s.id]
    if (!type || s.state === 'skipped') continue
    if (!previousDone) break
    const c = cond(type)
    if (c?.status === 'True') setStage(a, s.id, 'done', undefined, at)
    else {
      setStage(a, s.id, 'running', describe(c), at)
      previousDone = false
    }
  }
  if (a.stages.every((s) => s.state === 'done' || s.state === 'skipped')) {
    finish(a, 'succeeded', at)
    return { rollback: false }
  }

  const elapsed = now.getTime() - new Date(a.startedAt).getTime()
  const loaded = a.stages.find((s) => s.id === 'rules-loaded')!
  if (loaded.state !== 'done' && elapsed > timeoutMs) {
    setStage(a, 'rules-loaded', 'failed', loaded.detail ?? 'the gateway did not load the rules in time', at)
    return { rollback: true }
  }
  // Rules are live; an address or certificate that never comes is shown, not reverted.
  if (elapsed > Math.max(timeoutMs * 5, 600_000)) finish(a, 'failed', at, 'not_ready', 'The site did not become ready in time')
  return { rollback: false }
}

// ── lifecycle ─────────────────────────────────────────────────

/** A new apply record for a saved version: Saved is done, everything else waits. */
export async function startApply(record: SiteRecord, by: string, previous: SiteRecord['applied'] | null): Promise<ApplyRecord> {
  const now = new Date().toISOString()
  const vanity = record.site.exposure.mode === 'vanity'
  const stages: Stage[] = (Object.keys(LABELS) as StageId[]).map((id) => ({
    id,
    label: LABELS[id],
    state: (id === 'ingress' || id === 'certificate') && !vanity ? 'skipped' : 'pending',
  }))
  const a: ApplyRecord = { id: randomUUID(), site: record.site.name, version: record.version, by, startedAt: now, state: 'running', previous, stages }
  setStage(a, 'saved', 'done', undefined, now)
  await saveApply(a)
  await getRedisClient().set(latestKey(a.site), a.id)
  await prune(a.site)
  return a
}

const SYSTEM_ACTOR: Actor = { id: null, email: 'jinbe (automatic rollback)', ip: null, ua: null, sessionId: null, requestId: null }

/** Put back what the gateway had before this apply: its version, permissions and 2FA bar; or nothing. */
async function rollBack(a: ApplyRecord): Promise<void> {
  const kube = kubeSites()
  if (a.previous) {
    const prev = await sitesRepository.version(a.site, a.previous.version)
    if (!prev) throw new Error(`version ${a.previous.version} of ${a.site} is gone`)
    const current = await sitesRepository.get(a.site)
    const site = { ...prev.site, state: current?.site.state ?? prev.site.state }
    const rendered = render(site, await loadPlatform())
    await publishPermissions(a.site, rendered, { description: site.description ?? site.displayName, pinnedHosts: pinnedHostsOf(await sitesRepository.list(), site), actor: SYSTEM_ACTOR })
    await siteLoginStore.set(a.site, siteLoginOf(site))
    await kube.apply(withVersion(rendered.siteCr, a.previous.version))
    await sitesRepository.setApplied(a.site, a.previous)
  } else {
    await kube.delete(a.site)
    await unpublishPermissions(a.site, SYSTEM_ACTOR)
    await siteLoginStore.set(a.site, null)
    await sitesRepository.setApplied(a.site, undefined)
  }
}

/** One watch step: read the Site CR, advance, roll back if due, store. */
export async function stepApply(site: string, id: string): Promise<ApplyRecord> {
  const a = await requireApply(site, id)
  if (terminal(a)) return a
  const cr = await kubeSites().get(site)
  const now = new Date()
  const { rollback } = advance(a, cr, now, sitesConfig().SITES_RULES_LOADED_TIMEOUT_MS)
  if (rollback) {
    const to = a.previous ? `version ${a.previous.version}` : 'no site'
    try {
      await rollBack(a)
      finish(a, 'rolled-back', now.toISOString(), 'rules_not_loaded', `The gateway did not load the new rules in time, so the site went back to ${to}.`)
      auditSite('rollback', site, SYSTEM_ACTOR, `automatic rollback of version ${a.version} to ${to}`, { applyId: a.id, from: a.version, to: a.previous?.version ?? null })
    } catch (err) {
      finish(a, 'failed', now.toISOString(), 'rollback_failed', `The rules were not loaded and going back to ${to} failed: ${err instanceof Error ? err.message : 'error'}`)
    }
  }
  await saveApply(a)
  return a
}

/** Watch an apply in this process until it ends (SITES_APPLY_POLL_MS; 0 = nobody watches here). */
export function watchApply(site: string, id: string, log?: { warn: (o: object, m: string) => void }): void {
  const every = sitesConfig().SITES_APPLY_POLL_MS
  if (every <= 0) return
  const tick = () => {
    stepApply(site, id)
      .then((a) => { if (!terminal(a)) setTimeout(tick, every).unref() })
      .catch((err) => {
        log?.warn({ err, site, id }, '[sites] apply watch step failed; retrying')
        setTimeout(tick, every).unref()
      })
  }
  setTimeout(tick, every).unref()
}
