import { env } from '../../config/env.js'
import { getRedisClient } from '../../services/redis-client.service.js'
import { redisRbacRepository, type OathkeeperRule, type RouteRule } from '../../services/redis-rbac.repository.js'
import type { SiteCr } from '../render.js'
import { sitesRepository } from '../repository.js'
import { kubeSites } from '../kube-sites.js'
import { siteError } from '../checks.js'
import { sitesConfig } from '../config.js'
import { auditSite, type Actor } from '../audit.js'
import { gatekit } from '../gatekit.client.js'
import { BUILT_IN_RULE_IDS } from '../../bootstrap/build-rules.js'
import { blocksOf, convertLegacy, type Decision, type Fix, type MigrationGroup } from './convert.js'
import { probesOf, runParity, type ParityDiff, type ParityReport } from './parity.js'

/**
 * The one-time migration from the legacy rules source (Redis `rbac:oathkeeper:rules`, bootstrap
 * built-ins included) to Site CRs (site-ux §20.3):
 *
 *   not-started → previewed → dual-run → (cut-over running) → cut-over → done (rollback window over)
 *                                                          ↘ rolled-back
 *
 * Until the cut-over no new site is applied, unless the gateway loads both rule files
 * (SITES_MIXED_GATEWAY). The cut-over creates the converted Site CRs and waits for RulesLoaded on
 * each; switching Oathkeeper's rule source is the chart's job (both files mounted, C-2). It is
 * refused on a mixed gateway, and while a converted rule matches a URL a rule that stays in the
 * legacy source also matches: the built-ins, which the bootstrap writes again on every start, and
 * the rules not carried over. Rollback, for SITES_MIGRATION_ROLLBACK_DAYS, restores the frozen
 * legacy rules and pauses the migrated Site CRs.
 *
 * Built-ins are the platform's own rules (login, Kratos, kuma, jinbe, MCP): they are counted apart
 * and are never "rules to migrate".
 *
 *   rbac:sites:migration           → String: JSON(MigrationDoc)
 *   rbac:sites:migration:snapshot  → String: JSON(legacy rules at cut-over)
 */

type StoredState = 'not-started' | 'previewed' | 'dual-run' | 'cut-over' | 'rolled-back'
interface CutoverStage { id: 'snapshot' | 'create' | 'rules-loaded' | 'switch'; label: string; state: 'pending' | 'running' | 'done' | 'failed'; startedAt?: string; endedAt?: string; detail?: string }
interface DualRun { startedAt: string; ticks: number; compared: number; same: number; differs: ParityDiff[]; regressions: ParityDiff[] }

interface MigrationDoc {
  state: StoredState
  options?: { fixes: Record<string, Fix[]>; decisions: Record<string, Decision> }
  previewedAt?: string
  groups?: MigrationGroup[]
  parity?: ParityReport
  dualrun?: DualRun
  cutover?: { startedAt: string; by: string; note?: string; state: 'running' | 'done' | 'failed'; stages: CutoverStage[]; created: string[]; message?: string }
  migrated?: SiteCr[]
  cutoverAt?: string
  rollbackUntil?: string
  rolledBackAt?: string
}

const KEY = 'rbac:sites:migration'
const SNAPSHOT = 'rbac:sites:migration:snapshot'
const LISTED = 50

async function load(): Promise<MigrationDoc> {
  const raw = await getRedisClient().get(KEY)
  return raw ? (JSON.parse(raw) as MigrationDoc) : { state: 'not-started' }
}
const save = (doc: MigrationDoc) => getRedisClient().set(KEY, JSON.stringify(doc))

const windowOver = (doc: MigrationDoc, now = Date.now()) => doc.state === 'cut-over' && !!doc.rollbackUntil && now > new Date(doc.rollbackUntil).getTime()
const shownState = (doc: MigrationDoc) => (windowOver(doc) ? 'done' : doc.cutover?.state === 'running' ? 'cutting-over' : doc.state)

const builtInIds = new Set(BUILT_IN_RULE_IDS)
const isBuiltIn = (rule: { id: string }) => builtInIds.has(rule.id)

type ApplyBlock = { code: string; message: string }

/** Why new sites cannot be applied now, or null when they can. */
function applyBlock(doc: MigrationDoc, legacy: OathkeeperRule[]): ApplyBlock | null {
  if (doc.state === 'cut-over') return null
  if (doc.state === 'rolled-back') return { code: 'migration_rolled_back', message: 'The migration was rolled back; the gateway reads the legacy rules again, so sites cannot be applied' }
  // The gateway loads both rule files: sites coexist with the legacy rules (preview still refuses any overlap).
  if (sitesConfig().SITES_MIXED_GATEWAY) return null
  if (legacy.length > 0) return { code: 'migration_pending', message: 'The gateway still reads the legacy rules; sites can be applied once the migration is cut over' }
  return null
}

/** New sites are applied only after the cut-over, on a mixed gateway, or where there never were legacy rules. */
export async function assertApplyAllowed(): Promise<void> {
  const block = applyBlock(await load(), await redisRbacRepository.getAccessRules())
  if (block) throw siteError(409, block.code, block.message)
}

/** Site CRs the migration created, which the sync loop keeps in place after the cut-over. */
export async function migratedCrs(): Promise<SiteCr[]> {
  const doc = await load()
  return doc.state === 'cut-over' ? doc.migrated ?? [] : []
}

async function convertNow(doc: MigrationDoc) {
  const legacy = await redisRbacRepository.getAccessRules()
  const taken = (await sitesRepository.list()).map((r) => r.site.name)
  const cfg = sitesConfig()
  const groups = convertLegacy(legacy, {
    namespace: cfg.namespace,
    fixes: doc.options?.fixes ?? {},
    decisions: doc.options?.decisions ?? {},
    taken,
    enabled: { authenticators: env.OATHKEEPER_ENABLED_AUTHENTICATORS, authorizers: env.OATHKEEPER_ENABLED_AUTHORIZERS, mutators: env.OATHKEEPER_ENABLED_MUTATORS, errors: env.OATHKEEPER_ENABLED_ERROR_HANDLERS },
  })
  return { legacy, groups }
}

async function parityNow(doc: MigrationDoc, legacy: OathkeeperRule[], groups: MigrationGroup[]): Promise<ParityReport> {
  const others = (await sitesRepository.list()).filter((r) => r.applied).flatMap((r) => r.applied!.rules)
  const routeMaps: Record<string, RouteRule[]> = {}
  for (const g of groups) routeMaps[g.proposedSite] = (await redisRbacRepository.getRouteMap(g.proposedSite))?.rules ?? []
  const dropped = Object.entries(doc.options?.decisions ?? {}).filter(([, d]) => d === 'drop').map(([id]) => id)
  return runParity(legacy, groups, others, routeMaps, dropped)
}

function dualrunView(doc: MigrationDoc) {
  const min = sitesConfig().SITES_MIGRATION_DUALRUN_MIN_SEC
  const d = doc.dualrun
  if (!d) return null
  const elapsed = (Date.now() - new Date(d.startedAt).getTime()) / 1000
  return { ...d, running: doc.state === 'dual-run', minDurationSec: min, eligible: doc.state === 'dual-run' && d.ticks > 0 && d.regressions.length === 0 && elapsed >= min }
}

export async function getMigration() {
  const doc = await load()
  const legacy = await redisRbacRepository.getAccessRules()
  const block = applyBlock(doc, legacy)
  return {
    state: shownState(doc),
    // Rules to migrate; the built-ins are counted apart.
    legacyRules: legacy.filter((r) => !isBuiltIn(r)).length,
    builtIn: legacy.filter(isBuiltIn).length,
    mixedGateway: sitesConfig().SITES_MIXED_GATEWAY,
    applyAllowed: !block,
    ...(block ? { applyBlocked: block } : {}),
    groups: doc.groups ?? [],
    ...(doc.parity ? { parity: doc.parity } : {}),
    ...(doc.dualrun ? { dualrun: dualrunView(doc) } : {}),
    ...(doc.cutover ? { cutover: doc.cutover } : {}),
    ...(doc.cutoverAt ? { cutoverAt: doc.cutoverAt, rollbackUntil: doc.rollbackUntil } : {}),
    ...(doc.rolledBackAt ? { rolledBackAt: doc.rolledBackAt } : {}),
  }
}

const assertNotCutOver = (doc: MigrationDoc) => {
  if (doc.state === 'cut-over' || doc.cutover?.state === 'running') throw siteError(409, 'already_cut_over', 'The migration is already cut over')
}

export async function preview(body: { fixes?: Record<string, Fix[]>; decisions?: Record<string, Decision> }, actor: Actor) {
  const doc = await load()
  assertNotCutOver(doc)
  doc.options = { fixes: body.fixes ?? {}, decisions: body.decisions ?? {} }
  const { groups } = await convertNow(doc)
  Object.assign(doc, { state: 'previewed', previewedAt: new Date().toISOString(), groups })
  delete doc.parity
  delete doc.dualrun
  await save(doc)
  auditSite('migration_preview', 'migration', actor, `previewed ${groups.length} groups`, { blocks: blocksOf(groups).length })
  return { groups }
}

export async function parity(): Promise<ParityReport> {
  const doc = await load()
  if (doc.state !== 'previewed' && doc.state !== 'dual-run') throw siteError(409, 'not_previewed', 'Preview the conversion first')
  const { legacy, groups } = await convertNow(doc)
  doc.groups = groups
  doc.parity = await parityNow(doc, legacy, groups)
  await save(doc)
  return doc.parity
}

export async function dualrun(action: 'start' | 'stop', actor: Actor) {
  const doc = await load()
  if (action === 'stop') {
    if (doc.state !== 'dual-run') throw siteError(409, 'not_running', 'No dual run is running')
    doc.state = 'previewed'
  } else {
    if (doc.state !== 'previewed') throw siteError(409, 'not_previewed', 'Preview the conversion first (and not after a cut-over)')
    if (!doc.parity) throw siteError(409, 'parity_missing', 'Run the parity check first')
    if (doc.parity.regressions.length > 0) throw siteError(409, 'parity_regressions', `${doc.parity.regressions.length} regression(s) in the parity check`)
    const blocks = blocksOf(doc.groups ?? [])
    if (blocks.length > 0) throw siteError(409, 'migration_blocked', blocks.map((b) => b.message).join('; '))
    doc.state = 'dual-run'
    doc.dualrun = { startedAt: new Date().toISOString(), ticks: 0, compared: 0, same: 0, differs: [], regressions: [] }
  }
  await save(doc)
  auditSite(`migration_dualrun_${action}`, 'migration', actor, `dual run ${action}`)
  return dualrunView(doc)
}

export async function dualrunStatus() {
  const view = dualrunView(await load())
  if (!view) throw siteError(404, 'not_found', 'No dual run yet')
  return view
}

/**
 * One dual-run pass: the conversion is redone from the live legacy rules (so an edit during the run
 * is caught) and the corpus replayed through both rule sets. Real gateway paths are not replayed —
 * jinbe has no feed of them yet (paths from Oathkeeper logs/metrics are a platform task).
 */
export async function dualrunTick(): Promise<void> {
  const doc = await load()
  if (doc.state !== 'dual-run' || !doc.dualrun) return
  const { legacy, groups } = await convertNow(doc)
  const report = await parityNow(doc, legacy, groups)
  const d = doc.dualrun
  d.ticks++
  d.compared += report.total
  d.same += report.identical
  d.differs = [...d.differs, ...report.differs].slice(-LISTED)
  d.regressions = [...d.regressions, ...report.regressions].slice(-LISTED)
  for (const b of blocksOf(groups)) d.regressions.push({ method: '-', url: '-', before: { rules: [], verdict: '-' }, after: { rules: [], verdict: '-' }, cause: `blocked: ${b.message}` })
  doc.groups = groups
  await save(doc)
}

const stage = (id: CutoverStage['id'], label: string): CutoverStage => ({ id, label, state: 'pending' })
function mark(s: CutoverStage, state: CutoverStage['state'], detail?: string) {
  const at = new Date().toISOString()
  if (!s.startedAt) s.startedAt = at
  if (state === 'done' || state === 'failed') s.endedAt = at
  s.state = state
  if (detail) s.detail = detail
}

/**
 * Converted rules that match a URL a rule staying in the legacy source also matches. Parity takes the
 * converted legacy rules as gone; the built-ins are not (the bootstrap writes them again on every
 * start), nor are the rules not carried over. Two rules on one URL and Oathkeeper fails the request.
 */
async function cutoverOverlaps(groups: MigrationGroup[]): Promise<string[]> {
  const legacy = await redisRbacRepository.getAccessRules()
  const converted = new Set(groups.flatMap((g) => g.legacyRuleIds))
  const staying = legacy.filter((r) => isBuiltIn(r) || !converted.has(r.id))
  const rendered = groups.flatMap((g) => g.renderedRules)
  if (staying.length === 0 || rendered.length === 0) return []
  const candidate = new Set(rendered.map((r) => r.id))
  const hosts = [...new Set(groups.flatMap((g) => g.siteCr?.spec.hosts ?? []))]
  const probes = [...new Map([...staying, ...rendered].flatMap(probesOf).map((p) => [`${p.method} ${p.url}`, p])).values()]
  const result = await gatekit.overlap([...staying, ...rendered], probes, hosts)
  // One line per pair of rules, with the first request both match.
  const pairs = new Map<string, string>()
  for (const o of result.overlaps.filter((x) => candidate.has(x.a) !== candidate.has(x.b))) {
    const [site, old] = candidate.has(o.a) ? [o.a, o.b] : [o.b, o.a]
    if (!pairs.has(`${site} ${old}`)) pairs.set(`${site} ${old}`, `${site} and ${old} (${o.method} ${o.exampleUrl})`)
  }
  return [...pairs.values()]
}

export async function cutover(actor: Actor, note?: string) {
  const doc = await load()
  assertNotCutOver(doc)
  if (sitesConfig().SITES_MIXED_GATEWAY) {
    throw siteError(409, 'mixed_gateway', 'The gateway loads the legacy rules and the site rules side by side, so the cut-over would serve both copies of every converted rule. Sites can already be applied here; cut over once the gateway reads the site rules only')
  }
  const view = dualrunView(doc)
  if (!view?.eligible) throw siteError(409, 'dualrun_not_eligible', 'The dual run must run for its minimum duration with no regression first')
  const groups = (doc.groups ?? []).filter((g) => g.kind !== 'unassigned' && g.siteCr)
  const overlaps = await cutoverOverlaps(groups)
  if (overlaps.length > 0) {
    const shown = overlaps.slice(0, 5).join('; ')
    throw siteError(409, 'cutover_overlap', `${overlaps.length} pair(s) of rules: a converted rule matches the same requests as a rule that stays in the legacy source (the built-in platform rules are written again on every start); the gateway would fail those requests: ${shown}${overlaps.length > 5 ? '; …' : ''}`)
  }
  const kube = kubeSites()
  await kube.ping()

  const stages = [stage('snapshot', 'Legacy rules frozen'), stage('create', 'Site CRs created'), stage('rules-loaded', 'Rules loaded on every gateway pod'), stage('switch', 'Cut over')]
  doc.cutover = { startedAt: new Date().toISOString(), by: actor.email ?? 'unknown', ...(note ? { note } : {}), state: 'running', stages, created: [] }
  await getRedisClient().set(SNAPSHOT, JSON.stringify(await redisRbacRepository.getAccessRules()))
  mark(stages[0], 'done')
  mark(stages[1], 'running')
  try {
    for (const g of groups) {
      await kube.apply(g.siteCr!)
      doc.cutover.created.push(g.proposedSite)
    }
  } catch (err) {
    for (const name of doc.cutover.created) await kube.delete(name).catch(() => {})
    mark(stages[1], 'failed', err instanceof Error ? err.message : 'error')
    Object.assign(doc.cutover, { state: 'failed', message: 'Creating the Site CRs failed; the ones created were removed' })
    await save(doc)
    throw err
  }
  mark(stages[1], 'done', `${groups.length} Site CRs (${groups.filter((g) => g.kind === 'system').length} system)`)
  mark(stages[2], 'running')
  doc.migrated = groups.map((g) => g.siteCr!)
  await save(doc)
  auditSite('migration_cutover', 'migration', actor, `cut-over started: ${groups.length} Site CRs`, { sites: doc.cutover.created, ...(note ? { note } : {}) })
  watchCutover()
  return { state: 'cutting-over', cutover: doc.cutover }
}

/** One look at the created Site CRs: finish the cut-over when every one has its rules loaded, undo it on timeout. */
export async function stepCutover() {
  const doc = await load()
  const c = doc.cutover
  if (!c || c.state !== 'running') return { state: shownState(doc), ...(c ? { cutover: c } : {}) }
  const kube = kubeSites()
  const waiting: string[] = []
  for (const name of c.created) {
    const cr = await kube.get(name)
    const gen = cr?.metadata.generation
    const loaded = cr?.status?.conditions?.find((x) => x.type === 'RulesLoaded' && (gen === undefined || x.observedGeneration === undefined || x.observedGeneration >= gen))
    if (loaded?.status !== 'True') waiting.push(name)
  }
  const now = new Date()
  const [, , loadedStage, switchStage] = c.stages
  if (waiting.length === 0) {
    mark(loadedStage, 'done')
    mark(switchStage, 'done')
    c.state = 'done'
    doc.state = 'cut-over'
    doc.cutoverAt = now.toISOString()
    doc.rollbackUntil = new Date(now.getTime() + sitesConfig().SITES_MIGRATION_ROLLBACK_DAYS * 86_400_000).toISOString()
  } else if (now.getTime() - new Date(c.startedAt).getTime() > sitesConfig().SITES_RULES_LOADED_TIMEOUT_MS) {
    for (const name of c.created) await kube.delete(name).catch(() => {})
    mark(loadedStage, 'failed', `not loaded: ${waiting.join(', ')}`)
    c.state = 'failed'
    c.message = 'The gateway did not load the converted rules in time; the Site CRs were removed and the legacy rules still serve'
    delete doc.migrated
  } else {
    loadedStage.detail = `waiting for ${waiting.join(', ')}`
  }
  await save(doc)
  return { state: shownState(doc), cutover: c }
}

function watchCutover(): void {
  const every = sitesConfig().SITES_APPLY_POLL_MS
  if (every <= 0) return
  const tick = () => {
    stepCutover()
      .then((r) => { if (r.state === 'cutting-over') setTimeout(tick, every).unref() })
      .catch(() => setTimeout(tick, every).unref())
  }
  setTimeout(tick, every).unref()
}

export async function rollback(actor: Actor) {
  const doc = await load()
  if (doc.state !== 'cut-over') throw siteError(409, 'not_cut_over', 'Only a cut-over migration can be rolled back')
  if (windowOver(doc)) throw siteError(409, 'rollback_window_closed', `The rollback window closed on ${doc.rollbackUntil}`)
  const raw = await getRedisClient().get(SNAPSHOT)
  if (!raw) throw siteError(409, 'snapshot_missing', 'The frozen legacy rules are gone; rollback is not possible')
  const snapshot = JSON.parse(raw) as OathkeeperRule[]
  const kube = kubeSites()
  await kube.ping()
  await redisRbacRepository.setAccessRules(snapshot)
  const paused: string[] = []
  for (const name of doc.cutover?.created ?? []) {
    const cr = await kube.get(name)
    if (!cr) continue
    const { status: _status, ...rest } = cr
    await kube.apply({ ...rest, metadata: { ...rest.metadata }, spec: { ...rest.spec, paused: true } })
    paused.push(name)
  }
  const since = (await sitesRepository.list()).filter((r) => r.applied && doc.cutoverAt && r.applied.at > doc.cutoverAt).map((r) => r.site.name)
  doc.state = 'rolled-back'
  doc.rolledBackAt = new Date().toISOString()
  await save(doc)
  auditSite('migration_rollback', 'migration', actor, `rolled back: ${snapshot.length} legacy rules restored`, { paused, sitesAppliedSinceCutover: since })
  return { state: doc.state, restoredRules: snapshot.length, paused, sitesAppliedSinceCutover: since }
}
