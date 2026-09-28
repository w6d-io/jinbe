import { cacheKey, isFresh, readEpochs, readMany, refresh, type ModuleResult, type Stored } from './cache.js'
import { onLeaderTick } from './jobs.js'
import { canSee, scopeKeyOf, type HomeScope, type HomeView } from './scope.js'
import { HOME_MODULES, type HomeModuleName, type HomeResponse, type HomeWindow, type ModuleEnvelope } from './types.js'
import { within, type ModuleContext, type ModuleDef } from './modules/common.js'
import { healthModule } from './modules/health.js'
import { attentionModule } from './modules/attention.js'
import { peopleModule } from './modules/people.js'
import { activityModule } from './modules/activity.js'
import { accessModule } from './modules/access.js'
import { sitesModule } from './modules/sites.js'
import { changesModule } from './modules/changes.js'
import { actionsModule } from './modules/actions.js'
import { meModule } from './modules/me.js'

/**
 * Assembles the Home (home-data §3.6): one scope, then every visible module in parallel, each bounded
 * by its own budget so a slow or dead source costs its own tile and nothing else. The response is 200
 * whenever the scope resolved, even if every module is unavailable.
 */

export const MODULES: Record<HomeModuleName, ModuleDef<unknown>> = {
  health: healthModule,
  attention: attentionModule as ModuleDef<unknown>,
  people: peopleModule,
  activity: activityModule,
  access: accessModule,
  sites: sitesModule,
  changes: changesModule,
  actions: actionsModule,
  me: meModule,
}

const TIMED_OUT = Symbol('timed out')

function envelope(result: ModuleResult<unknown>, asOf: number | null, stale: boolean): ModuleEnvelope {
  const base = { status: result.status, asOf: asOf === null ? null : new Date(asOf).toISOString(), stale, sources: result.sources }
  if (result.status === 'ok') return { ...base, data: result.data }
  return { ...base, reason: result.reason, ...(result.connect ? { connect: result.connect } : {}) }
}

const warming = (): ModuleEnvelope => ({ status: 'unavailable', reason: 'warming', asOf: null, stale: false, sources: {} })
export const forbidden = (): ModuleEnvelope => ({ status: 'forbidden', asOf: null, stale: false, sources: {} })

async function finish(def: ModuleDef<unknown>, result: ModuleResult<unknown>, ctx: ModuleContext): Promise<ModuleResult<unknown>> {
  return def.personalise ? def.personalise(result, ctx) : result
}

async function serveDirect(def: ModuleDef<unknown>, ctx: ModuleContext): Promise<ModuleEnvelope> {
  try {
    const r = await within(def.compute(ctx), def.timeoutMs, TIMED_OUT)
    if (r === TIMED_OUT) return { status: 'unavailable', reason: 'timeout', asOf: null, stale: false, sources: {} }
    return envelope(r, ctx.now, false)
  } catch {
    return { status: 'unavailable', reason: 'source_down', asOf: null, stale: false, sources: {} }
  }
}

async function serveCached(def: ModuleDef<unknown>, key: string, stored: Stored | null, ctx: ModuleContext): Promise<ModuleEnvelope> {
  const start = () => refresh(key, def.freshMs, () => def.compute(ctx))
  if (stored) {
    if (isFresh(stored, ctx.now)) return envelope(await finish(def, stored.result, ctx), stored.asOf, false)
    // Past its fresh window: one refresh off the request; the last good value meanwhile, marked stale.
    void start().catch(() => {})
    if (stored.result.status === 'ok') return envelope(await finish(def, stored.result, ctx), stored.asOf, true)
    return envelope(stored.result, stored.asOf, false)
  }
  const running = start()
  if (def.tier === 'background') {
    void running.catch(() => {})
    return warming()
  }
  const r = await within(running, def.timeoutMs, TIMED_OUT).catch(() => null)
  // Still computing past the budget (it goes on and fills the cache), or another replica is: warming.
  if (r === TIMED_OUT || r === null) return warming()
  return envelope(await finish(def, r.result, ctx), r.asOf, false)
}

/**
 * The envelopes of these modules for one caller and view. `finish` (the per-caller pass) is bounded
 * by the module budget as well; a failure there is the module's, never the response's.
 */
export async function buildModules(scope: HomeScope, view: HomeView, window: HomeWindow, names: readonly HomeModuleName[], now = Date.now()): Promise<Partial<Record<HomeModuleName, ModuleEnvelope>>> {
  const ctx: ModuleContext = { scope, view, window, now }
  const scopeKey = scopeKeyOf(view, scope.subject)
  const cached = names.filter((n) => MODULES[n].tier !== 'direct')
  const epochs = await readEpochs(cached)
  const keys = cached.map((n) => cacheKey(n, epochs[n], scopeKey, MODULES[n].windowed ? window : undefined))
  const stored = await readMany(keys)

  const entries = await Promise.all(names.map(async (name): Promise<[HomeModuleName, ModuleEnvelope]> => {
    const def = MODULES[name]
    try {
      if (def.tier === 'direct') return [name, await serveDirect(def, ctx)]
      const i = cached.indexOf(name)
      const env = await within(serveCached(def, keys[i], stored[i], ctx), def.timeoutMs + 200, TIMED_OUT)
      return [name, env === TIMED_OUT ? warming() : env]
    } catch {
      return [name, { status: 'unavailable', reason: 'source_down', asOf: null, stale: false, sources: {} }]
    }
  }))
  return Object.fromEntries(entries)
}

export async function buildHome(scope: HomeScope, view: HomeView, window: HomeWindow, org: string | null, now = Date.now()): Promise<HomeResponse> {
  const visible = HOME_MODULES.filter((m) => canSee(m, scope, view))
  const modules = await buildModules(scope, view, window, visible, now)
  return {
    scope: { platform: scope.platform, orgs: scope.orgs, roles: scope.roles, org },
    generatedAt: new Date(now).toISOString(),
    window,
    modules: modules as HomeResponse['modules'],
  }
}

/** The leader keeps the platform-scope modules warm (a synthetic platform reader, no per-caller data). */
const WARM: HomeModuleName[] = ['health', 'attention', 'people', 'activity', 'sites', 'changes']
onLeaderTick(async () => {
  const scope: HomeScope = {
    subject: '(home-warmer)', email: '(home-warmer)', name: null, aal: 'aal1', stepUpFresh: false, roles: [], permissions: [],
    platform: true, superAdmin: false, canApply: false, people: true, sessions: false, orgs: [],
  }
  const now = Date.now()
  const epochs = await readEpochs(WARM)
  const ctx: ModuleContext = { scope, view: { kind: 'platform' }, window: '24h', now }
  const keys = WARM.map((n) => cacheKey(n, epochs[n], 'platform', MODULES[n].windowed ? '24h' : undefined))
  const stored = await readMany(keys)
  await Promise.all(WARM.map((n, i) => {
    const s = stored[i]
    if (s && isFresh(s, now + 60_000)) return null // still fresh at the next tick
    return refresh(keys[i], MODULES[n].freshMs, () => MODULES[n].compute(ctx)).catch(() => null)
  }))
})
