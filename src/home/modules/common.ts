import type { ModuleResult } from '../cache.js'
import type { HomeScope, HomeView } from '../scope.js'
import type { Connect, HomeModuleName, HomeWindow, ModuleReason, SourceDetail, SourceState } from '../types.js'

/** What a module computes from. */
export interface ModuleContext {
  scope: HomeScope
  view: HomeView
  window: HomeWindow
  now: number
}

/**
 * One Home module.
 *
 *   inline      cached; a cold key is computed while the request waits, up to `timeoutMs`
 *   background  cached; a cold key answers `warming` and is computed off the request (tier C —
 *               Loki, Kratos walks: never awaited by a request)
 *   direct      per caller, never cached (cheap, and personal)
 */
export interface ModuleDef<T = unknown> {
  name: HomeModuleName
  tier: 'inline' | 'background' | 'direct'
  freshMs: number
  timeoutMs: number
  /** The answer depends on the window (activity, access). */
  windowed?: boolean
  compute(ctx: ModuleContext): Promise<ModuleResult<T>>
  /** Per-caller finishing of a shared cached result (four-eyes, actionable, own inbox). */
  personalise?(result: ModuleResult<T>, ctx: ModuleContext): Promise<ModuleResult<unknown>>
}

/** Where to point an operator for each missing source (home-data §11). */
export const CONNECT = {
  loki: { setting: 'LOKI_URL', docs: 'docs/OBSERVABILITY.md' },
  prometheus: { setting: 'PROMETHEUS_URL', docs: 'jinbe/docs/observability.md' },
  kube: { setting: 'SITES_KUBE=in-cluster', docs: 'docs/SERVICE_PLUG.md' },
  decisions: { setting: 'opa-authz-proxy decision log (OBS-1.4)', docs: 'docs/research/obs-flow.md#36' },
  grafana: { setting: 'GRAFANA_URL', docs: 'jinbe/docs/observability.md' },
  auditV1: { setting: 'AUDIT_SINK=dual', docs: 'docs/OBSERVABILITY.md' },
} as const satisfies Record<string, Connect>

export const src = (state: SourceState, connect?: Connect): SourceDetail => (connect ? { state, connect } : { state })

export function ok<T>(data: T, sources: Record<string, SourceDetail> = {}): ModuleResult<T> {
  return { status: 'ok', data, sources }
}

export function unavailable(reason: ModuleReason, sources: Record<string, SourceDetail> = {}, connect?: Connect): ModuleResult<never> {
  return connect ? { status: 'unavailable', reason, sources, connect } : { status: 'unavailable', reason, sources }
}

/** Resolves with the value, or with `fallback` once `ms` pass (the work itself is not cancelled). */
export async function within<T, F>(p: Promise<T>, ms: number, fallback: F): Promise<T | F> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([p, new Promise<F>((resolve) => { timer = setTimeout(() => resolve(fallback), ms) })])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export const TIMED_OUT = Symbol('timed out')

/** A source call with its own budget: its value, or 'timeout' / 'down'. */
export async function probe<T>(p: () => Promise<T>, ms: number): Promise<{ ok: true; value: T } | { ok: false; state: 'timeout' | 'down'; error?: unknown }> {
  try {
    const v = await within(p(), ms, TIMED_OUT)
    return v === TIMED_OUT ? { ok: false, state: 'timeout' } : { ok: true, value: v as T }
  } catch (error) {
    return { ok: false, state: 'down', error }
  }
}

export const MINUTE = 60_000
export const HOUR = 60 * MINUTE
export const DAY = 24 * HOUR
export const windowMs = (w: HomeWindow) => (w === '7d' ? 7 * DAY : DAY)

export const iso = (ms: number) => new Date(ms).toISOString()

export function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 86400) return `${Math.round(s / 3600)} h`
  return `${Math.round(s / 86400)} d`
}
