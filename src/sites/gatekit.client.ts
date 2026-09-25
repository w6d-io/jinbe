import type { OathkeeperRule } from '../services/redis-rbac.repository.js'
import { sitesConfig } from './config.js'

/**
 * gatekit — the real Oathkeeper matcher and template engine, behind HTTP (GK-1).
 *
 * There is no JS approximation of what it answers: when gatekit is unset, down, slow or answers
 * anything but a 2xx, every caller gets `GatekitUnavailable` (503, "Checks are unavailable, nothing
 * was changed") and writes nothing.
 */

export interface CompileResult { id: string; ok: boolean; error?: string; warnings?: string[] }
export interface Overlap { a: string; b: string; method: string; exampleUrl: string }
export interface OverlapResult { overlaps: Overlap[]; invalid?: Array<{ id: string; error: string }> }
/** `error`: a rule failed to compile or timed out — Oathkeeper then fails the whole request. */
export interface MatchResult { matched: string[]; verdict: 'one' | 'none' | 'multiple' | 'error'; captureGroups?: string[]; errors?: Array<{ id: string; error: string }> }
export interface RenderResult { value: string; bytes: number; wire?: string; error?: string; warnings?: string[] }
export interface Probe { method: string; url: string }
export interface RenderSample { subject?: string; email?: string; aal?: 'aal1' | 'aal2'; anonymous?: boolean; method: string; url: string; pattern?: string }

export class GatekitUnavailable extends Error {
  readonly statusCode = 503
  readonly code = 'checks_unavailable'
  constructor(detail: string) {
    super(`Checks are unavailable, nothing was changed (${detail})`)
  }
}

/**
 * A 400 from gatekit is a verdict about the input (a template or rule that does not parse), not an
 * outage. Still nothing is written; the caller is told what gatekit refused.
 */
export class GatekitRejected extends Error {
  readonly statusCode = 422
  readonly code = 'checks_rejected'
  constructor(readonly detail: string) {
    super(`The checks refused the input: ${detail}`)
  }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const { GATEKIT_URL, GATEKIT_TIMEOUT_MS } = sitesConfig()
  if (!GATEKIT_URL) throw new GatekitUnavailable('GATEKIT_URL is not set')
  let res: Response
  try {
    res = await fetch(new URL(path, GATEKIT_URL), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(GATEKIT_TIMEOUT_MS),
    })
  } catch (err) {
    throw new GatekitUnavailable(err instanceof Error && err.name === 'TimeoutError' ? 'timed out' : 'unreachable')
  }
  if (res.status === 400) {
    const detail = await res.json().then((b) => (b as { error?: string }).error).catch(() => undefined)
    throw new GatekitRejected(detail ?? 'rejected')
  }
  if (!res.ok) throw new GatekitUnavailable(`gatekit answered ${res.status}`)
  try {
    return (await res.json()) as T
  } catch {
    throw new GatekitUnavailable('gatekit answered something that is not JSON')
  }
}

// Every request names the strategy: sites are written for `regexp` (the gateway's configured one).
const STRATEGY = 'regexp'

export const gatekit = {
  async compile(patterns: Array<{ id: string; url: string; methods?: string[] }>): Promise<CompileResult[]> {
    const out = await post<{ results?: CompileResult[] }>('/compile', { strategy: STRATEGY, patterns })
    if (!Array.isArray(out.results)) throw new GatekitUnavailable('malformed /compile answer')
    return out.results
  },

  /** Host-aware: probes are generated for `hosts` on top of the ones given. */
  async overlap(rules: OathkeeperRule[], probes: Probe[], hosts: string[]): Promise<OverlapResult> {
    const out = await post<OverlapResult>('/overlap', { strategy: STRATEGY, rules, probes, hosts })
    if (!Array.isArray(out.overlaps)) throw new GatekitUnavailable('malformed /overlap answer')
    return out
  },

  async match(rules: OathkeeperRule[], method: string, url: string): Promise<MatchResult> {
    const out = await post<MatchResult>('/match', { strategy: STRATEGY, rules, method, url })
    if (!Array.isArray(out.matched)) throw new GatekitUnavailable('malformed /match answer')
    return out
  },

  /** A template rendered against a sample session, as the header/cookie/payload/claims handler would. */
  async render(body: { template: string; kind: string; name?: string; sample: RenderSample }): Promise<RenderResult> {
    // gatekit knows no "email" or "anonymous": the session is built here, shaped like Kratos'.
    const { subject, email, aal, anonymous, method, url, pattern } = body.sample
    const id = subject ?? '00000000-0000-4000-8000-000000000000'
    return post<RenderResult>('/render', {
      kind: body.kind,
      template: body.template,
      ...(body.name ? { name: body.name } : {}),
      sample: {
        subject: anonymous ? '' : id,
        extra: anonymous ? {} : { identity: { id, traits: email ? { email } : {}, metadata_public: {} }, authenticator_assurance_level: aal ?? 'aal1' },
        header: {},
        matchContext: { url, method, header: {}, ...(pattern ? { pattern } : {}) },
      },
    }).catch((err) => {
      if (err instanceof GatekitRejected) return { value: '', bytes: 0, error: err.detail }
      throw err
    })
  },
}

export type Gatekit = typeof gatekit
