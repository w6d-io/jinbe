import { queryOpa } from '../services/opa-client.js'
import { permits, type HeldRights } from '../services/authorization-resolution.js'
import { SwrCache } from '../cache/swr.js'

/**
 * Every authorization question jinbe asks about its own API, answered by the engine that enforces
 * at the gateway: OPA, over the RBAC data jinbe publishes (Redis → OPAL → OPA, packages `rbac` and
 * `rbac.delegation`). ONE ENGINE — a guard reading anything else (the ConfigMap model it used to)
 * could let through what the gateway refuses, or refuse what it lets through, and nobody would see
 * the two drift.
 *
 * Cached for a few seconds per question: a guard runs on every request and a console fires several
 * at once. Short enough that a removed group stops granting almost at once. Only answers are cached —
 * a failure is asked again next time. Concurrent askers of one question share ONE query (a console
 * opening fires dozens of guarded requests at once, and each used to ask OPA itself).
 *
 * In process only (the `opa` namespace of src/cache is `local`): an authorization answer never goes
 * to a store another process can write. Every RBAC change drops the answers on every replica
 * (invalidateAuthz, from rbacService.invalidateBundle), and again once OPA has had time to load the
 * change, so an answer read in between is not kept either. Never stale: an answer older than the TTL
 * is asked again, never served while refreshing.
 *
 * Fails closed: OPA unconfigured, unreachable, or answering nothing (no policy loaded) throws
 * `AuthzUnavailableError`, and the guard answers 503 — never an allow, and never a 403 that would
 * read as "holds nothing" when the truth is "could not tell".
 */

export const AUTHZ_TTL_MS = 5_000

/** The app whose roles decide jinbe's own API. */
export const JINBE_APP = 'jinbe'

export class AuthzUnavailableError extends Error {}

/**
 * How long after an RBAC change OPA may still answer from the data it had: the OPAL push is debounced
 * (OPAL_PUSH_WINDOW_MS) and the client then fetches. Answers are dropped again after this.
 */
export const AUTHZ_PROPAGATION_MS = 2_000

// Bounded: a burst of distinct callers must not grow this for ever (oldest dropped first).
const answers = new SwrCache<unknown>({ namespace: 'opa', freshMs: AUTHZ_TTL_MS, staleMs: AUTHZ_TTL_MS, local: true, l1Max: 10_000 })

async function ask<T>(rule: string, input: Record<string, unknown>, read: (result: unknown) => T | undefined): Promise<T> {
  const key = `${rule}\u0000${JSON.stringify(input)}`
  return answers.get(key, async () => {
    let result: unknown
    try {
      result = await queryOpa<unknown>(rule, input)
    } catch (err) {
      throw new AuthzUnavailableError((err as Error).message)
    }
    const value = read(result)
    if (value === undefined) throw new AuthzUnavailableError(`OPA answered nothing usable for ${rule}`)
    return value
  }) as Promise<T>
}

const displayAnswers = new SwrCache<HeldRights>({ namespace: 'opa.display', freshMs: 30_000, staleMs: 5 * 60_000, local: true, l1Max: 20_000 })

let propagationTimer: ReturnType<typeof setTimeout> | null = null

/**
 * The RBAC data changed: drop every cached answer on every replica now, and once more after OPA has
 * loaded the change (an answer asked in between may predate it).
 */
export function invalidateAuthz(): void {
  void answers.invalidate()
  void displayAnswers.invalidate()
  if (propagationTimer) clearTimeout(propagationTimer)
  propagationTimer = setTimeout(() => {
    propagationTimer = null
    void answers.invalidate()
    void displayAnswers.invalidate()
  }, AUTHZ_PROPAGATION_MS)
  propagationTimer.unref?.()
}

const strings = (v: unknown): string[] | undefined =>
  Array.isArray(v) && v.every((s) => typeof s === 'string') ? [...v].sort() : undefined

/**
 * What somebody holds in one app (`rbac.user_info`): global roles included, exactly as `allow`
 * unions them. Keyed on the address because that is what the RBAC bindings are keyed on.
 */
export function rights(email: string, app: string = JINBE_APP): Promise<HeldRights> {
  return ask('rbac/user_info', { email, app }, (r) => {
    if (!r || typeof r !== 'object') return undefined
    const info = r as { groups?: unknown; roles?: unknown; permissions?: unknown }
    const groups = strings(info.groups ?? [])
    const roles = strings(info.roles ?? [])
    const permissions = strings(info.permissions ?? [])
    return groups && roles && permissions ? { groups, roles, permissions } : undefined
  })
}

/**
 * What somebody holds, for DISPLAY — a list of users showing each one's groups and roles. Never for a
 * decision: guards call `rights`.
 *
 * A users page asks this once per row, so it is kept longer than a decision (fresh 30s, then served
 * while refreshed, for up to 5 min) and dropped with every other answer on each RBAC change
 * (invalidateAuthz). In process only, like every answer.
 */
export function rightsForDisplay(email: string, app: string = JINBE_APP): Promise<HeldRights> {
  return displayAnswers.get(`${app}\u0000${email}`, () => rights(email, app))
}

export interface RouteQuestion {
  email: string
  /** HTTP method, as the gateway passes it. */
  method: string
  /** The request path, without its query string. */
  path: string
  aal?: string
  client?: boolean
}

export interface Decision {
  allow: boolean
  reason: string
}

/**
 * The gateway's own verdict on one request to jinbe (`rbac.decision`): the jinbe route_map, the site
 * layer, the org layer (membership, org grants, the per-org admin roster) and per-site 2FA — the same
 * rule, the same data, the same input.
 */
export function decide(q: RouteQuestion): Promise<Decision> {
  const input: Record<string, unknown> = {
    email: q.email,
    object: q.path,
    action: q.method.toUpperCase(),
    app: JINBE_APP,
  }
  if (q.aal) input.aal = q.aal
  if (q.client !== undefined) input.client = q.client
  return ask('rbac/decision', input, (r) => {
    const d = r as { allow?: unknown; reason?: unknown } | undefined
    if (!d || typeof d.allow !== 'boolean') return undefined
    return { allow: d.allow, reason: typeof d.reason === 'string' ? d.reason : d.allow ? 'ok' : 'forbidden' }
  })
}

/** The organisations this address administers: on that org's roster AND a member of it. */
export function manageableOrgs(email: string): Promise<string[]> {
  return ask('rbac/delegation/manageable_orgs', { actor: { email } }, strings)
}

/** The organisations this address belongs to, as the org layer reads membership. */
export function memberOrgs(email: string): Promise<string[]> {
  return ask('rbac/caller_organizations', { email }, strings)
}

/** Holder of a GLOBAL role carrying `*` — power over every org, not only within one service. */
export function isSuperAdmin(email: string): Promise<boolean> {
  return ask('rbac/super_admin', { email, app: JINBE_APP }, (r) =>
    typeof r === 'boolean' ? r : undefined,
  )
}

/**
 * Whether this address must hold a second factor (`rbac.second_factor_required`, rbac.rego § 8c:
 * a member of a group in data.second_factor). A policy that predates the rule answers nothing, which
 * is `AuthzUnavailableError` like any other unanswerable question.
 */
export function secondFactorRequired(email: string): Promise<boolean> {
  return ask('rbac/second_factor_required', { email }, (r) => (typeof r === 'boolean' ? r : undefined))
}

/**
 * Whether permissions OPA resolved allow the required one: `*`, the permission itself, or an
 * ancestor of it (`admin:read` covers `admin.organisation:read`).
 */
export function holds(permissions: readonly string[], required: string): boolean {
  return permissions.includes('*') || permits(permissions, required)
}

/** Whether somebody holds `required` in jinbe (global roles included). */
export async function holdsInJinbe(email: string, required: string): Promise<boolean> {
  return holds((await rights(email)).permissions, required)
}

/** Test seam. */
export function clearAuthzCache(): void {
  answers.resetLocal()
  displayAnswers.resetLocal()
}
