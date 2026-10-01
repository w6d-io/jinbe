import { queryOpa } from '../services/opa-client.js'
import type { HeldRights } from '../services/authorization-resolution.js'
import { grants } from '../policy/catalog.js'
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
  /**
   * A delegated caller (a user through a client): the scopes its token carries, and an OAuth token's
   * consent org when it names one (informational: a token is bound to no org). Sent only then, so
   * every other question keeps its input — and its cache key. The policy's `delegated_ok` (proposed)
   * requires a scope covering the route's permission; jinbe enforces the same before asking
   * (middleware/delegation-gate.ts).
   */
  delegation?: { scopes: readonly string[]; org?: string; client_id: string }
}

export interface Decision {
  allow: boolean
  reason: string
}

/**
 * The gateway's own verdict on one request to jinbe (`rbac.decision`): the jinbe route_map, the site
 * layer, the org layer (roles assigned in that org, the every-org map) and per-site 2FA — the same
 * rule, the same data, the same input.
 */
export function decide(q: RouteQuestion): Promise<Decision> {
  return ask('rbac/decision', decisionInput(q), (r) => {
    const d = r as { allow?: unknown; reason?: unknown } | undefined
    if (!d || typeof d.allow !== 'boolean') return undefined
    return { allow: d.allow, reason: typeof d.reason === 'string' ? d.reason : d.allow ? 'ok' : 'forbidden' }
  })
}

/** The exact input `decide` sends OPA for a question (the explainer shows it and asks `rbac.explain` with it). */
export function decisionInput(q: RouteQuestion): Record<string, unknown> {
  const input: Record<string, unknown> = {
    email: q.email,
    object: q.path,
    action: q.method.toUpperCase(),
    app: JINBE_APP,
  }
  if (q.aal) input.aal = q.aal
  if (q.client !== undefined) input.client = q.client
  if (q.delegation) {
    input.delegated = true
    input.scopes = [...q.delegation.scopes].sort()
    if (q.delegation.org) input.org = q.delegation.org
    input.client_id = q.delegation.client_id
  }
  return input
}

/** The organisations where this address holds `org.members:write` (assigned, or every-org). */
export function manageableOrgs(email: string): Promise<string[]> {
  return ask('rbac/delegation/manageable_orgs', { actor: { email } }, strings)
}

/** The organisations this address belongs to, as the org layer reads membership. */
export function memberOrgs(email: string): Promise<string[]> {
  return ask('rbac/caller_organizations', { email }, strings)
}

/**
 * What this address holds in each organisation (`rbac.org_permissions_by_org`): org permissions per
 * org, over the org universe — the roles assigned in each org it belongs to, plus what its platform
 * roles carry into every org (the every-org map). The org gates and `/me` read this.
 */
export function orgPermissionsByOrg(email: string, app: string = JINBE_APP): Promise<Record<string, string[]>> {
  return ask('rbac/org_permissions_by_org', { email, app }, (r) => {
    if (!r || typeof r !== 'object' || Array.isArray(r)) return undefined
    const out: Record<string, string[]> = {}
    for (const [org, perms] of Object.entries(r as Record<string, unknown>)) {
      const list = strings(perms)
      if (!list) return undefined
      out[org] = list
    }
    return out
  })
}

/**
 * THE HOLDING RULE's verdict on one grant (`rbac.delegation.*_verdict`): nobody grants what they do
 * not hold. ONE copy of the rule, in the policy, over the data the gateway decides on — jinbe keeps
 * none of its own, so the two cannot drift. Never cached: a grant is asked once and must see the
 * latest data. Fails closed like every question (AuthzUnavailableError → 503).
 */
export interface GrantVerdict {
  allow: boolean
  /** Sorted codes: missing_grant_permission, missing_permissions, missing_every_org_permissions,
   *  grantee_not_member, unknown_role, unknown_group, app_not_entitled, invalid_definition. */
  reasons: string[]
  /** app → what is missing on the platform (the grant permission itself included, under jinbe). */
  missing: Record<string, string[]>
  /** app → org permissions the grant carries into every org that the actor does not. */
  missingEveryOrg: Record<string, string[]>
  /** Names that would cover everything missing (groups, or "app:role" in that org). */
  grantedBy: string[]
}

export type GrantQuestion =
  | { kind: 'assign'; actor: string; grantee: string; org: string; role: string }
  | { kind: 'unassign'; actor: string; org: string }
  | { kind: 'add_to_group'; actor: string; group: string }
  | { kind: 'remove_from_group'; actor: string }
  /** A group as it will be; `roles` (app → role → permissions) resolves its roles to proposed ones (a bundle). */
  | { kind: 'define_group'; actor: string; definition: Record<string, readonly string[]>; roles?: Record<string, Record<string, readonly string[]>> }
  /** Roles as they will be, only the changed or new ones: app → role → permissions. */
  | { kind: 'define_roles'; actor: string; roles: Record<string, Record<string, readonly string[]>> }
  /** A per-person direct grant: one role or one permission of `app`, platform-wide or in one org. */
  | { kind: 'grant_direct'; actor: string; grantee: string; scope: string; app: string; grantKind: 'role' | 'permission'; name: string }
  | { kind: 'revoke_direct'; actor: string; scope: string }

function byApp(v: unknown): Record<string, string[]> | undefined {
  if (v === undefined || v === null) return {}
  if (typeof v !== 'object' || Array.isArray(v)) return undefined
  const out: Record<string, string[]> = {}
  for (const [app, perms] of Object.entries(v as Record<string, unknown>)) {
    const list = strings(perms)
    if (!list) return undefined
    if (list.length > 0) out[app] = list
  }
  return out
}

/** The exact rule and input a grant question sends OPA. */
export function grantInput(q: GrantQuestion): { rule: string; input: Record<string, unknown> } {
  const actor = { email: q.actor }
  switch (q.kind) {
    case 'assign': return { rule: 'rbac/delegation/assign_verdict', input: { actor, grantee: { email: q.grantee }, org: q.org, role: q.role } }
    case 'unassign': return { rule: 'rbac/delegation/unassign_verdict', input: { actor, org: q.org } }
    case 'add_to_group': return { rule: 'rbac/delegation/add_to_group_verdict', input: { actor, group: q.group } }
    case 'remove_from_group': return { rule: 'rbac/delegation/remove_from_group_verdict', input: { actor } }
    case 'define_group': return { rule: 'rbac/delegation/define_group_verdict', input: { actor, definition: q.definition, ...(q.roles ? { roles: q.roles } : {}) } }
    case 'define_roles': return { rule: 'rbac/delegation/define_roles_verdict', input: { actor, roles: q.roles } }
    // A platform grant names no org; an org grant names it (`org`), as delegation.rego reads them.
    case 'grant_direct': return { rule: 'rbac/delegation/grant_direct_verdict', input: { actor, grantee: { email: q.grantee }, app: q.app, kind: q.grantKind, name: q.name, ...(q.scope === 'platform' ? {} : { org: q.scope }) } }
    case 'revoke_direct': return { rule: 'rbac/delegation/revoke_direct_verdict', input: { actor, ...(q.scope === 'platform' ? {} : { org: q.scope }) } }
  }
}

export async function grantVerdict(q: GrantQuestion): Promise<GrantVerdict> {
  const { rule, input } = grantInput(q)
  let r: unknown
  try {
    r = await queryOpa<unknown>(rule, input)
  } catch (err) {
    throw new AuthzUnavailableError((err as Error).message)
  }
  const v = r as { allow?: unknown; reasons?: unknown; missing?: unknown; missing_every_org?: unknown; granted_by?: unknown } | undefined
  const reasons = strings(v?.reasons ?? [])
  const missing = byApp(v?.missing)
  const missingEveryOrg = byApp(v?.missing_every_org)
  const grantedBy = Array.isArray(v?.granted_by) && v.granted_by.every((s) => typeof s === 'string') ? [...(v.granted_by as string[])] : undefined
  if (!v || typeof v.allow !== 'boolean' || !reasons || !missing || !missingEveryOrg || !grantedBy) {
    throw new AuthzUnavailableError(`OPA answered nothing usable for ${rule}`)
  }
  return { allow: v.allow, reasons, missing, missingEveryOrg, grantedBy }
}

/** The org roles (`app:role`) this address may assign in `org` (`rbac.delegation.assignable_roles`). */
export function assignableRoles(email: string, org: string): Promise<string[]> {
  return ask('rbac/delegation/assignable_roles', { actor: { email }, org }, strings)
}

/**
 * Whether this address must hold a second factor (`rbac.second_factor_required`, rbac.rego § 8c:
 * a member of a group in data.second_factor). A policy that predates the rule answers nothing, which
 * is `AuthzUnavailableError` like any other unanswerable question.
 */
export function secondFactorRequired(email: string): Promise<boolean> {
  return ask('rbac/second_factor_required', { email }, (r) => (typeof r === 'boolean' ? r : undefined))
}

/** Whether permissions OPA resolved include the required one (exact match, policy/catalog.ts). */
export function holds(permissions: readonly string[], required: string): boolean {
  return grants(permissions, required)
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
