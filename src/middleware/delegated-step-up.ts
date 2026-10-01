import type { FastifyRequest } from 'fastify'
import { declaredRoute } from '../policy/declared-routes.js'
import { specOf } from '../policy/catalog.js'

/**
 * A delegated caller (an MCP key acting as its holder) never carries a second factor. Owner decision
 * 2026-09-29 ("Ok a b c d", item c): for the few step-up actions a key may do, the second factor its
 * holder proved WHEN CREATING THE KEY stands in — at most 30 days old, and only while the key was not
 * created with `allow_step_up_actions: false`.
 *
 * A browser sign-in (OAuth, src/oauth/) stands on the second factor proven for THAT sign-in, only when
 * the person ticked "Allow protected actions" at consent, and only until `stepUpUntil` — 12 h after that
 * proof by default (owner decision D1, 2026-09-30), computed by delegated-token.service.ts from the
 * settings (oauth/step-up-window.ts), the one clock token-info also hands auth-mcp.
 *
 * Deliberately narrow, whatever the catalogue says (a second guard): only these permissions. Sign-in
 * settings, the MCP switch, zones, the gateway, exports and anything `delegable: 'never'` stay with a
 * person in a browser.
 */
export const KEY_STEP_UP_PERMISSIONS: ReadonlySet<string> = new Set(['sites:apply', 'users:update_email', 'groups.members:write', 'groups:write'])
export const KEY_STEP_UP_MAX_AGE_MS = 30 * 24 * 3600 * 1000

export type KeyStepUpVerdict =
  | { ok: true; via: 'personal_key' | 'oauth_consent'; provenAt: string }
  | { ok: false; reason: 'not_delegated' | 'not_personal_key' | 'no_key_step_up' | 'step_up_actions_off' | 'key_step_up_expired' | 'not_allowed_here' }
export type DelegatedStepUpVerdict = KeyStepUpVerdict

/**
 * Whether this delegated request's step-up is satisfied by its key. `permission` is the one the guard
 * enforces (a guard that knows it passes it); else the route table's.
 */
export function delegatedStepUpVerdict(request: FastifyRequest, permission?: string, now = Date.now()): DelegatedStepUpVerdict {
  const uc = request.userContext
  if (uc?.authVia !== 'delegated' || !uc.delegation) return { ok: false, reason: 'not_delegated' }
  const d = uc.delegation
  let provenAt: string
  let via: 'personal_key' | 'oauth_consent'
  if (d.kind === 'oauth') {
    if (d.stepUpActions !== true) return { ok: false, reason: 'step_up_actions_off' }
    const at = d.stepUpAt ? Date.parse(d.stepUpAt) : NaN
    if (!Number.isFinite(at)) return { ok: false, reason: 'no_key_step_up' }
    const until = d.stepUpUntil ? Date.parse(d.stepUpUntil) : NaN
    if (!Number.isFinite(until) || now > until) return { ok: false, reason: 'key_step_up_expired' }
    provenAt = d.stepUpAt as string
    via = 'oauth_consent'
  } else if (d.kind === 'personal') {
    if (d.keyStepUpActions === false) return { ok: false, reason: 'step_up_actions_off' }
    const at = d.keyStepUpAt ? Date.parse(d.keyStepUpAt) : NaN
    if (!Number.isFinite(at)) return { ok: false, reason: 'no_key_step_up' }
    if (now - at > KEY_STEP_UP_MAX_AGE_MS) return { ok: false, reason: 'key_step_up_expired' }
    provenAt = d.keyStepUpAt as string
    via = 'personal_key'
  } else {
    return { ok: false, reason: 'not_personal_key' }
  }
  const method = request.method.toUpperCase()
  const pattern = request.routeOptions?.url ?? (request.url || '').split('?')[0]
  const required = permission ?? declaredRoute(method, pattern)?.permission
  if (!required || !KEY_STEP_UP_PERMISSIONS.has(required) || specOf(required)?.delegable !== 'direct') {
    return { ok: false, reason: 'not_allowed_here' }
  }
  return { ok: true, via, provenAt }
}

/** The name before browser sign-ins could stand on their consent (kept for one release). */
export const keyStepUpVerdict = delegatedStepUpVerdict
