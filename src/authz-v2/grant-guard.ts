import { auditEventService, type AuditActorInput } from '../services/audit-event.service.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import type { GroupDefinition } from '../services/redis-rbac.repository.js'
import { loadDataV2 } from './service.js'
import { isCodeOwnedGroup, mayAddToGroup, mayDefineGroup, type HoldingVerdict } from './holding.js'
import type { DataV2 } from './resolve.js'

/**
 * The escalation guard under authz v2 (rbac-escalation-guard.ts calls these once v2 is active): the
 * holding rule instead of "super admin or not". No `*`, no self-escalation special case — the rule
 * already means nobody grants what they do not hold, themselves included.
 *
 *   group definition    code-owned (staff groups, super_admins) → 409 defined_in_code; else holding
 *   roles, route maps,  code or a site intent owns them in v2 → 409 defined_in_code
 *   org service map
 *   group assignment    holding over what the group confers (platform + every-org)
 */

type Change =
  | { kind: 'group'; name: string; after: GroupDefinition | null }
  | { kind: 'roles'; service: string }
  | { kind: 'routes'; service: string }
  | { kind: 'org_services'; organizationId: string }

function targetOf(change: Change): string {
  switch (change.kind) {
    case 'group': return `group:${change.name}`
    case 'roles': return `service:${change.service}:roles`
    case 'routes': return `service:${change.service}:routes`
    case 'org_services': return `org_service_map:${change.organizationId}`
  }
}

function refuse(verdict: Exclude<HoldingVerdict, { ok: true }>, what: string, change: Change, actor: AuditActorInput): never {
  const status = verdict.reason === 'defined_in_code' ? 409 : verdict.reason === 'unknown_group' ? 422 : 403
  const message = verdict.reason === 'defined_in_code'
    ? `${what} is defined in code or by a site's intent, not through the API`
    : verdict.reason === 'unknown_group'
      ? `${what} does not exist in the v2 model`
      : verdict.reason === 'grant_permission_missing'
      ? `${what} needs ${verdict.permission}`
      : `${what} grants what you do not hold`
  auditEventService.emit({
    category: 'rbac', kind: 'change', verb: 'update', target: targetOf(change),
    result: 'denied', reason: verdict.reason, severity: 'warn',
    actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
    requestId: actor.requestId, source: 'jinbe-api',
  }).catch(() => {})
  const missing = 'missing' in verdict ? verdict.missing : undefined
  throw Object.assign(new Error(message), {
    statusCode: status, code: verdict.reason,
    refusal: { code: verdict.reason, message, ...(verdict.permission ? { permission: verdict.permission } : {}), ...(missing ? { missingByScope: missing } : {}) },
  })
}

async function data(): Promise<DataV2> {
  try {
    return await loadDataV2()
  } catch (err) {
    throw Object.assign(new Error(`The v2 model could not be read, so this change is refused: ${(err as Error).message}`), {
      statusCode: 503, code: POLICY_UNAVAILABLE,
    })
  }
}

function authenticated(actor?: AuditActorInput): asserts actor is AuditActorInput & { email: string } {
  if (!actor?.id || !actor.email) throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
}

export async function assertV2Change(change: Change, actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  if (change.kind !== 'group') return refuse({ ok: false, reason: 'defined_in_code' }, targetOf(change), change, actor)
  if (isCodeOwnedGroup(change.name)) return refuse({ ok: false, reason: 'defined_in_code' }, `Group '${change.name}'`, change, actor)
  const verdict = mayDefineGroup(await data(), actor.email, change.name, change.after)
  if (!verdict.ok) refuse(verdict, `Group '${change.name}'`, change, actor)
}

export async function assertV2Assign(group: string, actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  const verdict = mayAddToGroup(await data(), actor.email, group)
  if (!verdict.ok) refuse(verdict, `Group '${group}'`, { kind: 'group', name: group, after: null }, actor)
}
