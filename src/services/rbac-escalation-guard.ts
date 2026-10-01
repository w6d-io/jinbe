import { AuthzUnavailableError, grantVerdict, rights, type GrantQuestion, type GrantVerdict } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { redisRbacRepository, type GroupDefinition } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'
import { exceeding, flatten, isEmpty, isStaffGroup, type PermissionsByScope } from './grant-subset.js'
import { hintFor, refusalDetails } from './permission-refusal.js'

/**
 * Nobody grants what they do not hold — THE HOLDING RULE (authz-v2-design §1.1, §2.5).
 *
 * The rule has ONE copy: the policy's `rbac.delegation` verdicts, over the data the gateway decides
 * on. jinbe asks it for every grant — a group definition (`define_group`), handing out a group
 * (`add_to_group`), taking one away (`remove_from_group`) — and renders its answer: what is missing
 * (the every-org part included) and which groups would cover it. A super admin passes because they
 * hold everything, never because they are special. jinbe keeps no rule of its own to drift from it.
 *
 * Two changes the policy cannot judge, because what they grant is not in its data yet — widening a
 * role, importing a bundle — ask only that the actor holds, as OPA resolves it (`rbac.user_info`),
 * every permission they add. That is a subset test on OPA's answer, not a second rule.
 *
 * Objects defined in code — the staff groups and super_admins, jinbe's roles and route map — are not
 * changed through the API at all, whoever asks: 409 `defined_in_code`.
 *
 * FAIL-CLOSED: no identity answers 401, OPA unreachable 503 — never an allow.
 */

export type RbacChange =
  /** Create (`after` = the definition), update (`after`) or delete (`after` = null) of one group. */
  | { kind: 'group'; name: string; after: GroupDefinition | null }
  /** Replacing one service's roles. */
  | { kind: 'roles'; service: string; roles: Record<string, string[]> }
  /** Replacing one service's route map. */
  | { kind: 'routes'; service: string }

type Refusal = { missing?: string[]; missingByScope?: Record<string, string[]>; reasons?: string[]; permission?: string; grantedBy?: string[]; hint?: string }

function refuse(reason: string, message: string, change: RbacChange, actor: AuditActorInput, details: Refusal = {}, statusCode = 403): never {
  auditEventService.emit({
    category: 'rbac', kind: 'change', verb: 'update', target: targetOf(change),
    result: 'denied', reason, severity: 'warn',
    actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
    requestId: actor.requestId, source: 'jinbe-api',
  }).catch(() => {})
  throw Object.assign(new Error(message), { statusCode, code: reason, refusal: { code: reason, message, ...details } })
}

/** How a refused verdict reads: the platform part per app, then `every organisation: <perm>`. */
export function verdictRefusal(v: GrantVerdict): Refusal & { missing: string[] } {
  const names = [...flatten(v.missing), ...flatten(v.missingEveryOrg).map((p) => `every organisation: ${p}`)]
  return {
    missing: names,
    ...(names.length === 1 ? { permission: names[0] } : {}),
    // `every_org:<app>` for what a grant carries into every org, beside the platform part per app.
    missingByScope: { ...v.missing, ...Object.fromEntries(Object.entries(v.missingEveryOrg).map(([app, perms]) => [`every_org:${app}`, perms])) },
    reasons: v.reasons,
    grantedBy: v.grantedBy,
    hint: hintFor(v.grantedBy, names),
  }
}

/** Asks the policy; 503 when it cannot tell. */
async function ask(q: GrantQuestion): Promise<GrantVerdict> {
  try {
    return await grantVerdict(q)
  } catch (err) {
    if (err instanceof AuthzUnavailableError) unavailable(err)
    throw err
  }
}

function refuseVerdict(v: GrantVerdict, what: string, change: RbacChange, actor: AuditActorInput): never {
  const details = verdictRefusal(v)
  const why = details.missing.length > 0 ? `grants what you do not hold: ${details.missing.join(', ')}` : `is refused (${v.reasons.join(', ')})`
  refuse('grant_exceeds_own', `${what} ${why}`, change, actor, details)
}

function refuseDefinedInCode(what: string, change: RbacChange, actor: AuditActorInput): never {
  refuse('defined_in_code', `${what} is defined in code and cannot be changed here`, change, actor, {}, 409)
}

function targetOf(change: RbacChange): string {
  switch (change.kind) {
    case 'group': return `group:${change.name}`
    case 'roles': return `service:${change.service}:roles`
    case 'routes': return `service:${change.service}:routes`
  }
}

function unavailable(err: unknown): never {
  throw Object.assign(
    new Error(`OPA could not be asked, so this change to the access model is refused: ${(err as Error).message}`),
    { statusCode: 503, code: POLICY_UNAVAILABLE },
  )
}

async function askGroups(email: string): Promise<string[]> {
  try {
    return (await rights(email)).groups
  } catch (err) {
    unavailable(err)
  }
}

function authenticated(actor?: AuditActorInput): asserts actor is AuditActorInput & { email: string } {
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
}

/** What of `added` (app → permissions) the actor does not hold, as OPA resolves their roles per app. */
async function notHeld(email: string, added: PermissionsByScope): Promise<PermissionsByScope> {
  const held: PermissionsByScope = {}
  try {
    for (const app of Object.keys(added)) held[app] = (await rights(email, app)).permissions
  } catch (err) {
    unavailable(err)
  }
  return exceeding(added, held)
}

async function refuseNotHeld(missing: PermissionsByScope, what: string, change: RbacChange, actor: AuditActorInput): Promise<never> {
  const names = flatten(missing)
  refuse('grant_exceeds_own', `${what} grants what you do not hold: ${names.join(', ')}`, change, actor, {
    missing: names, missingByScope: missing, ...(await refusalDetails(missing)),
  })
}

/** What a roles change adds to the roles some group binds under `service`, as `{ service: [...] }`. */
async function addedToBoundRoles(service: string, roles: Record<string, string[]>): Promise<PermissionsByScope> {
  const current = (await redisRbacRepository.getRoles(service)) ?? {}
  const defs = await redisRbacRepository.getGroups()
  const bound = new Set(Object.values(defs).flatMap((d) => d[service] ?? []))
  const added = Object.entries(roles)
    .filter(([role]) => bound.has(role))
    .flatMap(([role, perms]) => perms.filter((p) => !(current[role] ?? []).includes(p)))
  return added.length > 0 ? { [service]: [...new Set(added)].sort() } : {}
}

/** Throws unless `actor` may make `change` (see the module comment). */
export async function assertNoSelfEscalation(change: RbacChange, actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  switch (change.kind) {
    case 'group': {
      if (isStaffGroup(change.name)) refuseDefinedInCode(`Group '${change.name}'`, change, actor)
      if (!change.after) return
      const v = await ask({ kind: 'define_group', actor: actor.email, definition: change.after })
      if (!v.allow) refuseVerdict(v, `Group '${change.name}'`, change, actor)
      return
    }
    case 'roles': {
      // Widening a role is widening every group that binds it: what it adds must be held too. A role
      // no group binds grants nobody anything yet (a new service's roles).
      const added = await addedToBoundRoles(change.service, change.roles)
      if (isEmpty(added)) return
      const missing = await notHeld(actor.email, added)
      if (!isEmpty(missing)) await refuseNotHeld(missing, `This change to the roles of '${change.service}'`, change, actor)
      return
    }
    case 'routes': {
      // Lowering what a route asks is a grant to everyone who holds the lower permission; refused to
      // anybody who holds a role in that service themselves.
      const groups = await askGroups(actor.email)
      const defs = await redisRbacRepository.getGroups()
      if (groups.some((g) => (defs[g]?.[change.service]?.length ?? 0) > 0)) {
        refuse('self_escalation', `You hold a role in '${change.service}', so you may not change its routes`, change, actor)
      }
      return
    }
  }
}

/**
 * Handing out a group (PUT /api/admin/users/:email/groups, the bulk add): the policy's
 * `add_to_group` verdict. A group nothing defines is refused earlier, as not in the model.
 */
export async function assertMayAssignGroup(group: string, actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  const v = await ask({ kind: 'add_to_group', actor: actor.email, group })
  if (!v.allow) refuseVerdict(v, `Group '${group}'`, { kind: 'group', name: group, after: null }, actor)
}

/** Taking groups away: the policy's `remove_from_group` verdict (the revoke permission). */
export async function assertMayRemoveFromGroups(groups: readonly string[], actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  if (groups.length === 0) return
  const v = await ask({ kind: 'remove_from_group', actor: actor.email })
  if (!v.allow) refuseVerdict(v, `Removing '${groups.join("', '")}'`, { kind: 'group', name: groups[0], after: null }, actor)
}

/**
 * A bundle import: every group whose grants the import changes (resolved against the roles the import
 * leaves) — never a code-defined group, nothing the actor does not hold (as OPA resolves it).
 */
export async function assertBundleWithinOwn(
  changed: ReadonlyArray<{ name: string; after: PermissionsByScope }>,
  actor?: AuditActorInput,
): Promise<void> {
  authenticated(actor)
  if (changed.length === 0) return
  for (const { name, after } of changed) {
    const change: RbacChange = { kind: 'group', name, after: null }
    if (isStaffGroup(name)) refuseDefinedInCode(`Group '${name}'`, change, actor)
    const missing = await notHeld(actor.email, after)
    if (!isEmpty(missing)) await refuseNotHeld(missing, `Imported group '${name}'`, change, actor)
  }
}
