import { rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { redisRbacRepository, type GroupDefinition } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'
import {
  everyOrgByGroups, exceeding, flatten, groupGrants, heldByGroups, isEmpty, isStaffGroup, loadEveryOrg, loadRoles,
  type PermissionsByScope,
} from './grant-subset.js'
import { refusalDetails } from './permission-refusal.js'

/**
 * Nobody grants what they do not hold — THE HOLDING RULE (authz-v2-design §1.1, §2.5).
 *
 * Every grant — a group definition, a widened role, a group assignment, an imported bundle — needs
 * the grant permission (checked by the route) AND that the actor holds every permission it confers,
 * app by app, including what it carries into every org (the every-org map). A super admin passes
 * because they hold everything, never because they are special: there is no wildcard and no bypass.
 * Taking power away needs nothing more than the route's permission.
 *
 * Objects defined in code — the staff groups and super_admins, jinbe's roles and route map — are not
 * changed through the API at all, whoever asks: 409 `defined_in_code`.
 *
 * What the actor holds is asked of OPA (their groups); what a definition confers is read from the
 * published model. FAIL-CLOSED: no identity answers 401, OPA unreachable 503 — never an allow.
 */

export type RbacChange =
  /** Create (`after` = the definition), update (`after`) or delete (`after` = null) of one group. */
  | { kind: 'group'; name: string; after: GroupDefinition | null }
  /** Replacing one service's roles. */
  | { kind: 'roles'; service: string; roles: Record<string, string[]> }
  /** Replacing one service's route map. */
  | { kind: 'routes'; service: string }

type Refusal = { missing?: string[]; missingByScope?: Record<string, string[]>; grantedBy?: string[]; hint?: string }

function refuse(reason: string, message: string, change: RbacChange, actor: AuditActorInput, details: Refusal = {}, statusCode = 403): never {
  auditEventService.emit({
    category: 'rbac', kind: 'change', verb: 'update', target: targetOf(change),
    result: 'denied', reason, severity: 'warn',
    actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
    requestId: actor.requestId, source: 'jinbe-api',
  }).catch(() => {})
  throw Object.assign(new Error(message), { statusCode, code: reason, refusal: { code: reason, message, ...details } })
}

/** What a grant confers: platform permissions per app, and org permissions carried into every org. */
interface Conferred {
  platform: PermissionsByScope
  everyOrg: PermissionsByScope
}

/** Refuses a grant that exceeds what the actor holds: what is missing, and who grants it. */
async function refuseExceeding(missing: Conferred, what: string, change: RbacChange, actor: AuditActorInput): Promise<never> {
  const names = [...flatten(missing.platform), ...flatten(missing.everyOrg).map((p) => `${p} (every org)`)]
  const details = await refusalDetails(missing.platform)
  refuse('grant_exceeds_own', `${what} grants what you do not hold: ${names.join(', ')}`, change, actor, {
    // `every_org:<app>` for what a group carries into every org, beside the platform part per app.
    missing: names,
    missingByScope: { ...missing.platform, ...Object.fromEntries(Object.entries(missing.everyOrg).map(([app, perms]) => [`every_org:${app}`, perms])) },
    ...details,
  })
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

/** What a group definition confers, from the current model. */
async function conferredBy(def: GroupDefinition): Promise<Conferred> {
  const apps = Object.keys(def)
  const [roles, everyOrg] = await Promise.all([loadRoles(apps), loadEveryOrg(apps)])
  return { platform: groupGrants(def, roles), everyOrg: groupGrants(def, everyOrg) }
}

/** What `conferred` grants that `groups` (the actor's) do not hold. */
async function beyond(groups: readonly string[], conferred: Conferred): Promise<Conferred> {
  const platformApps = Object.keys(conferred.platform)
  const everyOrgApps = Object.keys(conferred.everyOrg)
  const [held, heldEveryOrg] = await Promise.all([heldByGroups(groups, platformApps), everyOrgByGroups(groups, everyOrgApps)])
  return { platform: exceeding(conferred.platform, held), everyOrg: exceeding(conferred.everyOrg, heldEveryOrg) }
}

const nothing = (c: Conferred) => isEmpty(c.platform) && isEmpty(c.everyOrg)

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
      const missing = await beyond(await askGroups(actor.email), await conferredBy(change.after))
      if (!nothing(missing)) await refuseExceeding(missing, `Group '${change.name}'`, change, actor)
      return
    }
    case 'roles': {
      // Widening a role is widening every group that binds it: what it adds must be held too. A role
      // no group binds grants nobody anything yet (a new service's roles).
      const added = await addedToBoundRoles(change.service, change.roles)
      if (isEmpty(added)) return
      const missing = await beyond(await askGroups(actor.email), { platform: added, everyOrg: {} })
      if (!nothing(missing)) await refuseExceeding(missing, `This change to the roles of '${change.service}'`, change, actor)
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
 * Handing out a group (PUT /api/admin/users/:email/groups, the bulk add, a group given at creation):
 * the holding rule over what the group confers. The route already required groups.members:write.
 */
export async function assertMayAssignGroup(group: string, actor?: AuditActorInput): Promise<void> {
  authenticated(actor)
  const definition = (await redisRbacRepository.getGroups())[group]
  if (!definition) return
  const change: RbacChange = { kind: 'group', name: group, after: null }
  const missing = await beyond(await askGroups(actor.email), await conferredBy(definition))
  if (!nothing(missing)) await refuseExceeding(missing, `Group '${group}'`, change, actor)
}

/**
 * A bundle import: every group whose grants the import changes (resolved against the roles the import
 * leaves) clears the same rule as a single edit — never a code-defined group, nothing not held.
 */
export async function assertBundleWithinOwn(
  changed: ReadonlyArray<{ name: string; after: PermissionsByScope }>,
  actor?: AuditActorInput,
): Promise<void> {
  authenticated(actor)
  if (changed.length === 0) return
  const groups = await askGroups(actor.email)
  for (const { name, after } of changed) {
    const change: RbacChange = { kind: 'group', name, after: null }
    if (isStaffGroup(name)) refuseDefinedInCode(`Group '${name}'`, change, actor)
    const missing = await beyond(groups, { platform: after, everyOrg: {} })
    if (!nothing(missing)) await refuseExceeding(missing, `Imported group '${name}'`, change, actor)
  }
}
