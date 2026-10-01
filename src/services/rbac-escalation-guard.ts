import { isSuperAdmin, memberOrgs, rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { redisRbacRepository, type GroupDefinition } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'
import {
  exceeding, flatten, groupGrants, heldByGroups, isEmpty, isStaffGroup, loadRoles, type PermissionsByScope,
} from './grant-subset.js'
import { refusalDetails } from './permission-refusal.js'
import { isV2 } from '../authz-v2/model.js'

// Loaded on use: grant-guard reads the identity directory, which imports this module's importers.
const assertV2Change = async (...args: Parameters<typeof import('../authz-v2/grant-guard.js')['assertV2Change']>) =>
  (await import('../authz-v2/grant-guard.js')).assertV2Change(...args)
const assertV2Assign = async (...args: Parameters<typeof import('../authz-v2/grant-guard.js')['assertV2Assign']>) =>
  (await import('../authz-v2/grant-guard.js')).assertV2Assign(...args)

/**
 * No administrator rewrites the model in their own favour.
 *
 * `admin:write` lets somebody change groups, roles and route maps — but a change that touches what
 * THEY hold is one they could use to hand themselves more: widen a group they sit in, add a
 * permission to a role one of their groups carries, lower what a route of that service asks, map
 * another service onto their own organisation. Only a super admin (a global role carrying `*`, asked
 * of OPA) may make those, and only a super admin may create anything that grants `*`.
 *
 * GRANT ONLY WHAT YOU HOLD. Short of that, a holder of `groups:write` or `groups.members:write` could
 * still make a group bound to roles carrying what they lack, widen a group they are not in, or hand a
 * group to a second account they invited — escalation through somebody else. So a non-super-admin
 * may only create or update a group, widen a role a group binds, import a bundle, or assign a group,
 * when what it grants is a subset of what they hold, scope by scope (grant-subset.ts):
 * `grant_exceeds_own`, listing what is missing. The staff groups and super_admins are a super admin's
 * alone, however much the actor holds: `staff_group_super_admin_only`.
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
  /** Setting or clearing one organisation's service bundle. */
  | { kind: 'org_services'; organizationId: string }

const EVERYTHING = '*'

type Refusal = { permission?: string; missing?: string[]; missingByScope?: PermissionsByScope; grantedBy?: string[]; hint?: string }

function refuse(reason: string, message: string, change: RbacChange, actor: AuditActorInput, details: Refusal = {}): never {
  auditEventService.emit({
    category: 'rbac', kind: 'change', verb: 'update', target: targetOf(change),
    result: 'denied', reason, severity: 'warn',
    actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
    requestId: actor.requestId, source: 'jinbe-api',
  }).catch(() => {})
  throw Object.assign(new Error(message), { statusCode: 403, code: reason, refusal: { code: reason, message, ...details } })
}

/** Refuses a grant that exceeds what the actor holds: what is missing, and who grants it. */
async function refuseExceeding(missing: PermissionsByScope, what: string, change: RbacChange, actor: AuditActorInput): Promise<never> {
  const names = flatten(missing)
  const details = await refusalDetails(missing)
  refuse('grant_exceeds_own', `${what} grants what you do not hold: ${names.join(', ')}`, change, actor, {
    missing: names, missingByScope: missing, ...details,
  })
}

/** Refuses a change to a staff group or super_admins (a super admin's alone). */
async function refuseStaff(name: string, what: string, change: RbacChange, actor: AuditActorInput): Promise<never> {
  const details = await refusalDetails([EVERYTHING])
  refuse('staff_group_super_admin_only', `Only a super admin may ${what} '${name}': it is a staff group`, change, actor, {
    permission: EVERYTHING, ...details,
  })
}

/** What `groups` (the actor's) hold in the scopes `granted` names. */
async function actorHolds(groups: readonly string[], granted: PermissionsByScope): Promise<PermissionsByScope> {
  return heldByGroups(groups, Object.keys(granted))
}

function targetOf(change: RbacChange): string {
  switch (change.kind) {
    case 'group': return `group:${change.name}`
    case 'roles': return `service:${change.service}:roles`
    case 'routes': return `service:${change.service}:routes`
    case 'org_services': return `org_service_map:${change.organizationId}`
  }
}

function unavailable(err: unknown): never {
  throw Object.assign(
    new Error(`OPA could not be asked, so this change to the access model is refused: ${(err as Error).message}`),
    { statusCode: 503, code: POLICY_UNAVAILABLE },
  )
}

async function askSuperAdmin(email: string): Promise<boolean> {
  try {
    return await isSuperAdmin(email)
  } catch (err) {
    unavailable(err)
  }
}

async function askGroups(email: string): Promise<string[]> {
  try {
    return (await rights(email)).groups
  } catch (err) {
    unavailable(err)
  }
}

/** Whether a group definition hands out `*`: the global super_admin role, or a role carrying it. */
export async function grantsEverything(def: GroupDefinition): Promise<boolean> {
  for (const [service, roles] of Object.entries(def)) {
    if (!roles?.length) continue
    if (service === 'global' && roles.includes('super_admin')) return true
    const defined = (await redisRbacRepository.getRoles(service)) ?? {}
    if (roles.some((r) => (defined[r] ?? []).includes(EVERYTHING))) return true
  }
  return false
}

/** Whether any of these groups carries a role in `service`. */
async function groupsReach(groups: readonly string[], service: string): Promise<boolean> {
  if (groups.length === 0) return false
  const defs = await redisRbacRepository.getGroups()
  return groups.some((g) => (defs[g]?.[service]?.length ?? 0) > 0)
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
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
  const email = actor.email
  // authz v2: the holding rule; code- and intent-owned objects are not edited through the API.
  if (isV2()) return assertV2Change(change, actor)

  if (await askSuperAdmin(email)) return
  const groups = await askGroups(email)

  switch (change.kind) {
    case 'group': {
      if (groups.includes(change.name)) {
        refuse('self_escalation', `Only a super admin may change '${change.name}': you are a member of it`, change, actor)
      }
      if (isStaffGroup(change.name)) await refuseStaff(change.name, 'change', change, actor)
      if (!change.after) return
      if (await grantsEverything(change.after)) {
        refuse('grants_everything', `Only a super admin may make a group that grants '*'`, change, actor)
      }
      const granted = groupGrants(change.after, await loadRoles(Object.keys(change.after)))
      const missing = exceeding(granted, await actorHolds(groups, granted))
      if (!isEmpty(missing)) await refuseExceeding(missing, `Group '${change.name}'`, change, actor)
      return
    }
    case 'roles': {
      if (Object.values(change.roles).some((permissions) => permissions.includes(EVERYTHING))) {
        refuse('grants_everything', `Only a super admin may give a role '*'`, change, actor)
      }
      if (await groupsReach(groups, change.service)) {
        refuse('self_escalation', `Only a super admin may change the roles of '${change.service}': a group you are in holds one`, change, actor)
      }
      // Widening a role is widening every group that binds it: what it adds must be held too. A role
      // no group binds grants nobody anything yet (a new service's roles).
      const added = await addedToBoundRoles(change.service, change.roles)
      if (!isEmpty(added)) {
        const missing = exceeding(added, await actorHolds(groups, added))
        if (!isEmpty(missing)) await refuseExceeding(missing, `This change to the roles of '${change.service}'`, change, actor)
      }
      return
    }
    case 'routes':
      if (await groupsReach(groups, change.service)) {
        refuse('self_escalation', `Only a super admin may change the routes of '${change.service}': a group you are in holds a role there`, change, actor)
      }
      return
    case 'org_services': {
      let orgs: string[]
      try {
        orgs = await memberOrgs(email)
      } catch (err) {
        unavailable(err)
      }
      if (orgs.includes(change.organizationId)) {
        refuse('self_escalation', `Only a super admin may change the services of an organisation you belong to`, change, actor)
      }
      return
    }
  }
}

/**
 * Handing out a group (PUT /api/admin/users/:email/groups, the bulk add): `groups.members:write` lets
 * somebody assign one, but not a group that grants `*` (the global super_admin or admin role, or a
 * role carrying it), not to themselves — either would be the same escalation by membership instead of
 * by definition — not a staff group, and not one granting what they do not hold (a second account
 * would carry it). Only a super admin may.
 */
export async function assertMayAssignGroup(group: string, targetEmail: string, actor?: AuditActorInput): Promise<void> {
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
  if (isV2()) return assertV2Assign(group, actor)
  const self = targetEmail.toLowerCase() === actor.email.toLowerCase()
  const definition = (await redisRbacRepository.getGroups())[group]
  const wildcard = definition ? await grantsEverything(definition) : false

  if (await askSuperAdmin(actor.email)) return
  const change: RbacChange = { kind: 'group', name: group, after: null }
  if (wildcard) refuse('grants_everything', `Only a super admin may assign '${group}': it grants '*'`, change, actor)
  if (self) refuse('self_escalation', `Only a super admin may add themselves to '${group}'`, change, actor)
  await assertGrantWithinOwn(group, actor)
}

/**
 * The part of the rule every assigned group clears, platform-wide or not: not a staff group, and
 * nothing the actor does not hold. Super admins pass.
 */
export async function assertGrantWithinOwn(group: string, actor?: AuditActorInput): Promise<void> {
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
  if (isV2()) return assertV2Assign(group, actor)
  if (await askSuperAdmin(actor.email)) return
  const change: RbacChange = { kind: 'group', name: group, after: null }
  if (isStaffGroup(group)) await refuseStaff(group, 'assign', change, actor)
  const definition = (await redisRbacRepository.getGroups())[group]
  if (!definition) return
  const granted = groupGrants(definition, await loadRoles(Object.keys(definition)))
  if (isEmpty(granted)) return
  const missing = exceeding(granted, await actorHolds(await askGroups(actor.email), granted))
  if (!isEmpty(missing)) await refuseExceeding(missing, `Group '${group}'`, change, actor)
}

/**
 * A bundle import by a non-super-admin: every group whose grants the import changes (resolved
 * against the roles the import leaves) must clear the same rules as a single edit — not one they are
 * in, not a staff group, no `*`, nothing they do not hold. Removals and unchanged groups pass.
 */
export async function assertBundleWithinOwn(
  changed: ReadonlyArray<{ name: string; after: PermissionsByScope }>,
  actor?: AuditActorInput,
): Promise<void> {
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
  if (changed.length === 0) return
  // authz v2: a bundle carries v1 data; the v2 model is code and intents, never imported.
  if (isV2()) {
    for (const { name } of changed) await assertV2Change({ kind: 'group', name, after: null }, actor)
    return
  }
  if (await askSuperAdmin(actor.email)) return
  const groups = await askGroups(actor.email)
  for (const { name, after } of changed) {
    const change: RbacChange = { kind: 'group', name, after: null }
    if (groups.includes(name)) refuse('self_escalation', `Only a super admin may import a change to '${name}': you are a member of it`, change, actor)
    if (isStaffGroup(name)) await refuseStaff(name, 'import a change to', change, actor)
    if (Object.values(after).some((p) => p.includes(EVERYTHING))) {
      refuse('grants_everything', `Only a super admin may import a group that grants '*' ('${name}')`, change, actor)
    }
    const missing = exceeding(after, await actorHolds(groups, after))
    if (!isEmpty(missing)) await refuseExceeding(missing, `Imported group '${name}'`, change, actor)
  }
}
