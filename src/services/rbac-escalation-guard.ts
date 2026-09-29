import { isSuperAdmin, memberOrgs, rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { redisRbacRepository, type GroupDefinition } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'

/**
 * No administrator rewrites the model in their own favour.
 *
 * `admin:write` lets somebody change groups, roles and route maps — but a change that touches what
 * THEY hold is one they could use to hand themselves more: widen a group they sit in, add a
 * permission to a role one of their groups carries, lower what a route of that service asks, map
 * another service onto their own organisation. Only a super admin (a global role carrying `*`, asked
 * of OPA) may make those, and only a super admin may create anything that grants `*`.
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

function refuse(reason: string, message: string, change: RbacChange, actor: AuditActorInput): never {
  auditEventService.emit({
    category: 'rbac', kind: 'change', verb: 'update', target: targetOf(change),
    result: 'denied', reason, severity: 'warn',
    actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId },
    requestId: actor.requestId, source: 'jinbe-api',
  }).catch(() => {})
  throw Object.assign(new Error(message), { statusCode: 403, code: reason })
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

/** Throws unless `actor` may make `change` (see the module comment). */
export async function assertNoSelfEscalation(change: RbacChange, actor?: AuditActorInput): Promise<void> {
  if (!actor?.id || !actor.email) {
    throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
  }
  const email = actor.email

  let superAdmin: boolean
  try {
    superAdmin = await isSuperAdmin(email)
  } catch (err) {
    unavailable(err)
  }
  if (superAdmin) return

  let groups: string[]
  try {
    groups = (await rights(email)).groups
  } catch (err) {
    unavailable(err)
  }

  switch (change.kind) {
    case 'group':
      if (groups.includes(change.name)) {
        refuse('self_escalation', `Only a super admin may change '${change.name}': you are a member of it`, change, actor)
      }
      if (change.after && (await grantsEverything(change.after))) {
        refuse('grants_everything', `Only a super admin may make a group that grants '*'`, change, actor)
      }
      return
    case 'roles':
      if (Object.values(change.roles).some((permissions) => permissions.includes(EVERYTHING))) {
        refuse('grants_everything', `Only a super admin may give a role '*'`, change, actor)
      }
      if (await groupsReach(groups, change.service)) {
        refuse('self_escalation', `Only a super admin may change the roles of '${change.service}': a group you are in holds one`, change, actor)
      }
      return
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
