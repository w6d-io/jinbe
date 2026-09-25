import type { AuditEvent, AuditResult } from '../../services/audit-types.js'
import type { AuditEventType } from './catalog.js'
import type { AuditV1Input } from './emitter.js'

/**
 * Legacy `auditEventService.emit` → audit/v1 (AUD-2 dual-write).
 *
 * Takes the normalised rich event and, when the caller used the old `{type: 'x.y'}` form, that
 * type. A call site that knows its catalog key passes `v1Event` and skips the guessing.
 */

const BY_TYPE: Record<string, AuditEventType> = {
  'user.created': 'user.created',
  'user.updated': 'user.updated',
  'user.deleted': 'user.deleted',
  'user.organization_changed': 'org.member.updated',
  'user.recovery_email_sent': 'user.recovery_sent',
  'user.groups_changed': 'rbac.user_groups.changed',
  'organization_user.groups_changed': 'rbac.user_groups.changed',
  'organization_user.created': 'org.member.added',
  'organization_user.updated': 'org.member.updated',
  'organization_user.membership_added': 'org.member.added',
  'organization_user.membership_removed': 'org.member.removed',
  'organization_user.grants_changed': 'org.grants.changed',
  'organization_user.grants_refused': 'org.grants.refused',
  'organization.created': 'org.created',
  'api_key.created': 'apikey.created',
  'api_key.revoked': 'apikey.revoked',
  'rbac.group_created': 'rbac.group.created',
  'rbac.group_updated': 'rbac.group.updated',
  'rbac.group_deleted': 'rbac.group.deleted',
  'rbac.service_created': 'site.created',
  'rbac.service_deleted': 'site.deleted',
  'rbac.service_config_updated': 'site.config_changed',
  'rbac.service_routes_updated': 'site.routes_changed',
  'roles.updated': 'site.roles_changed',
  'rbac.roles_selfrepaired': 'site.roles_repaired',
  'rbac.access_rule_created': 'gateway.rule.created',
  'rbac.access_rule_updated': 'gateway.rule.updated',
  'rbac.access_rule_deleted': 'gateway.rule.deleted',
  'rbac.org_service_mapping_set': 'org.services.changed',
  'rbac.org_service_mapping_deleted': 'org.services.changed',
  'rbac.org_admins_set': 'org.admins.changed',
}

/** Rich emits, keyed `category.verb` (and `source:` for the ones only the source tells apart). */
const BY_VERB: Record<string, AuditEventType> = {
  'access.deny': 'access.denied',
  'auth.revoke': 'auth.session.revoked',
  'auth.revoke_all': 'auth.session.revoked_all',
  'rbac.export': 'config.bundle.exported',
  'rbac.import': 'config.bundle.imported',
  'rbac.backup': 'config.bundle.backed_up',
  'rbac.restore': 'config.bundle.restored',
  'rbac.rollback': 'config.bundle.rolled_back',
  'system.export': 'audit.exported',
  'scim:create': 'user.created',
  'scim:update': 'user.updated',
  'scim:delete': 'user.deleted',
}

const RECERT: Record<string, AuditEventType> = {
  activate: 'recert.campaign.activated',
  close: 'recert.campaign.closed',
  approve: 'recert.item.decided',
  revoke: 'recert.item.decided',
  expire: 'recert.item.expired',
  flag: 'recert.item.expired',
}

function eventOf(rich: AuditEvent, legacyType?: string): AuditEventType {
  if (rich.v1Event) return rich.v1Event
  if (legacyType && BY_TYPE[legacyType]) return BY_TYPE[legacyType]
  if (rich.source === 'scim' && rich.kind === 'change') return BY_VERB[`scim:${rich.verb}`] ?? 'system.unmapped'
  if (rich.target.startsWith('recert:') && RECERT[rich.verb]) return RECERT[rich.verb]
  if (rich.target === 'auth-methods') return 'config.auth_methods.changed'
  return BY_VERB[`${rich.category}.${rich.verb}`] ?? 'system.unmapped'
}

const RESULT: Record<AuditResult, AuditV1Input['result']> = {
  ok: 'success', applied: 'success', denied: 'denied', failed: 'failure', error: 'error',
}

/** Where a target label is `type:id` (`group:finance`, `recert:c1:i2`), split it. */
function targetOf(rich: AuditEvent): AuditV1Input['target'] {
  if (rich.targetType || rich.targetId) {
    return { type: rich.targetType ?? 'resource', id: rich.targetId ?? null, email: rich.details?.targetEmail as string | undefined }
  }
  if (!rich.target || rich.target === '—') return null
  if (/^[A-Z]+ \//.test(rich.target)) return { type: 'route', id: rich.target }
  const colon = rich.target.indexOf(':')
  return colon > 0
    ? { type: rich.target.slice(0, colon), id: rich.target.slice(colon + 1) }
    : { type: 'resource', id: rich.target }
}

const ORG_TARGETS = new Set(['organization', 'org_service_map', 'org_admin_map'])

export function legacyToV1(rich: AuditEvent, legacyType?: string): AuditV1Input {
  const details = rich.details ?? {}
  const event = eventOf(rich, legacyType)
  const org = (details.organizationId as string | undefined)
    ?? (rich.targetType && ORG_TARGETS.has(rich.targetType) ? rich.targetId : undefined)

  // Free-form details never travel to v1 — only the names of what changed, or a before/after list.
  let changes: AuditV1Input['changes'] = rich.changes
    ? { resource: rich.changes.resource, id: rich.changes.id, added: rich.changes.added, removed: rich.changes.removed, changedKeys: rich.changes.changedKeys, summary: rich.changes.summary }
    : undefined
  if (!changes && Array.isArray(details.before) && Array.isArray(details.after)) {
    const before = new Set(details.before as string[])
    const after = new Set(details.after as string[])
    changes = { resource: rich.targetType ?? 'resource', added: [...after].filter((x) => !before.has(x)), removed: [...before].filter((x) => !after.has(x)) }
  }
  if (!changes && (event.endsWith('.updated') || event.endsWith('_changed'))) {
    const keys = Object.keys(details).filter((k) => !['organizationId', 'targetEmail', 'actorEmail'].includes(k))
    if (keys.length) changes = { resource: rich.targetType ?? 'resource', changedKeys: keys.sort() }
  }

  return {
    event,
    result: RESULT[rich.result] ?? 'success',
    reason: rich.reason ?? null,
    // Only the flag-derived tier overrides the catalog; the rest of the legacy severity was derived
    // from the result, which the catalog entry already encodes.
    severity: rich.severity === 'high' ? 'high' : undefined,
    flags: rich.changes?.flags ?? [],
    actor: {
      id: rich.actor?.id, email: rich.actor?.email, ip: rich.actor?.ip, ua: rich.actor?.ua, sessionId: rich.actor?.sessionId,
      // How a Kratos flow was authenticated; the webhook's allow-listed details carry it.
      ...(rich.source === 'kratos-webhook' ? { aal: details.aal as string | undefined, method: details.method as string | undefined } : {}),
    },
    target: targetOf(rich),
    org_id: org ?? null,
    site: rich.service ?? null,
    changes,
    source: rich.source === 'kratos-webhook' ? 'kratos' : rich.source === 'scim' ? 'scim' : 'jinbe',
    request_id: rich.requestId ?? null,
    legacy_type: event === 'system.unmapped' ? (legacyType ?? `${rich.category}.${rich.verb}`) : undefined,
  }
}
