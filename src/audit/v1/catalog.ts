/**
 * The audit/v1 event catalog (docs/research/audit-tab.md §4.2).
 *
 * An event key is a stable name a query can rely on for years: never rename one, add a new one.
 * Each key fixes its category (a Loki label, so a short closed list) and its action.
 */

export const AUDIT_CATEGORIES = [
  'auth', 'directory', 'authz', 'config', 'secret', 'infra', 'review', 'access', 'audit', 'system',
] as const
export type AuditCategoryV1 = (typeof AUDIT_CATEGORIES)[number]

type Entry = readonly [AuditCategoryV1, string, ('info' | 'warn' | 'high')?]

export const AUDIT_EVENTS = {
  'auth.login.succeeded': ['auth', 'login'],
  'auth.login.failed': ['auth', 'login', 'warn'],
  'auth.mfa.enrolled': ['auth', 'update'],
  'auth.mfa.removed': ['auth', 'update', 'high'],
  'auth.password.changed': ['auth', 'update'],
  'auth.profile.updated': ['auth', 'update'],
  'auth.registration.succeeded': ['auth', 'create'],
  'auth.recovery.used': ['auth', 'recover', 'warn'],
  'auth.verification.succeeded': ['auth', 'verify'],
  'auth.session.revoked': ['auth', 'revoke'],
  'auth.session.revoked_all': ['auth', 'revoke'],
  'auth.logout': ['auth', 'logout'],

  'user.created': ['directory', 'create'],
  'user.updated': ['directory', 'update'],
  'user.deleted': ['directory', 'delete', 'warn'],
  'user.state_changed': ['directory', 'update'],
  'user.recovery_sent': ['directory', 'recover'],
  'user.login_link_sent': ['directory', 'recover', 'warn'],

  'org.created': ['directory', 'create'],
  'org.updated': ['directory', 'update'],
  'org.deleted': ['directory', 'delete', 'warn'],
  'org.member.added': ['directory', 'create'],
  'org.member.removed': ['directory', 'delete'],
  'org.member.updated': ['directory', 'update'],
  'org.grants.changed': ['authz', 'update'],
  'org.grants.refused': ['authz', 'update', 'warn'],
  'org.admins.changed': ['authz', 'update'],
  'org.services.changed': ['authz', 'update'],

  'rbac.group.created': ['authz', 'create'],
  'rbac.group.updated': ['authz', 'update'],
  'rbac.group.deleted': ['authz', 'delete'],
  'rbac.user_groups.changed': ['authz', 'update'],

  'site.created': ['authz', 'create'],
  'site.deleted': ['authz', 'delete', 'warn'],
  'site.config_changed': ['authz', 'update'],
  'site.routes_changed': ['authz', 'update'],
  'site.roles_changed': ['authz', 'update'],
  'site.roles_repaired': ['authz', 'update', 'warn'],
  // The Site lifecycle (sites module): a draft is work in progress, a save is a version, an apply
  // is what reaches the gateway.
  'site.draft_saved': ['authz', 'update'],
  'site.draft_discarded': ['authz', 'delete'],
  'site.saved': ['authz', 'update'],
  'site.applied': ['authz', 'apply', 'warn'],
  'site.rolled_back': ['authz', 'restore', 'warn'],
  'site.paused': ['authz', 'update', 'warn'],
  'site.resumed': ['authz', 'update'],
  'site.drift_accepted': ['authz', 'update', 'warn'],
  'site.restored': ['authz', 'restore', 'warn'],
  'site.apply_requested': ['authz', 'create'],
  'site.request_approved': ['authz', 'apply', 'warn'],
  'site.request_rejected': ['authz', 'update'],
  'site.logo_changed': ['authz', 'update'],
  'site.logo_removed': ['authz', 'delete'],
  'site.migration_changed': ['authz', 'apply', 'warn'],

  // Zones: a wildcard domain the platform serves (one Ingress, maybe a certificate) — what is exposed.
  'zone.created': ['config', 'create', 'warn'],
  'zone.deleted': ['config', 'delete', 'high'],

  'gateway.rule.created': ['authz', 'create'],
  'gateway.rule.updated': ['authz', 'update'],
  'gateway.rule.deleted': ['authz', 'delete'],
  'gateway.changed': ['config', 'update', 'high'],
  'gateway.rolled_back': ['config', 'restore', 'high'],

  'config.auth_methods.changed': ['config', 'update', 'high'],
  'config.bundle.exported': ['config', 'export'],
  'config.bundle.imported': ['config', 'import', 'warn'],
  'config.bundle.backed_up': ['config', 'backup'],
  'config.bundle.restored': ['config', 'restore', 'warn'],
  'config.bundle.rolled_back': ['config', 'restore', 'warn'],

  'apikey.created': ['secret', 'create'],
  'apikey.revoked': ['secret', 'delete'],
  'apikey.used': ['secret', 'use'],

  'infra.cluster.created': ['infra', 'create'],
  'infra.cluster.updated': ['infra', 'update'],
  'infra.cluster.deleted': ['infra', 'delete', 'warn'],
  'infra.cluster.verified': ['infra', 'verify'],
  'infra.database.created': ['infra', 'create'],
  'infra.database.updated': ['infra', 'update'],
  'infra.database.deleted': ['infra', 'delete', 'warn'],
  'infra.database_api.created': ['infra', 'create'],
  'infra.database_api.updated': ['infra', 'update'],
  'infra.database_api.deleted': ['infra', 'delete', 'warn'],
  'infra.backup.created': ['infra', 'create'],
  'infra.backup.deleted': ['infra', 'delete', 'warn'],
  'infra.backup.restored': ['infra', 'restore', 'warn'],
  'infra.backup_item.created': ['infra', 'create'],
  'infra.backup_item.updated': ['infra', 'update'],
  'infra.backup_item.deleted': ['infra', 'delete', 'warn'],
  'infra.job.started': ['infra', 'execute'],

  'recert.campaign.created': ['review', 'create'],
  'recert.campaign.activated': ['review', 'update'],
  'recert.campaign.closed': ['review', 'update'],
  'recert.campaign.deleted': ['review', 'delete', 'warn'],
  'recert.item.decided': ['review', 'update'],
  'recert.item.expired': ['review', 'update'],

  'access.denied': ['access', 'access', 'warn'],
  'access.decision': ['access', 'access'],
  'access.checked': ['access', 'read'],

  'audit.exported': ['audit', 'export', 'warn'],
  'audit.queried': ['audit', 'read'],
  'audit.checkpoint': ['audit', 'checkpoint'],

  // A legacy emit the map below does not know yet. Written rather than dropped — losing an audit
  // event is worse than filing one badly — and counted, so the gap is visible and gets a real key.
  'system.unmapped': ['system', 'unknown', 'warn'],
} as const satisfies Record<string, Entry>

export type AuditEventType = keyof typeof AUDIT_EVENTS
export const AUDIT_EVENT_TYPES = Object.keys(AUDIT_EVENTS) as [AuditEventType, ...AuditEventType[]]

export function catalogEntry(event: AuditEventType): { category: AuditCategoryV1; action: string; severity: 'info' | 'warn' | 'high' } {
  const [category, action, severity] = AUDIT_EVENTS[event] as Entry
  return { category, action, severity: severity ?? 'info' }
}
