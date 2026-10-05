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
  'user.second_factor_reset': ['auth', 'update', 'high'],
  // An administrator changed the sign-in address (POST /admin/users/:id/email); both addresses as HMACs.
  'user.email_changed': ['directory', 'update', 'high'],
  'user.verification_sent': ['directory', 'verify'],
  // The notice owed to the old address, recorded because jinbe cannot mail it (services/security-notice.ts).
  'user.address_notice_pending': ['directory', 'notify', 'warn'],
  // One bulk job (POST /admin/bulk/:op/execute); each item also has its own event.
  'bulk.executed': ['directory', 'execute', 'warn'],

  'org.created': ['directory', 'create'],
  'org.updated': ['directory', 'update'],
  'org.deleted': ['directory', 'delete', 'warn'],
  'org.member.added': ['directory', 'create'],
  'org.member.removed': ['directory', 'delete'],
  'org.member.updated': ['directory', 'update'],
  'org.grants.changed': ['authz', 'update'],
  // Public sign-up through a site (sites/signup) and the domains an org proves it owns.
  'org.domain.claimed': ['directory', 'create'],
  'org.domain.verified': ['directory', 'update', 'warn'],
  'org.domain.removed': ['directory', 'delete'],
  'org.grants.refused': ['authz', 'update', 'warn'],
  'org.admins.changed': ['authz', 'update'],
  // authz v2: org roles on the identity, and an org's owners named from the platform.
  'org.roles.changed': ['authz', 'update'],
  // RBAC owned by jinbe found edited outside jinbe, and converged back (bootstrap/owned-keys.ts).
  'rbac.owned_drift': ['authz', 'update', 'high'],
  // Break-glass (bootstrap/break-glass.ts): used and expired are the alert, tested is the drill.
  'rbac.break_glass_used': ['authz', 'update', 'high'],
  'rbac.break_glass_expired': ['authz', 'update', 'high'],
  'rbac.break_glass_tested': ['authz', 'verify'],
  'rbac.break_glass_refused': ['authz', 'update', 'high'],
  'org.roles.refused': ['authz', 'update', 'warn'],
  'org.owners.changed': ['authz', 'update', 'warn'],
  'org.services.changed': ['authz', 'update'],
  // Per-person direct grants (services/direct-grants.service.ts): given, taken away, run out, refused.
  'user.grant.granted': ['authz', 'create', 'warn'],
  'user.grant.revoked': ['authz', 'delete'],
  'user.grant.expired': ['authz', 'delete'],
  'user.grant.refused': ['authz', 'update', 'warn'],

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
  'site.imported': ['authz', 'update'],
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
  'site.address_changed': ['authz', 'update', 'warn'],
  'site.signup.joined': ['directory', 'create'],
  'site.signup.member_removed': ['directory', 'delete', 'warn'],
  // Ephemeral sites (sites/ephemeral.ts): an expiry set, cleared or moved, and the automatic pause.
  'site.ephemeral_set': ['authz', 'update'],
  'site.ephemeral_cleared': ['authz', 'update'],
  'site.ttl_renewed': ['authz', 'update'],
  'site.expired': ['authz', 'update', 'warn'],
  // Deletion requests (sites/deletion-requests.ts): asked (a key may), approved (the delete follows as
  // site.deleted), rejected.
  'site.deletion_requested': ['authz', 'create', 'warn'],
  'site.deletion_approved': ['authz', 'delete', 'warn'],
  'site.deletion_rejected': ['authz', 'update'],
  // The sync loop rewrote a Site CR that no longer matched the applied intent (sites/sync.ts).
  'site.synced': ['authz', 'restore'],
  'site.permissions_published': ['authz', 'update'],
  'site.permissions_removed': ['authz', 'delete'],

  // Zones: a wildcard domain the platform serves (one Ingress, maybe a certificate) — what is exposed.
  'zone.created': ['config', 'create', 'warn'],
  'zone.deleted': ['config', 'delete', 'high'],
  // Ingress ↔ Gateway, TLS: how the zone is reached and whether the WAF can be bypassed.
  'zone.updated': ['config', 'update', 'high'],

  'gateway.rule.created': ['authz', 'create'],
  'gateway.rule.updated': ['authz', 'update'],
  'gateway.rule.deleted': ['authz', 'delete'],
  'gateway.changed': ['config', 'update', 'high'],
  'gateway.rolled_back': ['config', 'restore', 'high'],

  'config.auth_methods.changed': ['config', 'update', 'high'],
  'config.second_factor.changed': ['config', 'update', 'high'],
  'config.sign_in_protection.changed': ['config', 'update', 'high'],
  'config.mcp.changed': ['config', 'update', 'high'],
  'config.bundle.exported': ['config', 'export'],
  'config.bundle.imported': ['config', 'import', 'warn'],
  'config.bundle.backed_up': ['config', 'backup'],
  'config.bundle.restored': ['config', 'restore', 'warn'],
  'config.bundle.rolled_back': ['config', 'restore', 'warn'],

  'apikey.created': ['secret', 'create'],
  'apikey.revoked': ['secret', 'delete'],
  'apikey.used': ['secret', 'use'],
  // Whether members may mint personal keys acting in the org.
  'apikey.policy_changed': ['secret', 'update', 'warn'],

  // Browser sign-in for MCP clients (src/oauth/): a client registered itself (DCR), a sign-in was
  // refused, consent given or denied, a sign-in revoked (one, all of a user's) or past its absolute life.
  'mcp.oauth.client_registered': ['secret', 'create'],
  'mcp.oauth.login_refused': ['auth', 'login', 'warn'],
  'mcp.oauth.consent_granted': ['secret', 'create', 'high'],
  'mcp.oauth.consent_denied': ['auth', 'login'],
  'mcp.oauth.revoked': ['secret', 'delete'],
  'mcp.oauth.revoked_all': ['secret', 'delete', 'warn'],
  'mcp.oauth.grant_expired': ['secret', 'delete'],
  // A person refreshed, through the link their assistant asked for, the second factor a key or a sign-in
  // stands on for protected actions (oauth/step-up-refresh.ts).
  'mcp.step_up.refreshed': ['auth', 'verify', 'warn'],

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
  // Gateway decisions, one event per subject and host per hour (audit/gateway/rollup.ts): what was
  // allowed, not only what was refused, without one line per request.
  'access.summary': ['access', 'access'],

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
