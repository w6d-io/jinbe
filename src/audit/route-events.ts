import type { FastifyReply, FastifyRequest } from 'fastify'
import type { AuditEventType } from './v1/catalog.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * Which audit/v1 event each mutating route of jinbe's published route table produces (CONTROL AU-2).
 *
 *   - `emit: 'handler'` — the handler or the service behind it emits, with the diff it alone knows.
 *   - `emit: 'route'`   — nothing downstream emits, so the onSend hook below does, once, from THIS
 *     table, after a 2xx. Writing the event from the same row the static check reads means the
 *     declaration and the emission cannot drift apart.
 *   - `exempt` — writes nothing that is audited (a preview, a dry run, a personal preference). The
 *     reason is part of the record: an exemption nobody can justify is a missing event.
 *
 * The AU-2 test builds the server and fails on a mutating route missing here, and on a row here that
 * no longer matches a route.
 */

export const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'] as const

type Audited = { event: AuditEventType | readonly AuditEventType[]; emit: 'handler' }
type RouteWritten = { event: AuditEventType; emit: 'route'; target: string }
export type RouteAudit = Audited | RouteWritten | { exempt: string }

const by = (event: Audited['event']): Audited => ({ event, emit: 'handler' })
const route = (event: AuditEventType, target: string): RouteWritten => ({ event, emit: 'route', target })
const exempt = (reason: string) => ({ exempt: reason })

import { GATEWAY_ROUTE_AUDIT } from '../gateway/audit.js'

export const WRITE_ROUTE_AUDIT: Record<string, RouteAudit> = {
  ...GATEWAY_ROUTE_AUDIT,
  // Authentication, directory, sessions
  'PUT /api/admin/auth/methods': by('config.auth_methods.changed'),
  'PUT /api/admin/settings/second-factor': by('config.second_factor.changed'),
  'PUT /api/admin/settings/sign-in-protection': by('config.sign_in_protection.changed'),
  'PUT /api/admin/settings/mcp': by('config.mcp.changed'),
  // Refusals are counted (jinbe_sign_in_guard_decisions_total), not audited: a flood of scripted
  // sign-ups would otherwise become a flood of audit rows. A sign-up that goes through is audited by
  // the after-hook above.
  'POST /api/webhooks/kratos/guard': exempt('judges a Kratos submit (bot check, sign-up policy, protected traits); jinbe stores nothing'),
  'POST /api/public/sign-in-protection/gate/self-service/:flow': exempt('a Kratos self-service submit passing through the sign-in gate; Kratos audits the flow, refusals are logged and counted'),
  'POST /api/admin/organizations': by('org.created'),
  'PATCH /api/admin/organizations/:id': by('org.updated'),
  'DELETE /api/admin/organizations/:id': by('org.deleted'),
  'POST /api/admin/users': by('user.created'),
  'PUT /api/admin/users/:id': by('user.updated'),
  'DELETE /api/admin/users/:id': by('user.deleted'),
  'PATCH /api/admin/users/:id/metadata': by('user.updated'),
  'PATCH /api/admin/users/:id/state': by('user.state_changed'),
  'PATCH /api/admin/users/:id/organization': by('org.member.updated'),
  'POST /api/admin/users/:id/recovery-email': by('user.recovery_sent'),
  'DELETE /api/admin/users/:id/sessions': by('auth.session.revoked_all'),
  'DELETE /api/admin/sessions/:sessionId': by('auth.session.revoked'),
  'PUT /api/admin/users/:email/groups': by('rbac.user_groups.changed'),
  'POST /api/webhooks/kratos': by(['auth.login.succeeded', 'auth.registration.succeeded', 'auth.password.changed', 'auth.profile.updated', 'auth.mfa.enrolled', 'auth.mfa.removed', 'auth.recovery.used', 'auth.verification.succeeded']),
  'POST /scim/v2/Users': by('user.created'),
  'PUT /scim/v2/Users/:id': by('user.updated'),
  'PATCH /scim/v2/Users/:id': by('user.updated'),
  'DELETE /scim/v2/Users/:id': by('user.deleted'),

  // Organisations
  'POST /api/organizations/:organizationId/users': by('org.member.added'),
  'PUT /api/organizations/:organizationId/users/:id': by('org.member.updated'),
  'DELETE /api/organizations/:organizationId/users/:id': by('org.member.removed'),
  'PUT /api/organizations/:organizationId/users/:id/membership': by(['org.member.added', 'org.member.removed']),
  'PUT /api/organizations/:organizationId/users/:id/grants': by(['org.grants.changed', 'org.grants.refused']),
  'POST /api/organizations/:organizationId/api-keys': by('apikey.created'),
  'DELETE /api/organizations/:organizationId/api-keys/:clientId': by('apikey.revoked'),
  'PUT /api/organizations/:organizationId/api-key-policy': by('apikey.policy_changed'),
  'POST /api/me/api-keys': by('apikey.created'),
  'DELETE /api/me/api-keys/:clientId': by('apikey.revoked'),
  'POST /api/mcp/token-info': exempt('introspects a token for auth-mcp; changes nothing (the calls made with it are audited with actor.act)'),
  'POST /api/mcp/personal-keys/exchange': by('apikey.used'),

  // RBAC and bundle
  'POST /api/admin/rbac/groups': by('rbac.group.created'),
  'PUT /api/admin/rbac/groups/:name': by('rbac.group.updated'),
  'DELETE /api/admin/rbac/groups/:name': by('rbac.group.deleted'),
  'PUT /api/admin/rbac/services/:name/roles': by('site.roles_changed'),
  'PUT /api/admin/rbac/services/:name/routes': by('site.routes_changed'),
  'PUT /api/admin/rbac/org-admin-map': by('org.admins.changed'),
  'PUT /api/admin/rbac/org-service-map': by('org.services.changed'),
  'DELETE /api/admin/rbac/org-service-map/:organizationId': by('org.services.changed'),
  'POST /api/admin/rbac/access-check': by('access.checked'),
  'POST /api/admin/rbac/bundle/import': by('config.bundle.imported'),
  'POST /api/admin/rbac/bundle/backups/now': by('config.bundle.backed_up'),
  'POST /api/admin/rbac/bundle/backups/restore': by('config.bundle.restored'),
  'POST /api/admin/rbac/bundle/history/:id/rollback': by('config.bundle.rolled_back'),

  // Recertification
  'POST /api/admin/recert/campaigns': by('recert.campaign.created'),
  'DELETE /api/admin/recert/campaigns/:id': by('recert.campaign.deleted'),
  'POST /api/admin/recert/campaigns/:id/activate': by('recert.campaign.activated'),
  'POST /api/admin/recert/campaigns/:id/close': by('recert.campaign.closed'),
  'POST /api/admin/recert/items/:campaignId/:itemId/decision': by('recert.item.decided'),

  'POST /api/admin/users/:id/login-link': by('user.login_link_sent'),
  'POST /api/admin/users/:id/email': by(['user.email_changed', 'user.address_notice_pending']),
  'POST /api/admin/users/:id/verification': by('user.verification_sent'),
  'POST /api/admin/bulk/sites.routes.upsert/plan': exempt('a dry run: judges the items, writes nothing but the plan (kept 1 h)'),
  'POST /api/admin/bulk/sites.routes.upsert/execute': by(['bulk.executed', 'site.draft_saved']),
  'POST /api/admin/bulk/users.invite/plan': exempt('a dry run: judges the items, writes nothing but the plan (kept 1 h)'),
  'POST /api/admin/bulk/users.invite/execute': by(['bulk.executed', 'user.created']),
  'POST /api/admin/bulk/users.verification/plan': exempt('a dry run: judges the items, writes nothing but the plan (kept 1 h)'),
  'POST /api/admin/bulk/users.verification/execute': by(['bulk.executed', 'user.verification_sent']),
  'POST /api/admin/bulk/groups.members.add/plan': exempt('a dry run: judges the items, writes nothing but the plan (kept 1 h)'),
  'POST /api/admin/bulk/groups.members.add/execute': by(['bulk.executed', 'rbac.user_groups.changed']),
  'POST /api/admin/users/:id/second-factors/reset': by('user.second_factor_reset'),

  // Sites (src/sites calls auditSite — audit/record.ts)
  'PUT /api/admin/sites/:name': by(['site.saved', 'site.ephemeral_set', 'site.ephemeral_cleared']),
  'DELETE /api/admin/sites/:name': by('site.deleted'),
  'PUT /api/admin/sites/:name/draft': by('site.draft_saved'),
  'DELETE /api/admin/sites/:name/draft': by('site.draft_discarded'),
  'POST /api/admin/sites/:name/apply': by('site.applied'),
  'POST /api/admin/sites/:name/rollback': by('site.rolled_back'),
  'POST /api/admin/sites/:name/pause': by('site.paused'),
  'POST /api/admin/sites/:name/resume': by('site.resumed'),
  'POST /api/admin/sites/:name/diff': exempt('compares a draft with the applied version; writes nothing'),
  'POST /api/admin/sites/:name/import/preview': exempt('proposes routes from an OpenAPI document; keeps only the uploaded bytes 24 h for the commit'),
  'POST /api/admin/sites/:name/import/commit': by('site.imported'),
  'POST /api/admin/sites/preview': exempt('renders an intent and runs the checks; writes nothing'),
  'POST /api/admin/sites/check-host': exempt('resolves a host against the zones; writes nothing'),
  'POST /api/admin/sites/zones': by('zone.created'),
  'DELETE /api/admin/sites/zones/:name': by('zone.deleted'),
  'PATCH /api/admin/sites/zones/:name': by('zone.updated'),
  'POST /api/admin/sites/zones/suggest': exempt('proposes the zone a host would need and probes its DNS; writes nothing'),
  'POST /api/admin/sites/match': exempt('asks which rule a request would hit; writes nothing'),
  'POST /api/admin/sites/render': exempt('renders a header template as the gateway would; writes nothing'),
  'POST /api/admin/sites/:name/verify': exempt('reads the rollout and sends anonymous GET/HEAD probes to the public URL; writes nothing (1 per site per 30 s)'),
  'POST /api/admin/sites/:name/drift/accept': route('site.drift_accepted', 'site'),
  'POST /api/admin/sites/:name/restore': route('site.restored', 'site'),
  'POST /api/admin/sites/:name/requests': route('site.apply_requested', 'site'),
  'POST /api/admin/sites/requests/:id/approve': route('site.request_approved', 'site'),
  'POST /api/admin/sites/requests/:id/reject': route('site.request_rejected', 'site'),
  'POST /api/admin/sites/:name/ttl': by('site.ttl_renewed'),
  'POST /api/admin/sites/:name/deletion-requests': by('site.deletion_requested'),
  'POST /api/admin/sites/deletion-requests/:id/approve': by(['site.deletion_approved', 'site.deleted']),
  'POST /api/admin/sites/deletion-requests/:id/reject': by('site.deletion_rejected'),
  'PUT /api/admin/sites/:name/logo': route('site.logo_changed', 'site'),
  'DELETE /api/admin/sites/:name/logo': route('site.logo_removed', 'site'),
  'POST /api/admin/sites/migration/preview': exempt('converts the live rules into proposed sites for review; writes nothing'),
  'POST /api/admin/sites/migration/parity': exempt('replays the probe corpus against both rule sets; only computes a report'),
  'POST /api/admin/sites/migration/dualrun': route('site.migration_changed', 'site'),
  'POST /api/admin/sites/migration/cutover': route('site.migration_changed', 'site'),
  'POST /api/admin/sites/migration/rollback': route('site.migration_changed', 'site'),

  // The audit API itself
  'POST /api/audit/exports': by('audit.exported'),
  'POST /api/audit/saved-queries': exempt('a saved filter is a view preference, not a change to anything audited'),
  'DELETE /api/audit/saved-queries/:id': exempt('a saved filter is a view preference, not a change to anything audited'),
}

/**
 * onSend: one audit/v1 event for a successful write whose row says `emit: 'route'`. Never alters the
 * reply and never throws — the response is already decided.
 */
export async function auditRouteWrite(request: FastifyRequest, reply: FastifyReply, payload: unknown): Promise<unknown> {
  if (reply.statusCode < 200 || reply.statusCode >= 300) return payload
  const entry = WRITE_ROUTE_AUDIT[`${request.method} ${request.routeOptions?.url ?? ''}`]
  if (!entry || !('emit' in entry) || entry.emit !== 'route') return payload

  const actor = auditActor(request)
  const params = (request.params ?? {}) as Record<string, string | undefined>
  const targetId = params.id ?? null
  try {
    auditEventService.emit({
      category: 'service',
      kind: 'change',
      verb: entry.event.split('.').at(-1) ?? 'change',
      target: `${entry.target}:${targetId ?? '—'}`,
      targetType: entry.target,
      ...(targetId ? { targetId } : {}),
      result: 'applied',
      actor: { id: actor.id, email: actor.email, ip: actor.ip, ua: actor.ua, sessionId: actor.sessionId, ...(actor.act ? { act: actor.act } : {}) },
      requestId: actor.requestId,
      method: request.method,
      path: (request.url || '').split('?')[0],
      statusCode: reply.statusCode,
      source: 'jinbe-api',
      v1Event: entry.event,
    }).catch(() => {})
  } catch {
    // A failed audit write is counted by the emitter; the reply is already on its way.
  }
  return payload
}
