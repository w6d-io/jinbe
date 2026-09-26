import type { FastifyReply, FastifyRequest } from 'fastify'
import type { AuditEventType } from './v1/catalog.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * Which audit/v1 event each mutating route of jinbe's published route table produces (CONTROL AU-2).
 *
 *   - `emit: 'handler'` — the handler or the service behind it emits, with the diff it alone knows.
 *   - `emit: 'route'`   — nothing downstream emits, so the onSend hook below does, once, from THIS
 *     table, after a 2xx. The infrastructure CRUD had no audit at all; writing the event from the
 *     same row the static check reads means the declaration and the emission cannot drift apart.
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
  'POST /api/admin/organizations': by('org.created'),
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
  'PUT /api/organizations/:organizationId/users/:id/groups': by('rbac.user_groups.changed'),
  'PUT /api/organizations/:organizationId/users/:id/grants': by(['org.grants.changed', 'org.grants.refused']),
  'POST /api/organizations/:organizationId/api-keys': by('apikey.created'),
  'DELETE /api/organizations/:organizationId/api-keys/:clientId': by('apikey.revoked'),

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
  'POST /api/admin/rbac/services/:name/routes/import/preview': exempt('computes the routes an OpenAPI document would produce; stores nothing'),
  'POST /api/admin/rbac/health-check': exempt('liveness answer for the console; reads and writes nothing'),

  // Recertification
  'POST /api/admin/recert/campaigns': by('recert.campaign.created'),
  'DELETE /api/admin/recert/campaigns/:id': by('recert.campaign.deleted'),
  'POST /api/admin/recert/campaigns/:id/activate': by('recert.campaign.activated'),
  'POST /api/admin/recert/campaigns/:id/close': by('recert.campaign.closed'),
  'POST /api/admin/recert/items/:campaignId/:itemId/decision': by('recert.item.decided'),

  'POST /api/admin/users/:id/login-link': by('user.login_link_sent'),

  // Sites (src/sites calls auditSite — audit/record.ts)
  'PUT /api/admin/sites/:name': by('site.saved'),
  'DELETE /api/admin/sites/:name': by('site.deleted'),
  'PUT /api/admin/sites/:name/draft': by('site.draft_saved'),
  'DELETE /api/admin/sites/:name/draft': by('site.draft_discarded'),
  'POST /api/admin/sites/:name/apply': by('site.applied'),
  'POST /api/admin/sites/:name/rollback': by('site.rolled_back'),
  'POST /api/admin/sites/:name/pause': by('site.paused'),
  'POST /api/admin/sites/:name/resume': by('site.resumed'),
  'POST /api/admin/sites/:name/diff': exempt('compares a draft with the applied version; writes nothing'),
  'POST /api/admin/sites/preview': exempt('renders an intent and runs the checks; writes nothing'),
  'POST /api/admin/sites/check-host': exempt('resolves a host against the zones; writes nothing'),
  'POST /api/admin/sites/match': exempt('asks which rule a request would hit; writes nothing'),
  'POST /api/admin/sites/render': exempt('renders a header template as the gateway would; writes nothing'),
  'POST /api/admin/sites/:name/drift/accept': route('site.drift_accepted', 'site'),
  'POST /api/admin/sites/:name/restore': route('site.restored', 'site'),
  'POST /api/admin/sites/:name/requests': route('site.apply_requested', 'site'),
  'POST /api/admin/sites/requests/:id/approve': route('site.request_approved', 'site'),
  'POST /api/admin/sites/requests/:id/reject': route('site.request_rejected', 'site'),
  'PUT /api/admin/sites/:name/logo': route('site.logo_changed', 'site'),
  'DELETE /api/admin/sites/:name/logo': route('site.logo_removed', 'site'),
  'POST /api/admin/sites/migration/preview': exempt('converts the live rules into proposed sites for review; writes nothing'),
  'POST /api/admin/sites/migration/parity': exempt('replays the probe corpus against both rule sets; only computes a report'),
  'POST /api/admin/sites/migration/dualrun': route('site.migration_changed', 'site'),
  'POST /api/admin/sites/migration/cutover': route('site.migration_changed', 'site'),
  'POST /api/admin/sites/migration/rollback': route('site.migration_changed', 'site'),

  // Infrastructure — no emit downstream, written from this table
  'POST /api/clusters': route('infra.cluster.created', 'cluster'),
  'PUT /api/clusters/:id': route('infra.cluster.updated', 'cluster'),
  'DELETE /api/clusters/:id': route('infra.cluster.deleted', 'cluster'),
  'POST /api/clusters/:id/verify': route('infra.cluster.verified', 'cluster'),
  'POST /api/clusters/verify': exempt('checks a kubeconfig that is not stored; nothing is saved or changed'),
  'POST /api/clusters/:id/databases': route('infra.database.created', 'database'),
  'POST /api/clusters/:id/backups': route('infra.backup.created', 'backup'),
  'POST /api/clusters/:clusterId/jobs': route('infra.job.started', 'job'),
  'PUT /api/databases/:id': route('infra.database.updated', 'database'),
  'DELETE /api/databases/:id': route('infra.database.deleted', 'database'),
  'POST /api/databases/:id/api': route('infra.database_api.created', 'database_api'),
  'PUT /api/database-apis/:id': route('infra.database_api.updated', 'database_api'),
  'DELETE /api/database-apis/:id': route('infra.database_api.deleted', 'database_api'),
  'DELETE /api/backups/:id': route('infra.backup.deleted', 'backup'),
  'POST /api/backups/:id/items': route('infra.backup_item.created', 'backup_item'),
  'PUT /api/backup-items/:id': route('infra.backup_item.updated', 'backup_item'),
  'DELETE /api/backup-items/:id': route('infra.backup_item.deleted', 'backup_item'),

  // Machines and the audit API itself
  'POST /api/opa/status': exempt('OPA status report from the engine (machine, no business change)'),
  'POST /api/audit/exports': by('audit.exported'),
  'POST /api/audit/saved-queries': exempt('a saved filter is a view preference, not a change to anything audited'),
  'DELETE /api/audit/saved-queries/:id': exempt('a saved filter is a view preference, not a change to anything audited'),
}

/** The id a create answered with (`{id}`, `{data: {id}}`, a job's name), or null. */
function createdId(payload: unknown): string | null {
  if (typeof payload !== 'string' || !payload.startsWith('{')) return null
  try {
    const body = JSON.parse(payload) as Record<string, unknown>
    const inner = (body.data && typeof body.data === 'object' ? body.data : body) as Record<string, unknown>
    const id = inner.id ?? inner._id ?? inner.jobName ?? inner.name
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
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
  // A create acts on what it made (the path id is its parent); anything else on the path's id.
  const creates = /\.(created|started)$/.test(entry.event)
  const targetId = creates ? createdId(payload) : params.id ?? null
  const parentId = creates ? params.id ?? params.clusterId : undefined
  try {
    auditEventService.emit({
      category: 'service',
      kind: 'change',
      verb: entry.event.split('.').at(-1) ?? 'change',
      target: `${entry.target}:${targetId ?? '—'}`,
      targetType: entry.target,
      ...(targetId ? { targetId } : {}),
      result: 'applied',
      actor: { id: actor.id, email: actor.email, ip: actor.ip, ua: actor.ua, sessionId: actor.sessionId },
      requestId: actor.requestId,
      method: request.method,
      path: (request.url || '').split('?')[0],
      statusCode: reply.statusCode,
      // The parent a child was created under (a database under a cluster) — ids only.
      ...(parentId ? { details: { parentId } } : {}),
      source: 'jinbe-api',
      v1Event: entry.event,
    }).catch(() => {})
  } catch {
    // A failed audit write is counted by the emitter; the reply is already on its way.
  }
  return payload
}
