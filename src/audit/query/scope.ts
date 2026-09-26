import type { FastifyReply, FastifyRequest } from 'fastify'
import { holds, manageableOrgs, rights } from '../../authz/opa.js'
import { enforcing } from '../../policy/declared-routes.js'

/**
 * Who may read which part of the audit trail (audit-tab.md §4.4, CONTROL C8).
 *
 *   - `audit:read` (or `admin:read`, which super_admin and platform admins hold) across the platform:
 *     every event, every org, platform events included.
 *   - an org admin: the events of the organisations they administer, and nothing else — the org
 *     filter is injected into the query HERE, never taken from the client.
 *   - anyone else: 403.
 *
 * Both asked of OPA (`rbac.user_info` for jinbe, `rbac.delegation.manageable_orgs`). "Holds nothing"
 * and "cannot tell" stay apart, as in the other gates: OPA unreachable is a 503, never a quiet
 * narrowing.
 */

export type AuditScope = { platform: true; orgs: [] } | { platform: false; orgs: string[] }

declare module 'fastify' {
  interface FastifyRequest {
    auditScope?: AuditScope
  }
}

const PLATFORM_READ = 'admin:read'

class ScopeUnknown extends Error {}

async function tell<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch {
    throw new ScopeUnknown()
  }
}

export async function resolveAuditScope(request: FastifyRequest, permission: string): Promise<AuditScope | null> {
  const email = request.userContext?.email
  if (!request.userContext?.id || !email || email === 'unknown') return null
  const held = (await tell(() => rights(email))).permissions
  if (holds(held, permission) || holds(held, PLATFORM_READ)) return { platform: true, orgs: [] }

  const administered = await tell(() => manageableOrgs(email))
  return { platform: false, orgs: [...new Set(administered)].sort() }
}

/**
 * The gate on every scoped audit route: resolves the caller's scope once and attaches it. Marked with
 * the permission it stands for, so the published route table reads it off the guard.
 */
export function requireAuditScope(permission = 'audit:read') {
  return enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
    const subject = request.userContext?.id
    if (!subject || subject === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }
    let scope: AuditScope | null
    try {
      scope = await resolveAuditScope(request, permission)
    } catch {
      request.log.warn({ subject }, '[audit] could not resolve what the caller may read — 503')
      return reply.status(503).send({ error: 'Service Unavailable', message: 'Unable to verify authorization. Please try again later.' })
    }
    if (!scope || (!scope.platform && scope.orgs.length === 0)) {
      return reply.status(403).send({ error: 'Forbidden', message: 'You can only see audit events for organisations you administer.' })
    }
    request.auditScope = scope
  }, permission)
}

/**
 * The orgs one query may read: a requested org must be inside the scope (else null → 403); no org
 * means the whole scope — every org for a platform reader (undefined), exactly theirs for an org admin.
 */
export function orgsFor(scope: AuditScope, requested?: string): string[] | undefined | null {
  if (scope.platform) return requested ? [requested] : undefined
  if (requested) return scope.orgs.includes(requested) ? [requested] : null
  return scope.orgs
}
