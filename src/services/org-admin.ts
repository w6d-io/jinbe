import type { FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { callerOrganisations } from './caller-organisations.js'
import { membersOf, organisationStoreConfigured } from './organisation-store.js'
import { redisRbacRepository } from './redis-rbac.repository.js'

/**
 * What administering one organisation gives, and nothing else: managing its people and its API keys
 * (the same set as `org_management_permission` in opal-policies org.rego, minus users:assign_group).
 *
 * Deliberately not `*`, not a service permission and not `users:assign_group`. Handing out a group
 * is a grant of rights: an org admin does that through the org-grant routes, where OPA's `can_grant`
 * bounds it to their own org and to what they hold — the site-wide group routes still refuse.
 */
export const ORG_ADMIN_PERMISSIONS = ['org:manage_users', 'org:manage_api_keys', 'users:read', 'users:create'] as const

/** The role a directory membership row carries for an organisation's admin. */
export const ORG_ADMIN_ROLE = 'org_admin'

/**
 * Whether the caller administers THIS organisation, or null when that could not be established.
 *
 * Two places name an org admin today, and both are honoured because both are live: the per-org
 * roster the gateway policy reads (`data.org_admin_map`, kept in Redis), and an `org_admin`
 * membership row in the directory. A roster entry counts only for a member of the organisation —
 * the same conjunction the policy applies — so a stale entry for somebody who left grants nothing.
 *
 * "Is not" and "cannot tell" stay apart: the gate turns the second into a 503 when nothing else
 * admits the caller, never into a quiet refusal.
 */
export async function administersOrganisation(
  request: FastifyRequest,
  organisationId: string,
): Promise<boolean | null> {
  const subject = request.userContext?.id
  const email = request.userContext?.email?.toLowerCase()
  if (!subject || !organisationId) return false

  try {
    if (env.ORGANISATION_SOURCE === 'directory' && organisationStoreConfigured()) {
      const members = await membersOf(organisationId)
      if (members.some((m) => m.subjectId === subject && m.role === ORG_ADMIN_ROLE)) return true
    }

    const roster = await redisRbacRepository.getOrgAdmins(organisationId)
    if (!email || !roster.some((entry) => entry.toLowerCase() === email)) return false

    return (await callerOrganisations(request)).includes(organisationId)
  } catch (err) {
    request.log.warn({ subject, organisationId, err }, '[org-admin] could not read who administers the organisation')
    return null
  }
}
