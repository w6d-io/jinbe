import { env } from '../config/index.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { kratosService } from './kratos.service.js'
import {
  addMember,
  membershipRowsKept,
  membersOf,
  organisationStoreConfigured,
  organisationStoreMode,
  organisationsForSubject,
  removeMember,
} from './organisation-store.js'
import { join, leave, MEMBER } from './organisation-store/membership.js'

/**
 * Membership of ONE organisation, added or taken away without touching any other.
 *
 * Somebody can belong to several organisations. The identity carries a primary one
 * (`organization_id`) and a list (`metadata_admin.organizations`).
 *
 *   kratos store   — that IS the record. Joining and leaving are one locked write to the identity.
 *   postgres store — the rows are the record every service asks about, and the identity is kept in
 *                    step on each change, because the console reconciles the rows from it on its
 *                    next edit.
 *
 * Nothing here deletes an identity. Leaving an organisation is not leaving the platform: site access
 * comes from groups, and a person removed from one company keeps it, and keeps their other ones.
 */

/** Whether membership rows are kept beside the identity (the postgres store). */
function ownsMembership(): boolean {
  return membershipRowsKept()
}

function listedOn(identity: KratosIdentity): string[] {
  const metadata = identity.metadata_admin as Record<string, unknown> | null | undefined
  const listed = Array.isArray(metadata?.organizations) ? (metadata.organizations as unknown[]) : []
  return listed.filter((id): id is string => typeof id === 'string' && id.length > 0)
}

function primaryOf(identity: KratosIdentity): string | null {
  return ((identity as Record<string, unknown>).organization_id as string | null | undefined) ?? null
}

/** Every organisation the identity itself names: the primary one, then the list. */
export function organisationsOnIdentity(identity: KratosIdentity): string[] {
  const primary = primaryOf(identity)
  return [...new Set([...(primary ? [primary] : []), ...listedOn(identity)])]
}

/**
 * Whether this identity belongs to the organisation — as primary, as a listed one, or by a
 * directory row. Asking only the primary one is what hid somebody's second organisation from its
 * admin.
 */
export async function isMemberOf(identity: KratosIdentity, organisationId: string): Promise<boolean> {
  if (organisationsOnIdentity(identity).includes(organisationId)) return true
  if (!ownsMembership()) return false
  return (await organisationsForSubject(identity.id)).includes(organisationId)
}

/** Every organisation the identity belongs to: the ones it names, then any directory row. */
export async function organisationsOf(identity: KratosIdentity): Promise<string[]> {
  const named = organisationsOnIdentity(identity)
  if (!ownsMembership()) return named
  return [...new Set([...named, ...(await organisationsForSubject(identity.id))])]
}

/** Add the identity to one organisation. Idempotent; every other membership is left as it was. */
export async function joinOrganisation(identity: KratosIdentity, organisationId: string): Promise<void> {
  if (organisationStoreMode() === 'kratos') {
    await addMember(organisationId, identity.id, MEMBER)
    return
  }
  if (ownsMembership()) await addMember(organisationId, identity.id, MEMBER)
  await kratosService.updateAdminState(identity.id, (state) => join(state, organisationId))
}

/**
 * Take the identity out of one organisation, and only that one.
 *
 * With rows, the row goes first: it is the record that authorises, so a failure after it leaves the
 * identity still naming the organisation — visible, and retried by the same call — rather than a
 * membership that still works while the screens say it was removed.
 *
 * When it was the primary organisation, the next one they still belong to takes its place; with
 * none left the primary is cleared, and the person stays.
 */
export async function leaveOrganisation(identity: KratosIdentity, organisationId: string): Promise<void> {
  if (organisationStoreMode() === 'kratos') {
    await removeMember(organisationId, identity.id)
    return
  }
  if (ownsMembership()) await removeMember(organisationId, identity.id)
  await kratosService.updateAdminState(identity.id, (state) => leave(state, organisationId))
}

/**
 * Everybody who belongs to the organisation: those whose primary it is, and — where membership is
 * kept here — those whose rows name it as a second one. Each person once.
 */
export async function identitiesInOrganisation(
  organisationId: string,
  opts: { pageSize?: number; credentialsIdentifier?: string } = {},
): Promise<KratosIdentity[]> {
  const identities = await kratosService.listIdentitiesByOrganizationCached(organisationId, opts)
  // Kratos filters on the PRIMARY organisation only. The others are in the list (kratos store) or
  // the rows (postgres store); membersOf reads whichever holds them.
  if (env.ORGANISATION_SOURCE !== 'directory' || !organisationStoreConfigured()) return identities

  const seen = new Set(identities.map((identity) => identity.id))
  const others = [...new Set((await membersOf(organisationId)).map((m) => m.subjectId))].filter(
    (id) => !seen.has(id),
  )

  const wanted = opts.credentialsIdentifier?.toLowerCase()
  // One batched read for every secondary member (it used to be one Kratos call each, in sequence). A
  // row naming an identity that no longer exists is skipped, not reported as a person; any other
  // failure is raised: a short list would say the rest are not members.
  const found = others.length ? await kratosService.getIdentitiesByIds(others) : new Map<string, KratosIdentity>()
  const extra: KratosIdentity[] = []
  for (const id of others) {
    const identity = found.get(id)
    if (!identity) continue
    if (wanted && String(identity.traits?.email ?? '').toLowerCase() !== wanted) continue
    extra.push(identity)
  }
  return [...identities, ...extra]
}
