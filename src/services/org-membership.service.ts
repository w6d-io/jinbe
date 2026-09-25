import { env } from '../config/index.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { kratosService } from './kratos.service.js'
import {
  addMember,
  membersOf,
  organisationStoreConfigured,
  organisationsForSubject,
  removeMember,
} from './organisation-store.js'

/**
 * Membership of ONE organisation, added or taken away without touching any other.
 *
 * Somebody can belong to several organisations. The identity carries a primary one
 * (`organization_id`) and a list (`metadata_admin.organizations`); where this service owns
 * membership, the directory rows are the record every service asks about. Both are kept in step on
 * each change — the console reconciles the rows from the identity on its next edit, so changing the
 * rows alone would quietly be undone.
 *
 * Nothing here deletes an identity. Leaving an organisation is not leaving the platform: site access
 * comes from groups, and a person removed from one company keeps it, and keeps their other ones.
 */

/** Whether membership rows are kept here, and can be read and written. */
function ownsMembership(): boolean {
  return env.ORGANISATION_SOURCE === 'directory' && organisationStoreConfigured()
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

async function writeListed(identity: KratosIdentity, organisations: string[]): Promise<void> {
  const metadata = (identity.metadata_admin as Record<string, unknown> | null | undefined) ?? {}
  await kratosService.updateIdentity(identity.id, {
    metadata_admin: { ...metadata, organizations: organisations },
  })
}

/** Add the identity to one organisation. Idempotent; every other membership is left as it was. */
export async function joinOrganisation(identity: KratosIdentity, organisationId: string): Promise<void> {
  if (ownsMembership()) await addMember(organisationId, identity.id, 'member')

  const primary = primaryOf(identity)
  if (!primary) {
    await kratosService.patchIdentity(identity.id, [
      { op: 'replace', path: '/organization_id', value: organisationId },
    ])
  } else if (primary !== organisationId && !listedOn(identity).includes(organisationId)) {
    await writeListed(identity, [...listedOn(identity), organisationId])
  }
}

/**
 * Take the identity out of one organisation, and only that one.
 *
 * The directory row goes first: it is the record that authorises, so a failure after it leaves the
 * identity still naming the organisation — visible, and retried by the same call — rather than a
 * membership that still works while the screens say it was removed.
 *
 * When it was the primary organisation, the next one they still belong to takes its place; with
 * none left the primary is cleared, and the person stays.
 */
export async function leaveOrganisation(identity: KratosIdentity, organisationId: string): Promise<void> {
  if (ownsMembership()) await removeMember(organisationId, identity.id)

  const listed = listedOn(identity)
  const remaining = listed.filter((id) => id !== organisationId)

  if (primaryOf(identity) === organisationId) {
    const next = remaining[0] ?? null
    await kratosService.patchIdentity(identity.id, [
      { op: 'replace', path: '/organization_id', value: next },
    ])
    if (listed.length > 0) await writeListed(identity, remaining.filter((id) => id !== next))
  } else if (remaining.length !== listed.length) {
    await writeListed(identity, remaining)
  }
}

/**
 * Everybody who belongs to the organisation: those whose primary it is, and — where membership is
 * kept here — those whose rows name it as a second one. Each person once.
 */
export async function identitiesInOrganisation(
  organisationId: string,
  opts: { pageSize?: number; credentialsIdentifier?: string } = {},
): Promise<KratosIdentity[]> {
  const { identities } = await kratosService.listIdentitiesByOrganization(organisationId, opts)
  if (!ownsMembership()) return identities

  const seen = new Set(identities.map((identity) => identity.id))
  const others = [...new Set((await membersOf(organisationId)).map((m) => m.subjectId))].filter(
    (id) => !seen.has(id),
  )

  const wanted = opts.credentialsIdentifier?.toLowerCase()
  const extra: KratosIdentity[] = []
  for (const id of others) {
    // A row naming an identity that no longer exists is skipped, not reported as a person. Any other
    // failure is raised: a short list would say the rest are not members.
    const identity = await kratosService.getIdentity(id).catch((err: { statusCode?: number }) => {
      if (err?.statusCode === 404) return null
      throw err
    })
    if (!identity) continue
    if (wanted && String(identity.traits?.email ?? '').toLowerCase() !== wanted) continue
    extra.push(identity)
  }
  return [...identities, ...extra]
}
