import { env } from '../config/index.js'
import { invalidateHome } from '../home/cache.js'
import { kratosService } from './kratos.service.js'
import * as kratos from './organisation-store/kratos.js'
import * as postgres from './organisation-store/postgres.js'
import {
  OrganisationStoreNotConfiguredError,
  type ApplyOutcome,
  type Organisation,
  type OrganisationChange,
  type OrganisationDeployment,
  type OrganisationMember,
  type OrganisationRecord,
} from './organisation-store/types.js'

export * from './organisation-store/types.js'

/**
 * Organisations as records this service owns: one interface, two stores.
 *
 *   kratos   — memberships (and org-scoped roles, and groups) on the Kratos identity, the registry
 *              (name, tenant, settings, entitlements) in Redis. The default without a database URL:
 *              one source of truth, nothing extra to run. See organisation-store/kratos.ts.
 *   postgres — rows in ORGANISATION_DATABASE_URL. Still works, no longer required.
 *
 * Every route, the policy bundle and the OPAL feeds go through the functions below and never ask
 * which store answered. What they get is the same shape from either.
 *
 * Every write here ends with the same fan-out: the directory cache is dropped (on every replica), the
 * home screens recount, and the engine is told to refetch (OPAL push) — so a membership change is
 * enforced now, not at the next poll.
 */

export type OrganisationStoreMode = 'kratos' | 'postgres'

export function organisationStoreMode(): OrganisationStoreMode {
  return env.ORGANISATION_STORE ?? (env.ORGANISATION_DATABASE_URL ? 'postgres' : 'kratos')
}

/** Whether this deployment has somewhere to keep organisations. Only a `postgres` store without a URL has not. */
export function organisationStoreConfigured(): boolean {
  return organisationStoreMode() === 'kratos' || postgres.postgresConfigured()
}

/**
 * Whether memberships are kept as ROWS beside the identity (the `postgres` store), so the screens
 * that edit the identity must also reconcile the rows. In the `kratos` store the identity is the
 * record and there is nothing to mirror.
 */
export function membershipRowsKept(): boolean {
  return env.ORGANISATION_SOURCE === 'directory' && organisationStoreMode() === 'postgres' && postgres.postgresConfigured()
}

/** The 503 every organisation route answers when there is nowhere to keep them. */
export function organisationStoreNotConfigured() {
  return {
    error: 'organisation_directory_unavailable',
    reason: 'not_configured',
    message: new OrganisationStoreNotConfiguredError().message,
  } as const
}

const store = () => (organisationStoreMode() === 'postgres' ? postgres : kratos)

/** After a committed write: never awaited, never able to fail the write it follows. */
function changed(reason: string, target: { type: string; id?: string }): void {
  try {
    kratosService.invalidateGroupsCache?.()
    invalidateHome(['people', 'attention'])
  } catch {
    // A cache that could not be dropped expires on its own TTL.
  }
  import('./rbac.service.js')
    .then(({ rbacService }) =>
      rbacService.invalidateBundle(`organisation.${reason}`, target, undefined, undefined, { audit: false }),
    )
    .catch(() => {})
}

async function write<T>(reason: string, target: { type: string; id?: string }, run: () => Promise<T>): Promise<T> {
  const result = await run()
  changed(reason, target)
  return result
}

// ─── Reads ───

export const organisationsForSubject = (subjectId: string): Promise<string[]> => store().organisationsForSubject(subjectId)
export const membershipsForSubjects = (subjectIds: readonly string[]): Promise<Map<string, string[]>> =>
  store().membershipsForSubjects(subjectIds)
export const groupsForSubjects = (subjectIds: readonly string[]): Promise<Map<string, string[]>> =>
  store().groupsForSubjects(subjectIds)
export const allGroupMemberships = (): Promise<Map<string, string[]>> => store().allGroupMemberships()
export const membersOfGroup = (groupName: string): Promise<string[]> => store().membersOfGroup(groupName)
export const membersOf = (organisationId: string): Promise<OrganisationMember[]> => store().membersOf(organisationId)
export const allOrganisations = (): Promise<Organisation[]> => store().allOrganisations()
export const organisationsById = (ids: readonly string[]): Promise<Organisation[]> => store().organisationsById(ids)
export const deploymentsOf = (organisationId: string): Promise<OrganisationDeployment[]> => store().deploymentsOf(organisationId)
export const allEntitlements = (): Promise<Map<string, string[]>> => store().allEntitlements()

// ─── Groups (the group editor notifies for itself) ───

export const addToGroup = (subjectId: string, groupName: string, createdBy?: string): Promise<void> =>
  write('group_member_added', { type: 'user', id: subjectId }, () => store().addToGroup(subjectId, groupName, createdBy))
export const removeFromGroup = (subjectId: string, groupName: string): Promise<void> =>
  write('group_member_removed', { type: 'user', id: subjectId }, () => store().removeFromGroup(subjectId, groupName))
export const applyGroupChange = (
  subjectId: string,
  revoked: readonly string[],
  granted: readonly string[],
  createdBy?: string,
): Promise<void> => store().applyGroupChange(subjectId, revoked, granted, createdBy)
export const forgetGroupsOf = (subjectId: string): Promise<void> => store().forgetGroupsOf(subjectId)

/**
 * Make somebody's groups exactly this set, in whichever store holds them — for imports and the
 * migration between stores, not for the group editor (which gates every change and notifies itself).
 */
export async function setGroupsOf(subjectId: string, groups: readonly string[]): Promise<void> {
  const wanted = [...new Set(groups)].sort()
  await write('groups_set', { type: 'user', id: subjectId }, async () => {
    if (organisationStoreMode() === 'kratos') {
      await kratosService.updateAdminState(subjectId, (state) => ({
        ...state,
        metadataAdmin: { ...state.metadataAdmin, groups: wanted },
      }))
      return
    }
    const current = (await postgres.groupsForSubjects([subjectId])).get(subjectId) ?? []
    await postgres.applyGroupChange(
      subjectId,
      current.filter((g) => !wanted.includes(g)),
      wanted.filter((g) => !current.includes(g)),
      'import',
    )
  })
}

// ─── Organisations and memberships ───

export const createOrganisation = (input: { name: string; tenant: string; attributes?: Readonly<Record<string, unknown>> }) =>
  write('created', { type: 'organization' }, () => store().createOrganisation(input))
export const updateOrganisation = (id: string, change: OrganisationChange): Promise<Organisation> =>
  write('updated', { type: 'organization', id }, () => store().updateOrganisation(id, change))
export const deleteOrganisation = (id: string): Promise<void> =>
  write('deleted', { type: 'organization', id }, () => store().deleteOrganisation(id))
export const setDeployments = (id: string, deployments: readonly OrganisationDeployment[]): Promise<void> =>
  write('deployments_changed', { type: 'organization', id }, () => store().setDeployments(id, deployments))
export const applyOrganisations = (records: readonly OrganisationRecord[]): Promise<ApplyOutcome> =>
  write('imported', { type: 'organization' }, () => store().applyOrganisations(records))

export const addMember = (organisationId: string, subjectId: string, role: string): Promise<void> =>
  write('member_added', { type: 'organization', id: organisationId }, () => store().addMember(organisationId, subjectId, role))
export const removeMember = (organisationId: string, subjectId: string, role?: string): Promise<void> =>
  write('member_removed', { type: 'organization', id: organisationId }, () => store().removeMember(organisationId, subjectId, role))
export const removeMemberEverywhere = (subjectId: string): Promise<void> =>
  write('member_removed', { type: 'user', id: subjectId }, () => store().removeMemberEverywhere(subjectId))
export const setMemberships = (subjectId: string, organisationIds: readonly string[], role?: string): Promise<void> =>
  write('memberships_set', { type: 'user', id: subjectId }, () => store().setMemberships(subjectId, organisationIds, role))

/** Released between tests, and on shutdown. Only the `postgres` store holds a connection. */
export const closeOrganisationStore = (): Promise<void> => postgres.closeOrganisationStore()
