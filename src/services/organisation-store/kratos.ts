import { DERIVED_MAX_AGE_MS, type ReadOptions } from '../../cache/swr.js'
import { KratosApiError, kratosService, type IdentityBinding } from '../kratos.service.js'
import * as registry from './registry.js'
import { join, leave, MEMBER, organisationsOn, setAll, setRoles } from './membership.js'
import {
  OrganisationInUseError,
  OrganisationNotFoundError,
  type ApplyOutcome,
  type OrganisationMember,
  type OrganisationRecord,
} from './types.js'

/**
 * The `kratos` organisation store: one source of truth per fact.
 *
 *   who belongs where, in what role, in which groups — the Kratos identity (see ./membership.ts),
 *     which is also what the OPAL bindings OPA decides with are read from;
 *   what an organisation is and which applications it has — the Redis registry (./registry.ts).
 *
 * Nothing is written twice. A question about ONE person reads that identity fresh; a question about
 * everybody (members of an organisation, the policy bundle) reads the one directory walk the
 * bindings feed already makes, so there is no second full read to fall out of step with it.
 */

export const {
  allOrganisations,
  organisationsById,
  createOrganisation,
  updateOrganisation,
  deploymentsOf,
  setDeployments,
  allEntitlements,
} = registry

async function identity(subjectId: string) {
  try {
    return await kratosService.getIdentity(subjectId)
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) return null
    throw err
  }
}

function stateOf(held: NonNullable<Awaited<ReturnType<typeof identity>>>) {
  const raw = held.metadata_admin
  return {
    organizationId: ((held as Record<string, unknown>).organization_id as string | null | undefined) ?? null,
    metadataAdmin: raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {},
  }
}

/**
 * How old a directory snapshot may be (the shared kratos.directory cache, dropped on every identity
 * write this service makes). Anything that decides — the policy bundle, a write's pre-image, "does
 * anybody still belong" — reads at the same bound as the OPAL bindings; a screen reads at the bound
 * of the other derived views.
 */
const DECIDES: ReadOptions = { maxAgeMs: 5_000 }
const SHOWS: ReadOptions = { maxAgeMs: DERIVED_MAX_AGE_MS }

async function bindingsById(opts: ReadOptions): Promise<Map<string, IdentityBinding>> {
  const bindings = await kratosService.getAllIdentitiesWithBindings(opts)
  return new Map([...bindings.values()].map((b) => [b.id, b]))
}

const orgsOfBinding = (b: IdentityBinding) =>
  [...new Set([...(b.primaryOrganization ? [b.primaryOrganization] : []), ...b.organizations])]

/**
 * A subject that no longer exists belongs to nothing; any other failure is raised, never "none".
 * Asked on every scoped request, so it reads the shared kratos.identity cache — which every
 * membership write drops, on every replica, before it returns.
 */
export async function organisationsForSubject(subjectId: string): Promise<string[]> {
  if (!subjectId) return []
  try {
    // Scopes what the caller may see (callerOrganisations → audit, directory): never older than the
    // 5 s bound OPA's own membership data has. A change made straight in Kratos shows within that.
    return organisationsOn(stateOf(await kratosService.getIdentityCached(subjectId, { maxAgeMs: 5000 })))
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 404) return []
    throw err
  }
}

export async function membershipsForSubjects(subjectIds: readonly string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>()
  if (subjectIds.length === 0) return out
  const byId = await bindingsById(SHOWS)
  for (const id of subjectIds) {
    const b = byId.get(id)
    const orgs = b ? orgsOfBinding(b) : []
    if (orgs.length > 0) out.set(id, orgs)
  }
  return out
}

/**
 * Groups as written on each identity. For a handful of subjects — the gate that decides a group
 * change reads ONE — each identity is read fresh, so the pre-image of a change is never a cached
 * copy. A page reads the directory walk. A subject with no group is absent, as in every store.
 */
export async function groupsForSubjects(subjectIds: readonly string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>()
  if (subjectIds.length === 0) return out
  if (subjectIds.length <= 5) {
    for (const id of subjectIds) {
      const held = await identity(id)
      const groups = held ? (stateOf(held).metadataAdmin.groups as unknown) : undefined
      const valid = Array.isArray(groups) ? groups.filter((g): g is string => typeof g === 'string').sort() : []
      if (valid.length > 0) out.set(id, valid)
    }
    return out
  }
  const byId = await bindingsById(DECIDES)
  for (const id of subjectIds) {
    const groups = byId.get(id)?.groups ?? []
    if (groups.length > 0) out.set(id, [...groups].sort())
  }
  return out
}

/** Everybody's groups, keyed by subject — the same walk the OPAL bindings are built from. */
export async function allGroupMemberships(): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>()
  for (const b of [...(await bindingsById(DECIDES)).values()].sort((x, y) => x.id.localeCompare(y.id))) {
    if (b.groups.length > 0) out.set(b.id, [...b.groups].sort())
  }
  return out
}

export async function membersOfGroup(groupName: string): Promise<string[]> {
  return [...(await bindingsById(SHOWS)).values()]
    .filter((b) => b.groups.includes(groupName))
    .map((b) => b.id)
    .sort()
}

async function writeGroups(subjectId: string, change: (groups: string[]) => string[]): Promise<void> {
  await kratosService.updateAdminState(subjectId, (state) => {
    const current = Array.isArray(state.metadataAdmin.groups) ? (state.metadataAdmin.groups as string[]) : []
    return { ...state, metadataAdmin: { ...state.metadataAdmin, groups: change(current) } }
  })
}

export async function addToGroup(subjectId: string, groupName: string): Promise<void> {
  await writeGroups(subjectId, (groups) => [...new Set([...groups, groupName])])
}

export async function removeFromGroup(subjectId: string, groupName: string): Promise<void> {
  await writeGroups(subjectId, (groups) => groups.filter((g) => g !== groupName))
}

/**
 * Nothing to do: in this store the groups ARE metadata_admin.groups, which the group editor writes
 * itself (KratosService.updateUserGroups). Writing them here too would be the second copy this store
 * exists to remove.
 */
export async function applyGroupChange(): Promise<void> {}

/** The identity is gone, and its metadata with it. */
export async function forgetGroupsOf(): Promise<void> {}

export async function membersOf(organisationId: string, opts: ReadOptions = SHOWS): Promise<OrganisationMember[]> {
  const out: OrganisationMember[] = []
  for (const b of await bindingsById(opts).then((m) => [...m.values()])) {
    if (!orgsOfBinding(b).includes(organisationId)) continue
    out.push({ subjectId: b.id, role: MEMBER })
    for (const role of b.organizationRoles[organisationId] ?? []) out.push({ subjectId: b.id, role })
  }
  return out.sort((a, b) => a.subjectId.localeCompare(b.subjectId) || a.role.localeCompare(b.role))
}

/** Refuses an organisation the registry does not hold: a membership pointing at nothing explains nothing. */
async function assertHeld(organisationId: string): Promise<void> {
  if (!(await registry.organisationHeld(organisationId))) throw new OrganisationNotFoundError(organisationId)
}

export async function addMember(organisationId: string, subjectId: string, role: string): Promise<void> {
  if (!(await organisationsForSubject(subjectId)).includes(organisationId)) await assertHeld(organisationId)
  await kratosService.updateAdminState(subjectId, (state) => join(state, organisationId, role))
}

export async function removeMember(organisationId: string, subjectId: string, role?: string): Promise<void> {
  await kratosService.updateAdminState(subjectId, (state) => leave(state, organisationId, role))
}

export async function removeMemberEverywhere(subjectId: string): Promise<void> {
  await kratosService.updateAdminState(subjectId, (state) => setAll(state, []))
}

export async function setMemberships(subjectId: string, organisationIds: readonly string[], role = MEMBER): Promise<void> {
  const wanted = organisationIds.filter((id, i) => organisationIds.indexOf(id) === i)
  // Only what is being ADDED must be held: somebody may already belong to an organisation that
  // predates the registry, and editing their other memberships must not fail on it.
  const current = await organisationsForSubject(subjectId)
  const added = wanted.filter((id) => !current.includes(id))
  const held = await registry.organisationsById(added)
  const missing = added.find((id) => !held.some((o) => o.id === id))
  if (missing) throw new OrganisationNotFoundError(missing)
  await kratosService.updateAdminState(subjectId, (state) => setAll(state, wanted, role))
}

/** Deletes the record once nobody belongs to it; otherwise refuses with how many still do. */
export async function deleteOrganisation(organisationId: string): Promise<void> {
  const members = new Set((await membersOf(organisationId, DECIDES)).map((m) => m.subjectId))
  if (members.size > 0) throw new OrganisationInUseError(organisationId, members.size)
  await registry.deleteOrganisation(organisationId)
}

/**
 * Write a set of organisations. Every write is keyed on the id the source already had, so it is
 * replayable: running it twice changes nothing, running it after a failure completes it. There is no
 * transaction across Redis and Kratos — what a failure leaves is a prefix of the input, and the rerun
 * finishes it. Deployments and members of a named organisation are REPLACED; nothing absent from the
 * input is deleted.
 */
export async function applyOrganisations(records: readonly OrganisationRecord[]): Promise<ApplyOutcome> {
  let deployments = 0
  let members = 0
  for (const record of records) {
    await registry.putOrganisation({ id: record.id, name: record.name, tenant: record.tenant, attributes: record.attributes ?? {} })
    if (record.deployments) {
      await registry.setDeployments(record.id, record.deployments)
      deployments += record.deployments.length
    }
    if (record.members) {
      const wanted = new Map<string, string[]>()
      for (const m of record.members) wanted.set(m.subjectId, [...(wanted.get(m.subjectId) ?? []), m.role])
      for (const current of new Set((await membersOf(record.id, DECIDES)).map((m) => m.subjectId))) {
        if (!wanted.has(current)) await removeMember(record.id, current)
      }
      for (const [subjectId, roles] of wanted) {
        await kratosService.updateAdminState(subjectId, (state) => setRoles(join(state, record.id), record.id, roles))
        members += roles.length
      }
    }
  }
  return { organisations: records.length, deployments, members }
}
