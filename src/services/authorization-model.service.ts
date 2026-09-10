import * as k8s from '@kubernetes/client-node'
import { groupsForSubjects } from './organisation-store.js'
import {
  EVERY_ORGANISATION,
  permits,
  resolveRights,
  type Groups,
  type HeldRights,
  type Roles,
} from './authorization-resolution.js'

export { resolveRights, type HeldRights }

/**
 * The model, read for the decisions THIS service makes about its own API.
 *
 * It reads the very ConfigMaps the bundle carries, so a decision taken here cannot disagree with one
 * the engine takes about somebody else's API. What it replaces asked an engine over the network for
 * `data.rbac.simulate` — a path that stopped existing when the model became `strada.authz`, so every
 * group assignment had been refused since, silently, with the console reporting a plain 403.
 *
 * WHY NOT ASK THE ENGINE: the engine that enforces runs inside the proxy pod and listens on its
 * loopback, so nothing outside that pod can reach it. That was the point of moving it. Reading the
 * same source is the way to stay consistent without re-opening it.
 *
 * NOT CACHED, deliberately. This gate decides who may hand out rights; a taken-away group has to
 * stop granting at once, not at the end of a window. The admin API is low-traffic and the read is one
 * list call.
 */
export class AuthorizationModelUnavailableError extends Error {}

const POLICY_DATA_SELECTOR = 'openpolicyagent.org/data=opa'
const NAMESPACE_FILE = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'


/** Administering the platform needs `admin.membership:write` to hand out a group. */
export const ASSIGN_MEMBERSHIP = 'admin.membership:write'

/**
 * What this subject holds ACROSS the platform — the roles their groups give under `*`.
 *
 * Administering the platform is not an act inside one organisation, so the organisation-scoped
 * entries are deliberately not read here: holding `admin.membership:write` in one company must not
 * let somebody hand out a group everywhere.
 *
 * What this replaced asked whether the subject held any group granting under `*`, whatever it
 * granted. That conflated "operator of one API everywhere" with "administrator of the platform", and
 * it was a predicate invented here rather than a permission the model declares. Now the model says
 * it, and the same rule that enforces a route decides it.
 */
export async function platformPermissions(subjectId: string): Promise<string[]> {
  return (await platformRightsOf(subjectId)).permissions
}

/**
 * What this subject holds across the platform: their groups, and what those give under `*`.
 *
 * The groups come from the store the artefact carries, which is the only place that says what is
 * ENFORCED. A screen showing groups from anywhere else shows something nobody decides against — and
 * an editing screen that saves one truth while displaying another turns a bad read into a bad write.
 *
 * Roles and permissions are the organisation-independent part only. Anything scoped to one company
 * cannot be stated in a list that is not about a company, and stating it anyway would read as a
 * right the holder has everywhere.
 */
export async function platformRightsOf(subjectId: string): Promise<HeldRights> {
  if (!subjectId) return { groups: [], roles: [], permissions: [] }
  const { documents, membership } = await readModelAndMembership(subjectId)
  const groups = membership.get(subjectId) ?? []

  const roles = new Set<string>()
  for (const group of groups) {
    for (const role of documents.groups[group]?.[EVERY_ORGANISATION] ?? []) roles.add(role)
  }
  const permissions = new Set<string>()
  for (const role of roles) {
    for (const permission of documents.roles[role] ?? []) permissions.add(permission)
  }
  return { groups: [...groups].sort(), roles: [...roles].sort(), permissions: [...permissions].sort() }
}

/**
 * Whether this subject may do something across the platform.
 *
 * Keyed on the immutable identity, never on an address: an address can be changed by its owner and
 * reused by somebody else, and this decides who may hand out rights.
 */
export async function holdsPlatformPermission(
  subjectId: string,
  required: string,
): Promise<boolean> {
  return permits(await platformPermissions(subjectId), required)
}

/**
 * What this subject holds IN one organisation.
 *
 * Resolved exactly as the policy resolves it, from the same two documents: a group gives roles in a
 * named organisation OR in every one, and `*` is a second source rather than a fallback for the
 * absence of the other — so both are read and unioned. Then each role carries its permissions.
 *
 * The organisation is its identifier, not a service name. What this replaces resolved the id to a
 * registered service name through Redis first, because the retired model keyed grants per service;
 * this one keys them per organisation, so there is nothing to translate and one store fewer to be up.
 */
export async function rightsOf(subjectId: string, organisationId: string): Promise<HeldRights> {
  if (!subjectId) return { groups: [], roles: [], permissions: [] }

  const { documents, membership } = await readModelAndMembership(subjectId)
  return resolveRights(documents, membership.get(subjectId) ?? [], organisationId)
}

/**
 * The groups this subject may hand out.
 *
 * Everything the model declares, or nothing: holding a group that grants in every organisation is
 * the only authority this model expresses over assignment, so there is no middle set to compute. A
 * picker offering more than the mutation would accept is worse than a short one — it turns a refusal
 * into a surprise.
 */
export async function assignableGroupsFor(subjectId: string): Promise<string[]> {
  if (!(await holdsPlatformPermission(subjectId, ASSIGN_MEMBERSHIP))) return []
  return declaredGroups()
}

/**
 * The model itself, for the screen that shows what a group grants before somebody hands it out.
 *
 * Read-only on purpose. This lives in Git and changes at a release, because a diff of it is the
 * only way anybody sees a permission change coming — so the console reports it rather than editing
 * it. What it replaces rendered a catalogue from a database, editable in place, with a column per
 * SERVICE: a shape this model does not have.
 */
export async function authorizationModel(): Promise<{ groups: Groups; roles: Roles }> {
  return policyDocuments()
}

/** Every group the model declares. Anything else confers nothing, wherever it is written. */
export async function declaredGroups(): Promise<string[]> {
  return Object.keys((await policyDocuments()).groups).sort()
}

/**
 * The model and this subject's memberships, read together.
 *
 * `Promise.all` rejects on the first failure and leaves a second one unobserved — and with no
 * `unhandledRejection` handler that ends the process, so a moment where BOTH the ConfigMaps and the
 * database are unreachable would kill the service instead of answering the 503 its callers build.
 * Settling both and then raising the first observes each one.
 */
async function readModelAndMembership(
  subjectId: string,
): Promise<{ documents: { groups: Groups; roles: Roles }; membership: Map<string, string[]> }> {
  const [documents, membership] = await Promise.allSettled([
    policyDocuments(),
    groupsForSubjects([subjectId]),
  ])
  if (documents.status === 'rejected') throw documents.reason
  if (membership.status === 'rejected') throw membership.reason
  return { documents: documents.value, membership: membership.value }
}

async function policyDocuments(): Promise<{ groups: Groups; roles: Roles }> {
  const namespace = await ownNamespace()
  let items: k8s.V1ConfigMap[]
  try {
    const kc = new k8s.KubeConfig()
    kc.loadFromCluster()
    const core = kc.makeApiClient(k8s.CoreV1Api)
    const answer = await core.listNamespacedConfigMap({ namespace, labelSelector: POLICY_DATA_SELECTOR })
    items = answer.items ?? []
  } catch (err) {
    // Raises rather than answering "no groups": "nobody is powerful" and "I could not tell" are
    // opposite facts, and the second one must never quietly authorize or quietly refuse.
    throw new AuthorizationModelUnavailableError(
      `Could not read the authorization model in ${namespace}: ${(err as Error).message}`,
    )
  }

  const groups: Groups = {}
  const roles: Roles = {}
  for (const item of items) {
    Object.assign(groups, parse<Groups>(item, 'groups.json') ?? {})
    Object.assign(roles, parse<Roles>(item, 'roles.json') ?? {})
  }
  return { groups, roles }
}

function parse<T>(item: k8s.V1ConfigMap, key: string): T | undefined {
  const held = item.data?.[key]
  if (!held) return undefined
  try {
    return JSON.parse(held) as T
  } catch (err) {
    // Raises rather than reading past it: a document that cannot be parsed is not an empty one, and
    // treating it as empty would quietly take away every right it granted.
    throw new AuthorizationModelUnavailableError(
      `${item.metadata?.name ?? 'a ConfigMap'}/${key} is not a document: ${(err as Error).message}`,
    )
  }
}

async function ownNamespace(): Promise<string> {
  const { readFile } = await import('node:fs/promises')
  try {
    return (await readFile(NAMESPACE_FILE, 'utf-8')).trim()
  } catch {
    throw new AuthorizationModelUnavailableError(
      'Not running in a cluster: the authorization model cannot be read.',
    )
  }
}

/**
 * What the write path needs to know about a set of groups, in ONE read of the model.
 *
 * The predicates this replaces each asked Redis a separate question per group, and for a group the
 * retired model never held they all answered "no": not a catalogue entry (refused with 400), not an
 * admin-power group (escalation gate skipped), not a system group (the target's second factor
 * skipped). Only the first of those three was audible.
 */
export type GroupFacts = {
  /** The model declares it. Anything else confers nothing, wherever it is written. */
  declared: boolean
  /** Confers a role in EVERY organisation — a platform grant rather than a tenant one. */
  everyOrganisation: boolean
  /** Confers no role in any organisation. */
  empty: boolean
}

/**
 * Read the model once and answer for every group at once.
 *
 * `everyOrganisation` is what replaces the retired model's "carries the `*` permission". The tree
 * has no `*` by design, so power can no longer be spotted by a wildcard; what distinguishes a
 * platform grant from a tenant one is the SCOPE it is given in. A group held in every organisation
 * at once is not an ordinary tenant role whatever it carries, so handing one out goes through the
 * escalation gate, the target's second factor and the actor's.
 *
 * An undeclared group confers nothing — that is a fact of this model, not a fallback. Adding one is
 * refused before these predicates are consulted; removing one takes nothing away.
 */
export async function groupFacts(names: readonly string[]): Promise<Map<string, GroupFacts>> {
  const { groups } = await policyDocuments()
  const facts = new Map<string, GroupFacts>()
  for (const name of names) {
    const definition = groups[name]
    if (!definition) {
      facts.set(name, { declared: false, everyOrganisation: false, empty: true })
      continue
    }
    const grants = Object.values(definition).filter((roles) => (roles ?? []).length > 0)
    facts.set(name, {
      declared: true,
      everyOrganisation: (definition[EVERY_ORGANISATION] ?? []).length > 0,
      empty: grants.length === 0,
    })
  }
  return facts
}
