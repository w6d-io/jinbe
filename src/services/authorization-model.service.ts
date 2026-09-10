import * as k8s from '@kubernetes/client-node'
import { groupsForSubjects } from './organisation-store.js'

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
/** Every organisation at once. A group naming it grants wherever the holder happens to be. */
const EVERY_ORGANISATION = '*'

/** `{ "<group>": { "<organisation>": ["<role>"] } }`, as `groups.json` holds it. */
type Groups = Record<string, Record<string, string[]>>

/**
 * The groups that grant in EVERY organisation.
 *
 * That is what global power is in this model — not a name. A group called `super_admins` that grants
 * nothing is not powerful, and a group called anything at all that grants under `*` is. Reading the
 * shape rather than the name is what stops a same-named but powerless group from waving somebody
 * through.
 */
export async function globalPowerGroups(): Promise<Set<string>> {
  const groups = await groupsModel()
  const powerful = new Set<string>()
  for (const [group, byOrganisation] of Object.entries(groups)) {
    const roles = byOrganisation?.[EVERY_ORGANISATION] ?? []
    if (roles.length > 0) powerful.add(group)
  }
  return powerful
}

/**
 * Whether this subject holds a group that grants in every organisation.
 *
 * Keyed on the immutable identity, never on an address: an address can be changed by its owner and
 * reused by somebody else, and this is the gate that decides who may hand out rights.
 */
export async function holdsGlobalPower(subjectId: string): Promise<boolean> {
  if (!subjectId) return false
  const [powerful, held] = await Promise.all([
    globalPowerGroups(),
    groupsForSubjects([subjectId]),
  ])
  return (held.get(subjectId) ?? []).some((group) => powerful.has(group))
}

async function groupsModel(): Promise<Groups> {
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
  for (const item of items) {
    const held = item.data?.['groups.json']
    if (!held) continue
    let parsed: Groups
    try {
      parsed = JSON.parse(held) as Groups
    } catch (err) {
      throw new AuthorizationModelUnavailableError(
        `${item.metadata?.name ?? 'a ConfigMap'}/groups.json is not a document: ${(err as Error).message}`,
      )
    }
    Object.assign(groups, parsed)
  }
  return groups
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
