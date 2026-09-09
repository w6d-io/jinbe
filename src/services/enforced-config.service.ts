import { readFile } from 'node:fs/promises'
import * as k8s from '@kubernetes/client-node'
import { stringify } from 'yaml'

/**
 * What actually decides, read from where it actually lives.
 *
 * The console used to serve rules from this service's own store, and the engines used to fetch them
 * from here at runtime. They no longer do: the edge reads a file the rule controller aggregates from
 * `Rule` resources, and the policy engine reads ConfigMaps a label brings it. Both are Git artifacts
 * synced by Argo. So an editor here would write somewhere nothing reads — which is worse than no
 * editor, because it looks like it worked.
 *
 * This answers the objects themselves, as text, and nothing else. Read-only is not a restriction on
 * a feature; it IS the feature: the source of truth is a repository, and a screen that let somebody
 * change it in place would be inviting a change the next sync silently reverts.
 */
export class EnforcedConfigUnavailableError extends Error {}

export interface EnforcedDocument {
  /** The Kubernetes kind, so the reader knows what they are looking at. */
  kind: string
  name: string
  namespace: string
  /** What this object decides, in the reader's terms rather than the cluster's. */
  decides: string
  /** The object as YAML, pruned of what the server adds. */
  yaml: string
  /**
   * The route table, read out of the document, when it holds one.
   *
   * Parsed here rather than in the browser: the shape is known here, and a console that parsed it
   * would be a second reader of the same document — free to disagree with the engine about what it
   * says, which is the one thing a screen showing "what is enforced" must never do.
   */
  routes?: EnforcedRoute[]
  /** What each role carries, when the document holds that instead. */
  roles?: EnforcedRole[]
}

export interface EnforcedRoute {
  method: string
  /** The path as called, rebuilt from the segments the engine matches on. */
  path: string
  /** `public` | `authenticated` | `authorized` — what the engine requires before forwarding. */
  class: string
  /** Only for `authorized`: the permission a caller must hold. */
  permission?: string
}

export interface EnforcedRole {
  role: string
  permissions: string[]
}

const RULE_GROUP = 'oathkeeper.ory.sh'
const RULE_VERSION = 'v1alpha1'
const RULE_PLURAL = 'rules'
/** The label the policy engine's loader selects on: only what it loads is shown. */
const POLICY_DATA_SELECTOR = 'openpolicyagent.org/data=opa'
const NAMESPACE_FILE = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'

/**
 * Everything the API server adds and nobody reviews. Left in, the YAML is unreadable and the reader
 * scrolls past the two lines that matter — which defeats the point of showing it at all.
 */
const SERVER_OWNED = ['managedFields', 'resourceVersion', 'uid', 'generation', 'creationTimestamp', 'selfLink']
const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'

function pruned(object: Record<string, unknown>, kind: string): Record<string, unknown> {
  const metadata = { ...((object.metadata as Record<string, unknown>) ?? {}) }
  for (const key of SERVER_OWNED) delete metadata[key]
  const annotations = { ...((metadata.annotations as Record<string, string>) ?? {}) }
  // A copy of the whole object, inside the object. Keeping it would show every document twice.
  delete annotations[LAST_APPLIED]
  if (Object.keys(annotations).length > 0) metadata.annotations = annotations
  else delete metadata.annotations

  const { status: _status, ...rest } = object
  return { apiVersion: object.apiVersion, kind: object.kind ?? kind, ...rest, metadata }
}

function asYaml(object: Record<string, unknown>, kind: string): string {
  // `literal` so the JSON documents held inside a ConfigMap stay readable as blocks rather than
  // becoming one escaped line. What is shown has to be what a reviewer would read in the repository.
  return stringify(pruned(object, kind), { blockQuote: 'literal', lineWidth: 0 })
}

async function ownNamespace(): Promise<string> {
  try {
    const declared = (await readFile(NAMESPACE_FILE, 'utf8')).trim()
    if (declared) return declared
  } catch {
    // Not running in a cluster.
  }
  return process.env.POD_NAMESPACE?.trim() || 'ory'
}

function client(): k8s.KubeConfig {
  const kc = new k8s.KubeConfig()
  // The pod's own credential, not a stored kubeconfig: this reads the namespace it runs in and
  // nothing else, and the grant that allows it is reviewable next to the deployment.
  kc.loadFromCluster()
  return kc
}

/**
 * The route table and the roles the policy engine decides from.
 *
 * Selected by the loader's own label, so this can never show a document the engine does not load —
 * a screen listing rules that are not enforced is the failure being fixed, not a nicer version of it.
 */
async function policyData(kc: k8s.KubeConfig, namespace: string): Promise<EnforcedDocument[]> {
  const core = kc.makeApiClient(k8s.CoreV1Api)
  const answer = await core.listNamespacedConfigMap({ namespace, labelSelector: POLICY_DATA_SELECTOR })
  return (answer.items ?? []).map((item) => ({
    kind: 'ConfigMap',
    name: item.metadata?.name ?? '(unnamed)',
    namespace,
    decides: describePolicyData(item),
    yaml: asYaml(item as unknown as Record<string, unknown>, 'ConfigMap'),
    routes: routesIn(item),
    roles: rolesIn(item),
  }))
}

/**
 * The route table as rows, or nothing.
 *
 * A malformed document costs the table and never the screen: the YAML is still shown, and somebody
 * looking at why the rows are missing is looking at the document that caused it.
 */
function routesIn(item: k8s.V1ConfigMap): EnforcedRoute[] | undefined {
  const held = item.data?.['permissions.json']
  if (!held) return undefined
  try {
    const parsed = JSON.parse(held) as {
      routes?: Record<string, Record<string, { segments?: string[]; class?: string; permission?: string }>>
    }
    const rows: EnforcedRoute[] = []
    for (const [method, byName] of Object.entries(parsed.routes ?? {})) {
      for (const definition of Object.values(byName ?? {})) {
        rows.push({
          method,
          path: `/${(definition.segments ?? []).join('/')}`,
          class: definition.class ?? 'unknown',
          ...(definition.permission ? { permission: definition.permission } : {}),
        })
      }
    }
    return rows.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
  } catch {
    return undefined
  }
}

/** What each role carries, so a permission on a route can be read back to the roles that hold it. */
function rolesIn(item: k8s.V1ConfigMap): EnforcedRole[] | undefined {
  const held = item.data?.['roles.json']
  if (!held) return undefined
  try {
    const parsed = JSON.parse(held) as Record<string, string[]>
    return Object.entries(parsed)
      .map(([role, permissions]) => ({ role, permissions: permissions ?? [] }))
      .sort((a, b) => a.role.localeCompare(b.role))
  } catch {
    return undefined
  }
}

/** Named by what a reader is looking for, not by the file that happens to hold it. */
function describePolicyData(item: k8s.V1ConfigMap): string {
  const keys = Object.keys(item.data ?? {})
  const parts: string[] = []
  if (keys.some((k) => k.startsWith('permissions'))) parts.push('which permission each route requires')
  if (keys.some((k) => k.startsWith('roles'))) parts.push('what each role carries')
  if (keys.some((k) => k.startsWith('grants'))) parts.push('who holds which role, per organisation')
  return parts.length > 0 ? parts.join(' · ') : 'policy data'
}

/** The edge: which host and method reach which upstream, and how the caller is authenticated. */
async function edgeRules(kc: k8s.KubeConfig, namespace: string): Promise<EnforcedDocument[]> {
  const custom = kc.makeApiClient(k8s.CustomObjectsApi)
  const answer = (await custom.listNamespacedCustomObject({
    group: RULE_GROUP,
    version: RULE_VERSION,
    namespace,
    plural: RULE_PLURAL,
  })) as { items?: Record<string, unknown>[] }
  return (answer.items ?? []).map((item) => ({
    kind: 'Rule',
    name: ((item.metadata as Record<string, unknown>)?.name as string) ?? '(unnamed)',
    namespace,
    decides: 'which requests reach this API, and how the caller is authenticated',
    yaml: asYaml(item, 'Rule'),
  }))
}

/**
 * Both halves, in the order a request meets them.
 *
 * A failure raises rather than answering a short list: "nothing is enforced" and "I could not read
 * what is enforced" are opposite facts, and only one of them should ever reach a screen.
 */
export async function enforcedConfiguration(): Promise<EnforcedDocument[]> {
  const namespace = await ownNamespace()
  try {
    const kc = client()
    const [edge, policy] = await Promise.all([edgeRules(kc, namespace), policyData(kc, namespace)])
    return [...edge, ...policy]
  } catch (err) {
    throw new EnforcedConfigUnavailableError(
      `Could not read the enforced configuration in namespace ${namespace}: ${(err as Error).message}`,
    )
  }
}
