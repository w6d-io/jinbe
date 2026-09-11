import { readFile } from 'node:fs/promises'
import * as k8s from '@kubernetes/client-node'
import { stringify } from 'yaml'
import { kratosService } from './kratos.service.js'
import {
  allGroupMemberships,
  organisationsById,
  organisationStoreConfigured,
} from './organisation-store.js'
import { declaredRoutes } from '../policy/declared-routes.js'

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
  /** For a `Rule`: what it matches, and which route table will decide it. */
  edge?: EnforcedEdge
  /**
   * Who holds which role, and where — the last link of the chain a reader is actually following.
   *
   * A screen that stops at "this route needs `context:read`" answers half the question. The half
   * that matters to whoever is asking is "so who can call it, and how would somebody else be
   * allowed to" — and that is a person, in an organisation, holding a role.
   */
  grants?: EnforcedGrant[]
}

export interface EnforcedGrant {
  /** The immutable identity the grant is keyed on. Never an address: one changes, the other does not. */
  subject: string
  /** The address that identity carries today, for a reader. Absent when it cannot be resolved. */
  email?: string
  /**
   * What this subject holds, per organisation — and THROUGH WHICH GROUP.
   *
   * The group is the hop that explains the rest: without it a reader sees that somebody holds a role
   * and has no way to know why, nor what to change to take it away. `*` as the organisation is the
   * model's own way of saying "every one".
   */
  held: {
    organisation: string
    organisationName?: string
    roles: string[]
    viaGroups: string[]
  }[]
}

/**
 * What a `Rule` lets in, where it sends it, and — the part that is not in the rule — which route
 * table the engine will consult for it.
 *
 * That last one is read from the authorizer's payload rather than from the rule, because that is
 * where it lives: the payload names a service, and the policy selects the table by that name. A rule
 * carries no such field, so a reader looking only at the rule cannot tell which table decides it.
 */
export interface EnforcedEdge {
  methods: string[]
  url: string
  upstream?: string
  /** How the caller is identified before anything is decided. */
  authenticators: string[]
  authorizer: string
  /** The service the payload names, i.e. the route table the engine looks up. */
  authorizesAs?: string
  /** Whether a LOADED policy document declares routes for that service. */
  tableDeclared?: boolean
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
/** The edge's own configuration, where the decision payload — and so the table selection — lives. */
const EDGE_CONFIG = 'oathkeeper-config'
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

  // Who is in a group, to join with what a group gives. Fail-soft on purpose and unlike the
  // documents: a directory that cannot answer costs the reader the last hop of the chain, while a
  // document that cannot be read means nobody knows what is enforced. Those are not the same
  // failure and must not have the same consequence.
  let memberships: Map<string, string[]> = new Map()
  if (organisationStoreConfigured()) {
    memberships = await allGroupMemberships().catch(() => new Map<string, string[]>())
  }

  return (answer.items ?? []).map((item) => ({
    kind: 'ConfigMap',
    name: item.metadata?.name ?? '(unnamed)',
    namespace,
    decides: describePolicyData(item),
    yaml: asYaml(item as unknown as Record<string, unknown>, 'ConfigMap'),
    routes: routesIn(item),
    roles: rolesIn(item),
    grants: grantsIn(item, memberships),
  }))
}

/**
 * Who holds what, read out of the document.
 *
 * Names are NOT resolved here — that is a directory read, and one failing directory must not cost
 * the answer to "what is enforced". They are added afterwards, per subject, and a subject nobody can
 * name is still shown by its identifier: a grant that cannot be attributed is more interesting than
 * one that can, not less.
 */
/**
 * Who holds which role, where, and through which group.
 *
 * Joined here rather than read from one file, because the two halves are owned by different people
 * on purpose: `groups.json` is the MODEL — what a group gives, per organisation — and changes at a
 * release by merge request; the memberships are the DIRECTORY — who is in a group — and change daily
 * from the console. A screen that showed only one of them would answer half the question.
 *
 * This used to read `grants.json`, a single file holding both. That file was retired when the model
 * split, and this kept reading it — so the last two hops of the chain silently disappeared from the
 * screen, which is how a route table and a role catalogue came to be shown with nobody holding
 * anything.
 */
function grantsIn(
  item: k8s.V1ConfigMap,
  memberships: Map<string, string[]>,
): EnforcedGrant[] | undefined {
  const declared = item.data?.['groups.json']
  if (!declared) return undefined

  let groups: Record<string, Record<string, string[]>>
  try {
    groups = JSON.parse(declared) as Record<string, Record<string, string[]>>
  } catch {
    return undefined
  }

  const bySubject = new Map<string, Map<string, { roles: Set<string>; groups: Set<string> }>>()
  for (const [subject, held] of memberships) {
    for (const group of held) {
      for (const [organisation, roles] of Object.entries(groups[group] ?? {})) {
        if (!roles?.length) continue
        const perOrganisation = bySubject.get(subject) ?? new Map()
        const entry = perOrganisation.get(organisation) ?? { roles: new Set(), groups: new Set() }
        for (const role of roles) entry.roles.add(role)
        entry.groups.add(group)
        perOrganisation.set(organisation, entry)
        bySubject.set(subject, perOrganisation)
      }
    }
  }

  return [...bySubject.entries()]
    .map(([subject, perOrganisation]) => ({
      subject,
      held: [...perOrganisation.entries()]
        .map(([organisation, entry]) => ({
          organisation,
          roles: [...entry.roles].sort(),
          viaGroups: [...entry.groups].sort(),
        }))
        .sort((a, b) => a.organisation.localeCompare(b.organisation)),
    }))
    .sort((a, b) => a.subject.localeCompare(b.subject))
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
  if (keys.some((k) => k.startsWith('groups'))) parts.push('what each group gives, per organisation')
  return parts.length > 0 ? parts.join(' · ') : 'policy data'
}

/** The edge: which host and method reach which upstream, and how the caller is authenticated. */
async function edgeRules(
  kc: k8s.KubeConfig,
  namespace: string,
  defaultPayloadService?: string,
): Promise<EnforcedDocument[]> {
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
    edge: edgeOf(item, defaultPayloadService),
  }))
}

/** The rule, read into the terms a reader asks in rather than the shape Oathkeeper stores. */
function edgeOf(item: Record<string, unknown>, defaultPayloadService?: string): EnforcedEdge {
  const spec = (item.spec as Record<string, unknown>) ?? {}
  const match = (spec.match as Record<string, unknown>) ?? {}
  const upstream = (spec.upstream as Record<string, unknown>) ?? {}
  const authorizer = (spec.authorizer as Record<string, unknown>) ?? {}
  const authenticators = (spec.authenticators as Record<string, unknown>[]) ?? []

  // A rule may carry its own payload; otherwise the engine uses the one configured globally. Reading
  // the rule alone would therefore answer the wrong table whenever the global one applies — which,
  // today, is every rule.
  const own = serviceInPayload(
    ((authorizer.config as Record<string, unknown>)?.payload as string) ?? undefined,
  )

  return {
    methods: (match.methods as string[]) ?? [],
    url: (match.url as string) ?? '',
    upstream: (upstream.url as string) ?? undefined,
    authenticators: authenticators.map((a) => (a.handler as string) ?? '(unnamed)'),
    authorizer: (authorizer.handler as string) ?? '(none)',
    authorizesAs: own ?? defaultPayloadService,
  }
}

/** The `service` a decision payload names. Absent rather than guessed when the shape is not that. */
function serviceInPayload(payload?: string): string | undefined {
  if (!payload) return undefined
  return /"service"\s*:\s*"([^"]+)"/.exec(payload)?.[1]
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
    // Which table a rule is decided against is configured on the ENGINE side, so it is read before
    // the rules and passed in. Fail-soft on purpose: an unreadable edge config costs the reader one
    // annotation, never the answer to "what is enforced" — the same trade `named` makes below.
    const defaultPayloadService = await configuredPayloadService(kc, namespace).catch(() => undefined)

    // `Promise.all` rejects on the first failure and leaves a second one unobserved; with no
    // `unhandledRejection` handler that ends the process, so a moment where BOTH reads fail would
    // kill the service instead of raising the error this catch turns into a 503.
    const [edge, policy] = await Promise.allSettled([
      edgeRules(kc, namespace, defaultPayloadService),
      policyData(kc, namespace),
    ])
    if (edge.status === 'rejected') throw edge.reason
    if (policy.status === 'rejected') throw policy.reason

    // This service's OWN table, alongside the ones the cluster holds. It is not a ConfigMap: it is
    // read off the guards this process attached, so it ships with the code that enforces it and a
    // deployment cannot end up with a table describing a different build.
    return await named(withTableCoverage(edge.value, [...policy.value, ownRouteTable(namespace)]))
  } catch (err) {
    throw new EnforcedConfigUnavailableError(
      `Could not read the enforced configuration in namespace ${namespace}: ${(err as Error).message}`,
    )
  }
}

/**
 * Say, per rule, whether the table it is decided against is actually loaded.
 *
 * This is the failure the screen exists to name: a rule can be perfectly formed, authorize against a
 * service, and that service declare no routes — in which case every call is refused for a reason
 * nothing on the rule shows.
 */
function withTableCoverage(
  edge: EnforcedDocument[],
  policy: EnforcedDocument[],
): EnforcedDocument[] {
  const declared = new Set(policy.filter((d) => d.routes && d.routes.length > 0).map((d) => d.name))
  const documents = [
    ...edge.map((document) =>
      document.edge?.authorizesAs
        ? { ...document, edge: { ...document.edge, tableDeclared: declared.has(document.edge.authorizesAs) } }
        : document,
    ),
    ...policy,
  ]
  return documents
}

/**
 * The service the engine's own authorizer payload names, from the edge configuration.
 *
 * Read rather than assumed: today every rule inherits this one value, so it is the single thing that
 * decides which route table applies to all of them.
 */
async function configuredPayloadService(
  kc: k8s.KubeConfig,
  namespace: string,
): Promise<string | undefined> {
  const core = kc.makeApiClient(k8s.CoreV1Api)
  // LISTED by name rather than read: the grant this pod holds on ConfigMaps is `list` and nothing
  // else, so a `get` is refused — and the fail-soft above would have turned that refusal into a
  // permanently missing annotation nobody would have questioned.
  const answer = await core.listNamespacedConfigMap({
    namespace,
    fieldSelector: `metadata.name=${EDGE_CONFIG}`,
  })
  const config = Object.values(answer.items?.[0]?.data ?? {}).join('\n')
  return serviceInPayload(config)
}

/**
 * Put a name on every subject and organisation a grant mentions.
 *
 * Separate from reading the documents, and failing separately: a directory or a membership store
 * that cannot answer costs the reader a name and never the answer to "what is enforced". An
 * identifier is worse to read and still true.
 */
async function named(documents: EnforcedDocument[]): Promise<EnforcedDocument[]> {
  const subjects = [...new Set(documents.flatMap((d) => (d.grants ?? []).map((g) => g.subject)))]
  const organisations = [
    ...new Set(documents.flatMap((d) => (d.grants ?? []).flatMap((g) => g.held.map((h) => h.organisation)))),
  ]
  if (subjects.length === 0) return documents

  const [addresses, organisationNames] = await Promise.all([
    addressesFor(subjects),
    organisationNamesFor(organisations),
  ])

  return documents.map((document) =>
    document.grants
      ? {
          ...document,
          grants: document.grants.map((grant) => ({
            ...grant,
            ...(addresses.get(grant.subject) ? { email: addresses.get(grant.subject) } : {}),
            held: grant.held.map((held) => ({
              ...held,
              ...(organisationNames.get(held.organisation)
                ? { organisationName: organisationNames.get(held.organisation) }
                : {}),
            })),
          })),
        }
      : document,
  )
}

async function addressesFor(subjects: readonly string[]): Promise<Map<string, string>> {
  const found = new Map<string, string>()
  // One at a time and tolerant of each: a subject present in a grant and absent from the directory
  // is exactly the case worth seeing, and it must not take the other names with it.
  await Promise.all(
    subjects.map(async (subject) => {
      try {
        const identity = await kratosService.getIdentity(subject)
        const email = (identity?.traits as { email?: string } | undefined)?.email
        if (email) found.set(subject, email)
      } catch {
        // Left unnamed on purpose.
      }
    }),
  )
  return found
}

async function organisationNamesFor(ids: readonly string[]): Promise<Map<string, string>> {
  if (!organisationStoreConfigured() || ids.length === 0) return new Map()
  try {
    return new Map((await organisationsById(ids)).map((o) => [o.id, o.name]))
  } catch {
    return new Map()
  }
}

/**
 * What THIS service requires on its own routes.
 *
 * jinbe does not sit behind the gateway — it is the thing an operator reaches to repair a broken
 * authorization state, and a component used to fix authorization must not be gated by authorization
 * it serves. So nothing looks this table up to decide. It is published because the console could
 * not otherwise say what `admin:read` opens, and because the rows that used to say it were seeded
 * into a store nothing reads, in a vocabulary the model no longer knows.
 */
function ownRouteTable(namespace: string): EnforcedDocument {
  const routes = declaredRoutes().filter((r) => r.class === 'authorized')
  return {
    kind: 'ConfigMap',
    name: 'jinbe',
    namespace,
    decides: 'What this service requires on its own routes. Enforced in-process, not at the edge.',
    yaml: '',
    routes: routes.map((r) => ({
      method: r.method,
      path: r.path,
      class: r.class,
      ...(r.permission ? { permission: r.permission } : {}),
    })),
  }
}
