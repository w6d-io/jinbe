import { createHash } from 'node:crypto'
import { createGzip } from 'node:zlib'
import * as k8s from '@kubernetes/client-node'
import { pack } from 'tar-stream'
import { allEntitlements, allGroupMemberships } from './organisation-store.js'

/**
 * Everything the authorization engine decides against, in one bundle it fetches for itself.
 *
 * Two kinds of fact, one artefact:
 *   - the MODEL — which permission each route requires, what each role carries, what each group
 *     gives. It ships as labelled ConfigMaps, each owned by whoever owns the thing it describes, and
 *     is read back here rather than re-declared: the API still owns its own route table.
 *   - the PEOPLE — which groups somebody is in, from the store that owns memberships.
 *
 * WHY ONE BUNDLE AND NOT TWO MECHANISMS: the engine used to take the model through a loader that
 * talks to the Kubernetes API and the people through a bundle. That works while the engine is a
 * deployment of its own, and stops working the moment it becomes a sidecar — every replica would
 * then need to watch the API server and hold a read grant of its own. Fetching one bundle over HTTP
 * needs neither.
 *
 * THE ROOTS COVER EVERYTHING THIS BUNDLE CARRIES — `ory` for the facts, and the package of every
 * rule it ships. A root governs data paths AND rule packages alike, so a bundle that declared only
 * the data root would be REFUSED whole, at every poll, the moment it also carried a rule: measured,
 * and the engine went on answering from the copy it had while reporting nothing but a 200 on
 * /health.
 *
 * Owning a root is also owning what is missing from it: a bundle that owned `ory` while missing one
 * service's table would delete that table, and every route of that service would answer "no such
 * route" — a refusal indistinguishable from a missing right.
 *
 * Which is why a ConfigMap that cannot be read RAISES. There is no partial bundle: the engine treats
 * what it receives as the whole truth for the root it owns.
 */
export class PolicyBundleUnavailableError extends Error {}

export interface PolicyBundle {
  /** The bundle itself, gzipped tar. */
  body: Buffer
  /** Content hash — the engine's bundle revision, and this response's ETag. */
  revision: string
}

const ROOT = 'ory'
/** The label the engine's own loader selects on; kept so the ConfigMaps need no second marker. */
const POLICY_DATA_SELECTOR = 'openpolicyagent.org/data=opa'
/**
 * The rules, selected by the loader's other label.
 *
 * They travel in the same bundle as the facts, and that is a transport decision rather than a
 * governance one: they still live in the repository and still change by merge request. What it buys
 * is that the engine needs no mounted file — a file mounted from a ConfigMap is read at startup and
 * stays stale after an edit, with the deployment reporting success, and one copy per replica makes
 * that worse rather than better.
 */
const POLICY_RULES_SELECTOR = 'openpolicyagent.org/policy=rego'
const NAMESPACE_FILE = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'
/** Where the memberships land. Not a ConfigMap, so it cannot collide with one. */
const MEMBERSHIP_KEY = 'membership'
/** Where the entitlements land — which applications each organisation has at all. */
const ENTITLEMENT_KEY = 'entitlements'

let cached: PolicyBundle | null = null

export async function policyBundle(): Promise<PolicyBundle> {
  const namespace = await ownNamespace()
  const [model, memberships, entitlements] = await Promise.all([
    modelFrom(namespace),
    allGroupMemberships(),
    allEntitlements(),
  ])

  for (const key of [MEMBERSHIP_KEY, ENTITLEMENT_KEY]) {
    if (!Object.prototype.hasOwnProperty.call(model, key)) continue
    // A ConfigMap under one of these names would silently overwrite what this bundle carries, or be
    // overwritten by it depending on order. Refused rather than resolved by luck.
    throw new PolicyBundleUnavailableError(
      `A ConfigMap named "${key}" collides with what this bundle carries under the same name.`,
    )
  }

  const sorted = (held: Map<string, string[]>) =>
    Object.fromEntries([...held.entries()].sort(([a], [b]) => a.localeCompare(b)))

  const data = {
    [ROOT]: {
      ...model,
      [MEMBERSHIP_KEY]: sorted(memberships),
      [ENTITLEMENT_KEY]: sorted(entitlements),
    },
  }

  const payload = JSON.stringify(data, null, 2)
  const rules = await rulesFrom(namespace)

  const roots = rootsFor(rules)

  // ONE revision, over everything the bundle CARRIES AND EVERYTHING IT ASSERTS — the roots included.
  // Two mistakes were made here in turn, and they are the same mistake. First the revision ignored
  // the rules, so a policy change went out under an unchanged identity. Then it ignored the roots,
  // and correcting how they are derived produced a genuinely different artefact under the identity
  // of the broken one: the engine answered 304 and kept refusing the bundle it already had. The
  // revision identifies the artefact, not a subset of its bytes.
  const revision = createHash('sha256')
    .update(payload)
    .update(rules.map((r) => `${r.name}\n${r.content}`).join('\n'))
    .update(roots.join(','))
    .digest('hex')
    .slice(0, 16)
  if (cached?.revision === revision) return cached

  const manifest = JSON.stringify({ revision, roots }, null, 2)
  cached = {
    body: await archive([
      { name: '.manifest', content: manifest },
      { name: 'data.json', content: payload },
      ...rules,
    ]),
    revision,
  }
  return cached
}

/**
 * What this bundle claims ownership of: the facts, plus the package of every rule it carries.
 *
 * Derived rather than listed, because a listed root is a second place to remember: a rule added in a
 * new package would be refused, and the refusal names the manifest rather than the rule. Read off
 * the modules instead, so the claim and the content cannot disagree.
 *
 * A root that sits under another is dropped — the engine refuses a manifest whose roots overlap, and
 * `ory` already covers `ory/anything`.
 */
function rootsFor(rules: { name: string; content: string }[]): string[] {
  const claimed = new Set([ROOT])
  for (const rule of rules) {
    claimed.add(packageOf(rule))
  }
  const roots = [...claimed].sort()
  return roots.filter((root) => !roots.some((other) => other !== root && root.startsWith(`${other}/`)))
}

/** The module's package, as a bundle root. Absent, the engine would refuse the whole bundle. */
function packageOf(rule: { name: string; content: string }): string {
  const declared = /^\s*package\s+([A-Za-z0-9_.]+)/m.exec(rule.content)
  if (!declared) {
    throw new PolicyBundleUnavailableError(`${rule.name} declares no package; refusing to publish it.`)
  }
  return declared[1].split('.').join('/')
}

/**
 * The rules, as `.rego` entries of the bundle.
 *
 * Absent is allowed here, unlike the model: a deployment can legitimately keep its rules on disk
 * while this is being adopted, and answering an empty list lets both arrangements coexist. What is
 * NOT allowed is a rule that cannot be read — see below.
 */
async function rulesFrom(namespace: string): Promise<{ name: string; content: string }[]> {
  let items: k8s.V1ConfigMap[]
  try {
    const kc = new k8s.KubeConfig()
    kc.loadFromCluster()
    const core = kc.makeApiClient(k8s.CoreV1Api)
    const answer = await core.listNamespacedConfigMap({ namespace, labelSelector: POLICY_RULES_SELECTOR })
    items = answer.items ?? []
  } catch (err) {
    // Not "no rules": the difference between "none declared" and "cannot tell" is the difference
    // between a deployment that keeps its rules on disk and one that is about to lose them.
    throw new PolicyBundleUnavailableError(
      `Could not read the policy ConfigMaps in ${namespace}: ${(err as Error).message}`,
    )
  }

  const rules: { name: string; content: string }[] = []
  for (const item of items) {
    const from = item.metadata?.name ?? 'unnamed'
    for (const [key, content] of Object.entries(item.data ?? {})) {
      if (!key.endsWith('.rego')) continue
      if (!content.trim()) {
        throw new PolicyBundleUnavailableError(`${from}/${key} is empty; refusing to publish it.`)
      }
      // Named after where it came from, so a conflict between two ConfigMaps is visible in the
      // bundle rather than resolved by whichever was read last.
      rules.push({ name: `${from}.${key}`, content })
    }
  }
  return rules.sort((a, b) => a.name.localeCompare(b.name))
}

/** Emptied between tests; nothing else may call it. */
export function forgetPolicyBundle(): void {
  cached = null
}

/**
 * The model, read from the ConfigMaps the engine's loader would have read.
 *
 * Shaped exactly as that loader shapes it — `data.<namespace-root>.<configmap>.<key>`, key suffix
 * included — because the policy addresses it that way and a bundle that reshaped it would be a
 * silent rewrite of every rule.
 */
async function modelFrom(namespace: string): Promise<Record<string, Record<string, unknown>>> {
  let items: k8s.V1ConfigMap[]
  try {
    const kc = new k8s.KubeConfig()
    kc.loadFromCluster()
    const core = kc.makeApiClient(k8s.CoreV1Api)
    const answer = await core.listNamespacedConfigMap({ namespace, labelSelector: POLICY_DATA_SELECTOR })
    items = answer.items ?? []
  } catch (err) {
    throw new PolicyBundleUnavailableError(
      `Could not read the policy ConfigMaps in ${namespace}: ${(err as Error).message}`,
    )
  }

  if (items.length === 0) {
    // An empty model is never a legitimate answer: it would take every route table with it.
    throw new PolicyBundleUnavailableError(
      `No ConfigMap in ${namespace} carries ${POLICY_DATA_SELECTOR}; refusing to publish an empty model.`,
    )
  }

  const model: Record<string, Record<string, unknown>> = {}
  for (const item of items) {
    const name = item.metadata?.name
    if (!name) continue
    const entries: Record<string, unknown> = {}
    for (const [key, raw] of Object.entries(item.data ?? {})) {
      try {
        entries[key] = JSON.parse(raw)
      } catch (err) {
        // One malformed document is the whole bundle's problem: publishing without it removes what
        // it granted, and the refusal that follows names a route rather than a broken file.
        throw new PolicyBundleUnavailableError(
          `${name}/${key} is not a document: ${(err as Error).message}`,
        )
      }
    }
    model[name] = entries
  }
  for (const [name, entries] of Object.entries(model)) {
    const table = entries['permissions.json']
    if (table) assertDecidable(name, table)
  }
  return model
}

/** One route of a service's table, as the generator emits it. */
interface RouteDefinition {
  segments: string[]
  class: string
  permission?: string
}

const ROUTE_CLASSES = new Set(['public', 'authenticated', 'authorized'])
const PLACEHOLDER = '{'

/**
 * Refuses a route table the policy could not decide against.
 *
 * TWO ROUTES OF EQUAL SPECIFICITY do not make the policy pick one, and do not make it refuse: the
 * winner is a complete rule, two winners make it produce two outputs, and evaluation FAILS. At the
 * edge the adapter turns anything that is neither a grant nor a refusal into a fault, so the caller
 * reads 500 on that route — measured. Caught here instead, it is a bundle that does not publish,
 * which the engine's readiness turns into a rollout that does not complete.
 *
 * The other two refusals are of the same kind: a class nobody implements, and an `authorized` route
 * naming no permission, both decide "no" for a reason no operator can read off the verdict.
 */
function assertDecidable(service: string, table: unknown): void {
  const routes = (table as { routes?: Record<string, Record<string, RouteDefinition>> }).routes
  if (!routes) return

  for (const [method, byName] of Object.entries(routes)) {
    for (const [name, definition] of Object.entries(byName)) {
      if (!Array.isArray(definition.segments)) {
        throw new PolicyBundleUnavailableError(
          `${service}: route ${method} ${name} declares no segments; refusing to publish it.`,
        )
      }
      if (!ROUTE_CLASSES.has(definition.class)) {
        throw new PolicyBundleUnavailableError(
          `${service}: route ${method} ${name} has class "${definition.class}", which no rule implements; refusing to publish it.`,
        )
      }
      if (definition.class === 'authorized' && !definition.permission) {
        throw new PolicyBundleUnavailableError(
          `${service}: route ${method} ${name} is authorized but names no permission; refusing to publish it.`,
        )
      }
    }

    const named = Object.entries(byName)
    for (let i = 0; i < named.length; i += 1) {
      for (let j = i + 1; j < named.length; j += 1) {
        const [leftName, left] = named[i]
        const [rightName, right] = named[j]
        if (!overlap(left, right)) continue
        if (literals(left) !== literals(right)) continue
        throw new PolicyBundleUnavailableError(
          `${service}: routes ${method} ${leftName} and ${rightName} match the same paths with equal specificity, ` +
            `so neither can win; refusing to publish the table.`,
        )
      }
    }
  }
}

/** Whether some path exists that both definitions would match. */
function overlap(left: RouteDefinition, right: RouteDefinition): boolean {
  if (left.segments.length !== right.segments.length) return false
  return left.segments.every((segment, index) => {
    const other = right.segments[index]
    return segment.startsWith(PLACEHOLDER) || other.startsWith(PLACEHOLDER) || segment === other
  })
}

/** How specific a definition is: the policy lets the one with more literal segments win. */
function literals(definition: RouteDefinition): number {
  return definition.segments.filter((segment) => !segment.startsWith(PLACEHOLDER)).length
}

async function ownNamespace(): Promise<string> {
  try {
    const declared = (await import('node:fs/promises')).readFile
    const value = (await declared(NAMESPACE_FILE, 'utf8')).trim()
    if (value) return value
  } catch {
    // Not running in a cluster.
  }
  return process.env.POD_NAMESPACE?.trim() || 'ory'
}

function archive(entries: readonly { name: string; content: string }[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const tar = pack()
    const gzip = createGzip()
    const chunks: Buffer[] = []

    gzip.on('data', (chunk: Buffer) => chunks.push(chunk))
    gzip.on('end', () => resolve(Buffer.concat(chunks)))
    gzip.on('error', reject)
    tar.on('error', reject)
    tar.pipe(gzip)

    for (const entry of entries) {
      const buffer = Buffer.from(entry.content, 'utf-8')
      tar.entry({ name: entry.name, size: buffer.length }, buffer)
    }
    tar.finalize()
  })
}
