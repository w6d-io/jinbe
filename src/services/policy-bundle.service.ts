import { createHash } from 'node:crypto'
import { createGzip } from 'node:zlib'
import * as k8s from '@kubernetes/client-node'
import { pack } from 'tar-stream'
import { allGroupMemberships } from './organisation-store.js'

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
 * THE ROOT IS `ory`, so this bundle owns everything the engine decides against. That is only safe
 * because it carries everything: a bundle that owned the root while missing one service's table
 * would delete that table, and every route of that service would answer "no such route" — a refusal
 * indistinguishable from a missing right.
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

let cached: PolicyBundle | null = null

export async function policyBundle(): Promise<PolicyBundle> {
  const namespace = await ownNamespace()
  const [model, memberships] = await Promise.all([modelFrom(namespace), allGroupMemberships()])

  if (Object.prototype.hasOwnProperty.call(model, MEMBERSHIP_KEY)) {
    // A ConfigMap named `membership` would silently overwrite the people with the model, or the
    // other way round depending on order. Refused rather than resolved by luck.
    throw new PolicyBundleUnavailableError(
      `A ConfigMap named "${MEMBERSHIP_KEY}" collides with the memberships this bundle carries.`,
    )
  }

  const data = {
    [ROOT]: {
      ...model,
      [MEMBERSHIP_KEY]: Object.fromEntries(
        [...memberships.entries()].sort(([a], [b]) => a.localeCompare(b)),
      ),
    },
  }

  const payload = JSON.stringify(data, null, 2)
  const revision = createHash('sha256').update(payload).digest('hex').slice(0, 16)
  if (cached?.revision === revision) return cached

  const rules = await rulesFrom(namespace)
  // The revision covers the rules as well: a policy change has to move it, or the engine answers 304
  // and keeps deciding with the previous rules while the repository says otherwise.
  const fullRevision = createHash('sha256')
    .update(payload)
    .update(rules.map((r) => `${r.name}\n${r.content}`).join('\n'))
    .digest('hex')
    .slice(0, 16)
  if (cached?.revision === fullRevision) return cached

  const manifest = JSON.stringify({ revision: fullRevision, roots: [ROOT] }, null, 2)
  cached = {
    body: await archive([
      { name: '.manifest', content: manifest },
      { name: 'data.json', content: payload },
      ...rules,
    ]),
    revision: fullRevision,
  }
  return cached
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
  return model
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
