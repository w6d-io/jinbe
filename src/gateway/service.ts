import { env } from '../config/env.js'
import { sitesConfig } from '../sites/config.js'
import type { SiteCrObject } from '../sites/kube-sites.js'
import { auditGateway, type Actor } from './audit.js'
import { CATALOG, HANDLER_KINDS, PLATFORM_HANDLERS, handlerMeta, type FieldMeta, type HandlerKind } from './catalog.js'
import {
  GATEWAY_NAME, PREVIOUS_SPEC_ANNOTATION, SPEC_KEY, fromCrSpec, kubeGateway, toCrSpec,
  type Condition, type GatewayCr, type GatewaySpec, type HandlerSpec, type SpecKey,
} from './kube-gateway.js'
import type { ProposalBody } from './schemas.js'
import { maskConfig, resolveSecrets, type SecretIssue } from './secrets.js'
import { validate, type InUse, type Issue, type Verdict } from './validate.js'

/**
 * The platform level of the gateway: which Oathkeeper handlers exist, their global config, and the
 * rolling restart that loads a change (per-site rules are src/sites).
 *
 * The source of truth is the Gateway CR. Until one exists the live Oathkeeper config is shown,
 * read-only, as `managed: false`; the first accepted PUT creates the CR from the edited copy.
 */

export const PLATFORM_USER = '(platform)'
const UNMANAGED_ETAG = 'unmanaged'

type Json = Record<string, unknown>
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)

const httpError = (statusCode: number, code: string, message: string, extra: Json = {}) =>
  Object.assign(new Error(message), { statusCode, code, ...extra })

interface Current {
  managed: boolean
  source: 'gateway-cr' | 'oathkeeper-config' | 'env'
  spec: GatewaySpec
  etag: string
  cr: GatewayCr | null
}

const emptySpec = (): GatewaySpec => ({ authenticators: {}, authorizers: {}, mutators: {}, errors: {}, errorFallback: [] })

/** Oathkeeper's own config.yaml → the Gateway spec shape. */
export function specFromOathkeeperConfig(doc: Json): GatewaySpec {
  const spec = emptySpec()
  const section = (key: SpecKey): Json => {
    const raw = doc[key]
    if (key !== 'errors') return isObject(raw) ? raw : {}
    return isObject(raw) && isObject(raw.handlers) ? raw.handlers : {}
  }
  for (const kind of HANDLER_KINDS) {
    const key = SPEC_KEY[kind]
    for (const [name, value] of Object.entries(section(key))) {
      if (!isObject(value)) continue
      spec[key][name] = { enabled: value.enabled === true, ...(isObject(value.config) ? { config: value.config } : {}) }
    }
  }
  const errors = doc.errors
  spec.errorFallback = isObject(errors) && Array.isArray(errors.fallback) ? errors.fallback.filter((x): x is string => typeof x === 'string') : ['json']
  return spec
}

function specFromEnv(): GatewaySpec {
  const spec = emptySpec()
  const on = (key: SpecKey, names: string[]) => names.forEach((n) => { spec[key][n] = { enabled: true } })
  on('authenticators', env.OATHKEEPER_ENABLED_AUTHENTICATORS)
  on('authorizers', env.OATHKEEPER_ENABLED_AUTHORIZERS)
  on('mutators', env.OATHKEEPER_ENABLED_MUTATORS)
  on('errors', env.OATHKEEPER_ENABLED_ERROR_HANDLERS)
  spec.errorFallback = env.OATHKEEPER_ENABLED_ERROR_HANDLERS.includes('json') ? ['json'] : []
  return spec
}

async function current(): Promise<Current> {
  const kube = kubeGateway()
  const cr = await kube.get()
  if (cr) {
    return { managed: true, source: 'gateway-cr', spec: fromCrSpec(cr.spec), etag: `rv:${cr.metadata.resourceVersion ?? ''}`, cr }
  }
  const live = await kube.liveOathkeeperConfig()
  return live
    ? { managed: false, source: 'oathkeeper-config', spec: specFromOathkeeperConfig(live), etag: UNMANAGED_ETAG, cr: null }
    : { managed: false, source: 'env', spec: specFromEnv(), etag: UNMANAGED_ETAG, cr: null }
}

/**
 * Which sites and platform rules reference each handler: the Site CRs, plus the operator's
 * `status.inUse` (which also sees the platform's own rules, as `rule/<name>`). Before the operator
 * has reported, the handlers the platform is known to need stand in for its rules.
 */
export function handlersInUse(sites: SiteCrObject[], cr: GatewayCr | null = null): InUse {
  const inUse: InUse = { authenticator: {}, authorizer: {}, mutator: {}, error: {} }
  const add = (kind: HandlerKind, name: string | undefined, who: string) => {
    if (!name) return
    const list = (inUse[kind][name] ??= [])
    if (!list.includes(who)) list.push(who)
  }
  const reported = cr?.status?.inUse
  if (reported) {
    const kindOf = Object.fromEntries(HANDLER_KINDS.map((k) => [SPEC_KEY[k], k])) as Record<string, HandlerKind>
    for (const use of reported) {
      const [plural, name] = use.handler.split('/')
      if (kindOf[plural]) use.usedBy.forEach((who) => add(kindOf[plural], name, who))
    }
  } else {
    for (const kind of HANDLER_KINDS) PLATFORM_HANDLERS[kind].forEach((n) => add(kind, n, PLATFORM_USER))
  }
  for (const site of sites) {
    const who = site.metadata.name
    for (const gate of site.spec?.gates ?? []) {
      gate.authenticators?.forEach((h) => add('authenticator', h.handler, who))
      add('authorizer', gate.authorizer?.handler, who)
      gate.mutators?.forEach((h) => add('mutator', h.handler, who))
      gate.errors?.forEach((h) => add('error', h.handler, who))
    }
  }
  return inUse
}

const defaultsOf = (fields: FieldMeta[]): Json =>
  Object.fromEntries(fields.filter((f) => f.default !== undefined).map((f) => [f.key, f.default]))

export type RolloutPhase = 'Pending' | 'Progressing' | 'Complete' | 'Failed' | 'RolledBack'

/**
 * The operator reports conditions (Validated, Applied, Rolled, Ready); the console wants one phase.
 * A generation the operator has not observed yet is Pending whatever the conditions say.
 */
export function rolloutOf(cr: GatewayCr) {
  const conditions = cr.status?.conditions ?? []
  const cond = (type: string): Condition | undefined => conditions.find((c) => c.type === type)
  const generation = cr.metadata.generation ?? null
  const observed = cr.status?.observedGeneration ?? null
  const validated = cond('Validated')
  const applied = cond('Applied')
  const rolled = cond('Rolled')
  const ready = cond('Ready')
  let phase: RolloutPhase
  let decisive: Condition | undefined
  if (generation !== null && observed !== generation) phase = 'Pending'
  else if (validated?.status === 'False') [phase, decisive] = ['Failed', validated]
  else if (applied?.status === 'False' && applied.reason === 'RolledBack') [phase, decisive] = ['RolledBack', applied]
  else if (ready?.status === 'False' && ready.reason === 'RolloutFailed') [phase, decisive] = ['Failed', ready]
  else if (ready?.status === 'True') [phase, decisive] = ['Complete', ready]
  else if (rolled?.status === 'False' && rolled.reason === 'RollingOut') [phase, decisive] = ['Progressing', rolled]
  else [phase, decisive] = ['Pending', rolled ?? validated]
  // Rolled's message while rolling: "n/N pods updated, n ready, n total".
  const pods = /(\d+)\/(\d+) pods updated, (\d+) ready, (\d+) total/.exec(rolled?.message ?? '')
  return {
    phase,
    reason: decisive?.reason ?? null,
    message: decisive?.message ?? null,
    since: decisive?.lastTransitionTime ?? null,
    pods: pods ? { updated: Number(pods[1]), ready: Number(pods[3]), total: Number(pods[4]) } : null,
    configHash: cr.status?.configHash ?? null,
    failedHash: cr.status?.failedHash ?? null,
  }
}

function statusView(cr: GatewayCr | null) {
  return {
    generation: cr?.metadata.generation ?? null,
    observedGeneration: cr?.status?.observedGeneration ?? null,
    conditions: cr?.status?.conditions ?? [],
    liveEnabled: cr?.status?.enabled ?? null,
    lastRollout: cr ? rolloutOf(cr) : null,
  }
}

export async function view() {
  const [cur, sites] = await Promise.all([current(), kubeGateway().listSites()])
  const inUse = handlersInUse(sites, cur.cr)
  const handlers = HANDLER_KINDS.flatMap((kind) => {
    const key = SPEC_KEY[kind]
    const known = CATALOG.filter((m) => m.kind === kind)
    const unknown = Object.keys(cur.spec[key]).filter((n) => !handlerMeta(kind, n))
    return [
      ...known.map((meta) => {
        const h: HandlerSpec | undefined = cur.spec[key][meta.name]
        return {
          kind, name: meta.name, label: meta.label, description: meta.description,
          enabled: h?.enabled === true,
          config: maskConfig(h?.config) ?? {},
          defaults: defaultsOf(meta.fields),
          inUse: inUse[kind][meta.name] ?? [],
          ...(meta.locked ? { locked: meta.locked } : {}),
          fields: meta.fields,
        }
      }),
      // A handler the running config has and the catalog does not know: shown, never editable.
      ...unknown.map((name) => ({
        kind, name, label: name, description: 'Not in the handler catalog of Oathkeeper v25.4.0',
        enabled: cur.spec[key][name].enabled === true, config: {}, defaults: {},
        inUse: inUse[kind][name] ?? [], locked: 'Unknown to this console', fields: [],
      })),
    ]
  })
  return {
    managed: cur.managed,
    source: cur.source,
    namespace: sitesConfig().namespace,
    etag: cur.etag,
    errorFallback: cur.spec.errorFallback,
    handlers,
    status: statusView(cur.cr),
  }
}

/** The proposal with `***` secrets resolved against what is saved, plus its verdict. */
async function evaluate(body: ProposalBody, cur: Current): Promise<{ spec: GatewaySpec; verdict: Verdict }> {
  const spec = emptySpec()
  const secretIssues: Issue[] = []
  for (const kind of HANDLER_KINDS) {
    const key = SPEC_KEY[kind]
    for (const [name, h] of Object.entries(body.spec[key])) {
      const { config, issues } = resolveSecrets(h.config, cur.spec[key][name]?.config)
      spec[key][name] = { enabled: h.enabled, ...(config ? { config } : {}) }
      issues.forEach((i: SecretIssue) => secretIssues.push({ severity: 'error', code: i.code, message: i.message, kind, handler: name, path: i.path }))
    }
  }
  spec.errorFallback = body.spec.errorFallback
  const sites = await kubeGateway().listSites()
  const verdict = validate(spec, cur.spec, handlersInUse(sites, cur.cr))
  const issues = [...secretIssues, ...verdict.issues]
  return { spec, verdict: { ok: verdict.ok && secretIssues.length === 0, issues, changes: verdict.changes } }
}

export async function preview(body: ProposalBody) {
  const cur = await current()
  const { verdict } = await evaluate(body, cur)
  return { ...verdict, managed: cur.managed, etag: cur.etag }
}

const unquote = (v: string | undefined) => v?.trim().replace(/^W\//, '').replace(/^"(.*)"$/, '$1')

function crFor(spec: GatewaySpec, previous: GatewaySpec | null, base: GatewayCr | null, actor: Actor, note?: string): GatewayCr {
  const annotations = { ...(base?.metadata.annotations ?? {}) }
  if (previous) annotations[PREVIOUS_SPEC_ANNOTATION] = JSON.stringify(previous)
  else delete annotations[PREVIOUS_SPEC_ANNOTATION]
  annotations['auth.w6d.io/changed-by'] = actor.email ?? actor.id ?? 'unknown'
  if (note) annotations['auth.w6d.io/change-note'] = note
  else delete annotations['auth.w6d.io/change-note']
  return {
    apiVersion: 'auth.w6d.io/v1alpha1',
    kind: 'Gateway',
    metadata: {
      name: GATEWAY_NAME,
      namespace: sitesConfig().namespace,
      labels: { ...(base?.metadata.labels ?? {}), 'app.kubernetes.io/managed-by': 'jinbe' },
      annotations,
    },
    spec: toCrSpec(spec),
  }
}

export async function put(body: ProposalBody, ifMatch: string | undefined, actor: Actor) {
  const expected = unquote(ifMatch)
  if (!expected) throw httpError(428, 'precondition_required', 'If-Match is required: send the etag of the configuration you edited')
  const cur = await current()
  if (expected !== cur.etag) throw httpError(412, 'precondition_failed', 'The gateway configuration changed since you read it; reload and retry')
  const { spec, verdict } = await evaluate(body, cur)
  if (!verdict.ok) throw httpError(422, 'gateway_invalid', 'The proposed gateway configuration is refused', { issues: verdict.issues })

  // Adopting the live config: no previous spec is recorded — it was never a Gateway.
  const written = await kubeGateway().write(
    crFor(spec, cur.managed ? cur.spec : null, cur.cr, actor, body.note),
    cur.managed ? cur.cr!.metadata.resourceVersion ?? '' : null,
  )
  auditGateway('gateway.changed', actor, cur.managed ? `${verdict.changes.length} handler change(s)` : 'gateway adopted from the live Oathkeeper config', {
    changes: verdict.changes, generation: written.metadata.generation, note: body.note,
  })
  return {
    etag: `rv:${written.metadata.resourceVersion ?? ''}`,
    generation: written.metadata.generation ?? null,
    changes: verdict.changes,
    issues: verdict.issues,
  }
}

export async function rollback(ifMatch: string | undefined, actor: Actor, note?: string) {
  const cur = await current()
  if (!cur.cr) throw httpError(404, 'not_managed', 'There is no Gateway resource to roll back')
  const expected = unquote(ifMatch)
  if (expected && expected !== cur.etag) throw httpError(412, 'precondition_failed', 'The gateway configuration changed since you read it; reload and retry')
  const raw = cur.cr.metadata.annotations?.[PREVIOUS_SPEC_ANNOTATION]
  if (!raw) throw httpError(409, 'no_previous', 'No previous gateway configuration is recorded')
  let previous: GatewaySpec
  try {
    previous = { ...emptySpec(), ...(JSON.parse(raw) as GatewaySpec) }
  } catch {
    throw httpError(409, 'no_previous', 'The recorded previous configuration cannot be read')
  }
  // The previous spec is re-checked against today's sites: rolling back must not pull a handler
  // out from under a site plugged since.
  const verdict = validate(previous, cur.spec, handlersInUse(await kubeGateway().listSites(), cur.cr))
  if (!verdict.ok) throw httpError(422, 'gateway_invalid', 'The previous configuration is refused today', { issues: verdict.issues })
  const written = await kubeGateway().write(crFor(previous, cur.spec, cur.cr, actor, note), cur.cr.metadata.resourceVersion ?? '')
  auditGateway('gateway.rolled_back', actor, `rolled back ${verdict.changes.length} handler change(s)`, {
    changes: verdict.changes, generation: written.metadata.generation, note,
  })
  return { etag: `rv:${written.metadata.resourceVersion ?? ''}`, generation: written.metadata.generation ?? null, changes: verdict.changes }
}

const SETTLED = new Set<RolloutPhase>(['Complete', 'Failed', 'RolledBack'])

export async function rollout() {
  const cr = await kubeGateway().get()
  if (!cr) return { managed: false as const, settled: true, generation: null, observedGeneration: null, rollout: null, conditions: [] }
  const s = statusView(cr)
  return {
    managed: true as const,
    settled: SETTLED.has(s.lastRollout!.phase),
    generation: s.generation,
    observedGeneration: s.observedGeneration,
    rollout: s.lastRollout,
    conditions: s.conditions,
  }
}
