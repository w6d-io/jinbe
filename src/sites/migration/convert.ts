import type { OathkeeperRule } from '../../services/redis-rbac.repository.js'
import { platformPayload, sha256, upstreamUrl, type SiteCr, type SiteCrGate } from '../render.js'
import type { FieldChange } from '../diff.js'
import type { Handler } from '../schemas.js'

/**
 * Legacy rules → proposed Sites and system sites (site-ux §20.3), converted 1:1: same match URL,
 * methods, handlers and upstream, one gate per rule. What the operator would refuse as it is
 * becomes a `block` warning, cleared by an opt-in fix or a decision:
 *
 *   `http<(s?)>://` scheme       rewritten to `<https?>://` — the same requests, listed as a change
 *   remote_json without the app  fix `pin-app`: the platform payload pinned to the site (a policy change)
 *   host not literal             unassigned: decide `drop` (the rule is not carried over)
 *
 * Built-ins (bootstrap build-rules.ts) become system sites: kuma, jinbe, sign-in.
 */

export type Fix = 'pin-app'
export type Decision = 'drop'
export interface ConvertOptions { namespace: string; fixes?: Record<string, Fix[]>; decisions?: Record<string, Decision>; taken?: string[]; enabled?: Record<'authenticators' | 'authorizers' | 'mutators' | 'errors', string[]> }
export interface MigrationWarning { level: 'block' | 'warn'; code: string; message: string; ruleId?: string }
export interface MigrationGroup {
  proposedSite: string
  kind: 'site' | 'system' | 'unassigned'
  legacyRuleIds: string[]
  siteCr: SiteCr | null
  /** The rules the operator would render from siteCr, as Oathkeeper sees them. */
  renderedRules: OathkeeperRule[]
  /** rendered rule id → legacy rule id (parity maps matches back through it). */
  ruleMap: Record<string, string>
  changes: FieldChange[]
  warnings: MigrationWarning[]
  fixes: Fix[]
}

// The operator accepts only these scheme prefixes, followed by a literal site host and '/'.
const OPERATOR_SCHEMES = ['https://', 'http://', '<https?>://', '<http|https>://', '<(http|https)>://']
const LEGACY_SCHEMES = ['http<(s?)>://', 'http<s?>://', 'http<(s)?>://']
const HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/
const SECRET_KEY = /secret|password|passwd|token|api[_-]?key|private[_-]?key/i

export function systemSiteOf(id: string): string | null {
  if (id.startsWith('kuma-')) return 'kuma'
  if (id.startsWith('jinbe-')) return 'jinbe'
  if (id.startsWith('selfservice-') || id === 'kratos-public') return 'sign-in'
  return null
}

/** Scheme prefix, literal host and the rest of a match URL; host null when it is not literal. */
export function splitMatchUrl(url: string): { scheme: string; host: string | null; rest: string; legacyScheme: boolean } | null {
  for (const scheme of [...OPERATOR_SCHEMES, ...LEGACY_SCHEMES]) {
    if (!url.startsWith(scheme)) continue
    const after = url.slice(scheme.length)
    const end = after.search(/[/<]/)
    const host = end === -1 ? after : after.slice(0, end)
    const rest = end === -1 ? '' : after.slice(end)
    return { scheme, host: HOST.test(host) && rest.startsWith('/') ? host : null, rest, legacyScheme: LEGACY_SCHEMES.includes(scheme) }
  }
  return null
}

export function parseUpstream(raw: string, namespace: string): SiteCr['spec']['upstream'] | null {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  const parts = u.hostname.split('.')
  const label = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/
  const cluster = parts.length === 5 && parts.slice(2).join('.') === 'svc.cluster.local'
  const ok = parts.length === 1 || (parts.length === 2) || (parts.length === 3 && parts[2] === 'svc') || cluster
  if (!ok || !label.test(parts[0]) || (parts[1] !== undefined && !label.test(parts[1]))) return null
  return {
    service: parts[0],
    namespace: parts[1] ?? namespace,
    port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
    scheme: u.protocol === 'https:' ? 'https' : 'http',
    preserveHost: false,
  }
}

const gateNameOf = (id: string) => id.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32).replace(/-+$/, '') || 'rule'
const siteNameOf = (host: string) => {
  const n = host.split('.')[0].replace(/[^a-z0-9-]/g, '-').replace(/^[^a-z]+/, '').slice(0, 40).replace(/-+$/, '')
  return n.length >= 2 ? n : `site-${n || 'x'}`
}
const unique = (base: string, taken: Set<string>, max: number) => {
  let name = base
  for (let i = 2; taken.has(name); i++) name = `${base.slice(0, max - String(i).length - 1)}-${i}`
  taken.add(name)
  return name
}

function secretsIn(value: unknown, path: string): string[] {
  if (!value || typeof value !== 'object') return []
  return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => {
    if (typeof v === 'string' && SECRET_KEY.test(k) && v.length > 0 && !v.includes('{{')) return [`${path}.${k}`]
    return secretsIn(v, `${path}.${k}`)
  })
}

const appPinned = (h: Handler, site: string) => {
  const payload = (h.config as { payload?: unknown } | undefined)?.payload
  return typeof payload === 'string' && payload.replace(/\s+/g, '').includes(`"app":"${site}"`)
}

function convertGroup(site: string, kind: 'site' | 'system', rules: OathkeeperRule[], opts: ConvertOptions): MigrationGroup {
  const fixes = opts.fixes?.[site] ?? []
  const warnings: MigrationWarning[] = []
  const changes: FieldChange[] = []
  const gates: SiteCrGate[] = []
  const hosts: string[] = []
  const renderedRules: OathkeeperRule[] = []
  const ruleMap: Record<string, string> = {}
  const names = new Set<string>()
  let siteUpstream: SiteCr['spec']['upstream'] | null = null

  for (const rule of rules) {
    const split = splitMatchUrl(rule.match.url)!
    if (!hosts.includes(split.host!)) hosts.push(split.host!)
    const name = unique(gateNameOf(rule.id), names, 32)
    let url = rule.match.url
    if (split.legacyScheme) {
      url = `<https?>://${split.host}${split.rest}`
      changes.push({ path: `gates[${name}].match.url`, before: rule.match.url, after: url })
    }
    const parsed = parseUpstream(rule.upstream.url, opts.namespace)
    if (!parsed) {
      warnings.push({ level: 'block', code: 'upstream_unparseable', message: `${rule.id}: upstream ${rule.upstream.url} is not an in-cluster Service URL`, ruleId: rule.id })
    }
    const upstream = parsed ? { ...parsed, preserveHost: !!rule.upstream.preserve_host, ...(rule.upstream.strip_path ? { stripPath: rule.upstream.strip_path } : {}) } : null
    siteUpstream ??= upstream
    let authorizer = rule.authorizer as Handler
    if (authorizer.handler === 'remote_json' && !appPinned(authorizer, site)) {
      if (fixes.includes('pin-app')) {
        const pinned: Handler = { handler: 'remote_json', config: { ...((authorizer.config as object | undefined) ?? {}), payload: platformPayload(site) } }
        changes.push({ path: `gates[${name}].authorizer.config.payload`, before: (authorizer.config as { payload?: unknown } | undefined)?.payload ?? null, after: pinned.config!.payload })
        authorizer = pinned
      } else {
        warnings.push({ level: 'block', code: 'app_not_pinned', message: `${rule.id}: the policy payload does not name the site "${site}"; the operator refuses it (fix: pin-app, a policy change)`, ruleId: rule.id })
      }
    }
    for (const at of secretsIn({ authenticators: rule.authenticators, authorizer: rule.authorizer, mutators: rule.mutators, errors: rule.errors }, rule.id)) {
      warnings.push({ level: 'block', code: 'secret_in_rule', message: `${at} looks like a secret; Site CRs are readable in the cluster — move it to platform config`, ruleId: rule.id })
    }
    const stages = { authenticators: rule.authenticators, authorizers: [authorizer], mutators: rule.mutators, errors: rule.errors ?? [] }
    for (const [stage, hs] of Object.entries(stages) as Array<[keyof typeof stages, Array<{ handler: string }>]>) {
      for (const h of hs) {
        if (opts.enabled && !opts.enabled[stage].includes(h.handler)) {
          warnings.push({ level: 'warn', code: 'handler_disabled', message: `${rule.id}: ${h.handler} is not enabled on the gateway — converted as-is, still broken`, ruleId: rule.id })
        }
      }
    }
    const gate: SiteCrGate = {
      name,
      match: { methods: [...rule.match.methods], url },
      authenticators: rule.authenticators as Handler[],
      authorizer,
      mutators: rule.mutators.length > 0 ? (rule.mutators as Handler[]) : [{ handler: 'noop' }],
      ...(rule.errors?.length ? { errors: rule.errors as Handler[] } : {}),
      ...(upstream && siteUpstream && sha256(upstream) !== sha256(siteUpstream) ? { upstream } : {}),
    }
    gates.push(gate)
    const up = upstream ?? siteUpstream
    const rendered: OathkeeperRule = {
      id: `site-${site}-${name}`,
      upstream: up ? { url: upstreamUrl(up), ...(up.preserveHost ? { preserve_host: true } : {}), ...(up.stripPath ? { strip_path: up.stripPath } : {}) } : rule.upstream,
      match: gate.match,
      authenticators: gate.authenticators,
      authorizer: gate.authorizer,
      mutators: gate.mutators,
      ...(gate.errors ? { errors: gate.errors } : {}),
    }
    renderedRules.push(rendered)
    ruleMap[rendered.id] = rule.id
  }
  if (gates.length > 32) warnings.push({ level: 'block', code: 'too_many_gates', message: `${gates.length} rules; a Site holds at most 32` })
  if (hosts.length > 16) warnings.push({ level: 'block', code: 'too_many_hosts', message: `${hosts.length} hosts; a Site holds at most 16` })

  const spec: SiteCr['spec'] = {
    hosts,
    upstream: siteUpstream ?? { service: 'unknown', namespace: opts.namespace, port: 80, scheme: 'http', preserveHost: false },
    gates,
    exposure: { mode: 'zone' },
    paused: false,
    ...(kind === 'system' ? { system: true } : {}),
  }
  const siteCr: SiteCr = {
    apiVersion: 'auth.w6d.io/v1alpha1',
    kind: 'Site',
    metadata: {
      name: site,
      namespace: opts.namespace,
      labels: { 'auth.w6d.io/site': site, 'app.kubernetes.io/managed-by': 'jinbe', 'auth.w6d.io/migrated': 'true' },
      annotations: { 'auth.w6d.io/spec-hash': sha256(spec) },
    },
    spec,
  }
  return { proposedSite: site, kind, legacyRuleIds: rules.map((r) => r.id), siteCr, renderedRules, ruleMap, changes, warnings, fixes }
}

export function convertLegacy(rules: OathkeeperRule[], opts: ConvertOptions): MigrationGroup[] {
  const buckets = new Map<string, { kind: 'site' | 'system'; rules: OathkeeperRule[] }>()
  const unassigned: OathkeeperRule[] = []
  const taken = new Set<string>(opts.taken ?? [])
  const byHost = new Map<string, string>()
  for (const s of ['kuma', 'jinbe', 'sign-in']) taken.add(s)

  for (const rule of rules) {
    const split = splitMatchUrl(rule.match?.url ?? '')
    if (!split?.host) {
      unassigned.push(rule)
      continue
    }
    const system = systemSiteOf(rule.id)
    let site = system
    if (!site) {
      site = byHost.get(split.host) ?? unique(siteNameOf(split.host), taken, 40)
      byHost.set(split.host, site)
    }
    const bucket = buckets.get(site) ?? { kind: system ? 'system' : 'site', rules: [] }
    bucket.rules.push(rule)
    buckets.set(site, bucket)
  }

  const groups = [...buckets.entries()].map(([site, b]) => convertGroup(site, b.kind, b.rules, opts))
  if (unassigned.length > 0) {
    groups.push({
      proposedSite: 'unassigned',
      kind: 'unassigned',
      legacyRuleIds: unassigned.map((r) => r.id),
      siteCr: null,
      renderedRules: [],
      ruleMap: {},
      changes: [],
      fixes: [],
      warnings: unassigned.map((r) => opts.decisions?.[r.id] === 'drop'
        ? { level: 'warn' as const, code: 'dropped', message: `${r.id} is dropped: not carried over to the sites`, ruleId: r.id }
        : { level: 'block' as const, code: 'unassigned', message: `${r.id}: the match URL has no literal host (${r.match?.url}); decide what to do with it`, ruleId: r.id }),
    })
  }
  return groups
}

export const blocksOf = (groups: MigrationGroup[]) => groups.flatMap((g) => g.warnings.filter((w) => w.level === 'block'))
