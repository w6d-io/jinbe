import { env } from '../config/env.js'
import { HANDLER_KINDS, handlerMeta, type FieldMeta, type HandlerKind, type HandlerMeta } from './catalog.js'
import { SPEC_KEY, type GatewaySpec, type HandlerSpec } from './kube-gateway.js'
import { isSecretKey } from './secrets.js'

/**
 * Everything a proposed Gateway spec is checked against before it may be written.
 *
 * `error` refuses the write: Oathkeeper would reject the config (a missing required field, an
 * unknown key, a fallback naming a disabled handler), or a live rule would lose its handler.
 * `warn` is a risk the admin must see (sign-in skipped, everything allowed). `info` explains a
 * consequence (a rolling restart, a handler sites cannot use yet).
 */

export interface Issue {
  severity: 'error' | 'warn' | 'info'
  code: string
  message: string
  kind?: HandlerKind
  handler?: string
  path?: string
}

export interface Change {
  kind: HandlerKind
  handler: string
  change: 'enabled' | 'disabled' | 'config'
  /** Top-level config keys that differ. Names only — never values, which may be secrets. */
  changedKeys?: string[]
  /** Only an edited restart-sensitive template or secret, never its value. */
  sensitive?: boolean
}

export type InUse = Record<HandlerKind, Record<string, string[]>>

export interface Verdict { ok: boolean; issues: Issue[]; changes: Change[] }

const ENV_ENABLED: Record<HandlerKind, () => string[]> = {
  authenticator: () => env.OATHKEEPER_ENABLED_AUTHENTICATORS,
  authorizer: () => env.OATHKEEPER_ENABLED_AUTHORIZERS,
  mutator: () => env.OATHKEEPER_ENABLED_MUTATORS,
  error: () => env.OATHKEEPER_ENABLED_ERROR_HANDLERS,
}

type Json = Record<string, unknown>
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)
const getAt = (obj: unknown, key: string): unknown =>
  key.split('.').reduce<unknown>((cur, p) => (isObject(cur) ? cur[p] : undefined), obj)
const empty = (v: unknown) => v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0) || (isObject(v) && Object.keys(v).length === 0)
const isDuration = (v: unknown, pattern?: string) => typeof v === 'string' && new RegExp(pattern ?? '.').test(v)

function isUrl(v: unknown): boolean {
  if (typeof v !== 'string') return false
  try {
    new URL(v)
    return true
  } catch {
    return false
  }
}

/** Why `value` does not fit `field`, or null. */
function typeProblem(field: FieldMeta, value: unknown): string | null {
  switch (field.type) {
    case 'bool': return typeof value === 'boolean' ? null : 'must be true or false'
    case 'int': return Number.isInteger(value) && (value as number) >= 0 ? null : 'must be a non-negative integer'
    case 'url': return isUrl(value) ? null : 'must be an absolute URL'
    case 'duration': return isDuration(value, field.pattern) ? null : 'must be a duration like 500ms, 1s, 5m'
    case 'enum': return field.options?.includes(value as string | number) ? null : `must be one of ${field.options?.join(', ')}`
    case 'list': return Array.isArray(value) && value.every((x) => typeof x === 'string') ? null : 'must be a list of strings'
    case 'kv': return isObject(value) && Object.values(value).every((x) => typeof x === 'string') ? null : 'must be a map of strings'
    case 'string':
    case 'template':
      if (typeof value !== 'string') return 'must be a string'
      return field.pattern && !new RegExp(field.pattern).test(value) ? `must match ${field.pattern}` : null
    case 'json': return null
  }
}

function checkTokenFrom(value: unknown): string | null {
  if (value === null || value === undefined) return null
  if (!isObject(value)) return 'must be an object'
  const keys = Object.keys(value)
  const ok = keys.length === 1 && ['header', 'query_parameter', 'cookie'].includes(keys[0]) && typeof value[keys[0]] === 'string'
  return ok ? null : 'must have exactly one of header, query_parameter, cookie'
}

function checkWhen(value: unknown): string | null {
  if (value === undefined) return null
  if (!Array.isArray(value)) return 'must be a list of conditions'
  for (const cond of value) {
    const request = isObject(cond) ? cond.request : undefined
    if (isObject(request) && ('cidr' in request || 'remote_ip' in request)) {
      return 'IP conditions (request.cidr / remote_ip) do not work in Oathkeeper v25.4.0'
    }
  }
  return null
}

/** Schema problems in one enabled handler's config. */
function checkConfig(meta: HandlerMeta, config: Json | undefined, push: (i: Omit<Issue, 'kind' | 'handler'>) => void): void {
  const known = new Set(meta.fields.map((f) => f.key.split('.')[0]))
  for (const key of Object.keys(config ?? {})) {
    if (!known.has(key)) push({ severity: 'error', code: 'unknown_field', path: key, message: `${meta.name} has no setting "${key}"` })
  }
  for (const field of meta.fields) {
    const value = getAt(config, field.key)
    if (empty(value)) {
      if (field.required) push({ severity: 'error', code: 'field_required', path: field.key, message: `${meta.name}: ${field.label} is required once the handler is enabled` })
      continue
    }
    const problem = field.key === 'token_from' ? checkTokenFrom(value) : field.key === 'when' ? checkWhen(value) : typeProblem(field, value)
    if (problem) push({ severity: 'error', code: 'field_invalid', path: field.key, message: `${meta.name}: ${field.label} ${problem}` })
  }
  // Oathkeeper requires the secret with these blocks, and the Gateway may not carry one.
  if (getAt(config, 'pre_authorization.enabled') === true) {
    push({ severity: 'error', code: 'needs_platform_secret', path: 'pre_authorization', message: `${meta.name}: pre-authorization needs a client secret, which only the platform (chart) can set` })
  }
  if (getAt(config, 'api.auth') !== undefined) {
    push({ severity: 'error', code: 'needs_platform_secret', path: 'api.auth', message: `${meta.name}: basic auth needs a password, which only the platform (chart) can set` })
  }
  if (meta.name === 'jwt' && !empty(getAt(config, 'required_scope')) && (getAt(config, 'scope_strategy') ?? 'none') === 'none') {
    push({ severity: 'error', code: 'field_invalid', path: 'scope_strategy', message: 'jwt: required scopes with scope strategy "none" make every request answer 500' })
  }
}

const enabledIn = (spec: GatewaySpec | null, kind: HandlerKind, name: string) => spec?.[SPEC_KEY[kind]]?.[name]?.enabled === true

function changedKeys(meta: HandlerMeta | undefined, before: HandlerSpec | undefined, after: HandlerSpec | undefined): Change | null {
  const a = before?.config ?? {}
  const b = after?.config ?? {}
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k])).sort()
  if (!keys.length) return null
  const sensitiveTop = new Set([
    ...(meta?.fields.filter((f) => f.restart).map((f) => f.key.split('.')[0]) ?? []),
  ])
  return {
    kind: meta?.kind ?? 'authenticator',
    handler: meta?.name ?? '',
    change: 'config',
    changedKeys: keys,
    ...(keys.some((k) => sensitiveTop.has(k) || isSecretKey(k)) ? { sensitive: true } : {}),
  }
}

export function validate(proposed: GatewaySpec, current: GatewaySpec | null, inUse: InUse): Verdict {
  const issues: Issue[] = []
  const changes: Change[] = []

  for (const kind of HANDLER_KINDS) {
    const key = SPEC_KEY[kind]
    const names = new Set([...Object.keys(proposed[key] ?? {}), ...Object.keys(current?.[key] ?? {})])
    for (const name of names) {
      const meta = handlerMeta(kind, name)
      const push = (i: Omit<Issue, 'kind' | 'handler'>) => issues.push({ ...i, kind, handler: name })
      const after = proposed[key]?.[name]
      const wasOn = enabledIn(current, kind, name)
      const isOn = after?.enabled === true

      if (!meta) {
        if (after) push({ severity: 'error', code: 'unknown_handler', message: `Oathkeeper has no ${kind} "${name}"` })
        continue
      }
      if (isOn) checkConfig(meta, after?.config, push)
      if (isOn && !wasOn && meta.locked) push({ severity: 'error', code: 'handler_locked', message: `${name} cannot be enabled from the console: ${meta.locked}` })

      if (wasOn && !isOn) {
        const users = inUse[kind][name] ?? []
        if (users.length) push({ severity: 'error', code: 'handler_in_use', message: `${name} is used by ${users.join(', ')}; move them off it first` })
        changes.push({ kind, handler: name, change: 'disabled' })
      } else if (isOn && !wasOn) {
        changes.push({ kind, handler: name, change: 'enabled' })
        if (!ENV_ENABLED[kind]().includes(name)) {
          push({ severity: 'info', code: 'sites_env_stale', message: `Sites cannot reference ${name} until jinbe's OATHKEEPER_ENABLED_* lists it` })
        }
      }
      if (isOn) {
        const diff = changedKeys(meta, current?.[key]?.[name], after)
        if (diff && wasOn) changes.push(diff)
      }
    }
  }

  // Risks of what the change turns on.
  const turnedOn = (kind: HandlerKind, name: string) => changes.some((c) => c.kind === kind && c.handler === name && c.change === 'enabled')
  if (turnedOn('authenticator', 'noop') || turnedOn('authenticator', 'anonymous')) {
    issues.push({ severity: 'warn', code: 'risk_anonymous', kind: 'authenticator', message: 'Any rule may now let requests through with no sign-in' })
  }
  if (turnedOn('authorizer', 'allow')) {
    issues.push({ severity: 'warn', code: 'risk_allow_all', kind: 'authorizer', handler: 'allow', message: 'Any rule may now skip the permission check entirely' })
  }
  if (turnedOn('mutator', 'hydrator')) {
    issues.push({ severity: 'warn', code: 'risk_hydrator', kind: 'mutator', handler: 'hydrator', message: 'The hydrator receives every request header, cookies and Authorization included' })
  }
  if (turnedOn('authenticator', 'oauth2_client_credentials')) {
    issues.push({ severity: 'warn', code: 'risk_basic_secret', kind: 'authenticator', handler: 'oauth2_client_credentials', message: 'Callers send their client secret on every request' })
  }
  if (enabledIn(proposed, 'error', 'json') && getAt(proposed.errors.json?.config, 'verbose') === true && getAt(current?.errors?.json?.config, 'verbose') !== true) {
    issues.push({ severity: 'warn', code: 'risk_verbose_errors', kind: 'error', handler: 'json', message: 'Error responses will include internal reasons' })
  }
  const ttlChanged = changes.find((c) => c.kind === 'authenticator' && c.handler === 'oauth2_introspection' && c.changedKeys?.includes('cache'))
  if (ttlChanged) {
    issues.push({ severity: 'info', code: 'shared_cache', kind: 'authenticator', handler: 'oauth2_introspection', message: 'The introspection cache is one per gateway process: its TTL applies to every rule' })
  }

  // errors.fallback
  if (!proposed.errorFallback.length) {
    issues.push({ severity: 'error', code: 'fallback_empty', path: 'errorFallback', message: 'At least one fallback error handler is required' })
  }
  for (const name of proposed.errorFallback) {
    if (!enabledIn(proposed, 'error', name)) {
      issues.push({ severity: 'error', code: 'fallback_disabled', path: 'errorFallback', handler: name, message: `The fallback ${name} is not an enabled error handler; every unmatched request would answer 500` })
    }
  }

  if (changes.length || JSON.stringify(proposed.errorFallback) !== JSON.stringify(current?.errorFallback ?? [])) {
    issues.push({ severity: 'info', code: 'rolling_restart', message: 'The gateway pods restart one at a time to load the change' })
  }

  return { ok: !issues.some((i) => i.severity === 'error'), issues, changes }
}
