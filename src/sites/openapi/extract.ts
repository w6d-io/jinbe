import { LIMITS, specError } from './limits.js'
import { derefObject } from './refs.js'
import { toRoutePath } from './path.js'

/**
 * The ~10 fields an import reads, out of a parsed Swagger 2.0 / OpenAPI 3.0 / 3.1 tree, normalised to
 * one model: paths, methods, operationId, tags, security, security scheme names, servers/basePath,
 * path-parameter names, deprecated, and the x-w6d-* / x-rbac-* extensions. Request and response
 * schemas are never looked at. Every value is re-checked by hand (type, length); anything else in the
 * document is ignored, never trusted. 3.1 `webhooks` are not routes: counted, not imported.
 */

export const SPEC_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const
export type SpecMethod = (typeof SPEC_METHODS)[number]
export type Security = Array<Record<string, string[]>>

export interface SpecOperation {
  method: SpecMethod
  path: string
  operationId?: string
  tags: string[]
  /** The operation's security, else the root's; absent when neither says anything. */
  security?: Security
  securityFrom: 'operation' | 'root' | 'none'
  /** Names of the `in: path` parameters (path item and operation). */
  params: string[]
  deprecated: boolean
  /** x-w6d-* and x-rbac-* only, the operation's over its path item's. */
  ext: Record<string, unknown>
  notes: string[]
}

export interface ParsedSpec {
  format: '2.0' | '3.0' | '3.1'
  title: string
  version: string
  /** Base paths from servers[].url (3.x) or basePath (2.0), deduplicated, in spec order. */
  basePaths: string[]
  /** Hosts the spec names. Never used for the site address: shown for information only. */
  hosts: string[]
  securitySchemes: string[]
  /** Root `x-w6d: {resource, defaultAccess}`. */
  root: { resource?: string; defaultAccess?: string }
  operations: SpecOperation[]
  counts: { paths: number; operations: number; webhooks: number; ignoredMethods: number }
  notes: string[]
}

type Json = unknown
type Obj = Record<string, Json>
const isObject = (v: Json): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const str = (v: Json, max: number): string | undefined => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : undefined)
const own = (o: Obj, k: string): Json => (Object.hasOwn(o, k) ? o[k] : undefined)

const EXTENSIONS = ['x-w6d-access', 'x-w6d-permission', 'x-w6d-org-param', 'x-w6d-gate', 'x-w6d-2fa', 'x-w6d-skip', 'x-w6d-route-id', 'x-rbac-permission', 'x-rbac-public']

function extensionsOf(node: Obj): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of EXTENSIONS) {
    const v = own(node, key)
    if (typeof v === 'boolean' || (typeof v === 'string' && v.length <= 256)) out[key] = v
    else if (key === 'x-w6d-access' && isObject(v) && str(own(v, 'permission'), 256)) out[key] = { permission: own(v, 'permission') }
  }
  return out
}

function version(tree: Obj): ParsedSpec['format'] {
  const swagger = own(tree, 'swagger')
  const openapi = own(tree, 'openapi')
  if (swagger === '2.0') return '2.0'
  if (typeof openapi === 'string' && openapi.length <= 16) {
    if (/^3\.0\.[0-9]+$/.test(openapi)) return '3.0'
    if (/^3\.1\.[0-9]+$/.test(openapi)) return '3.1'
  }
  throw specError('unsupported_version', 'not a Swagger 2.0, OpenAPI 3.0 or OpenAPI 3.1 document')
}

function security(v: Json): Security | undefined {
  if (!Array.isArray(v) || v.length > 32) return undefined
  const out: Security = []
  for (const req of v) {
    if (!isObject(req) || Object.keys(req).length > 16) return undefined
    const entry: Record<string, string[]> = {}
    for (const [scheme, scopes] of Object.entries(req)) {
      if (!Array.isArray(scopes) || scopes.length > 64 || !scopes.every((s) => str(s, 256))) return undefined
      entry[scheme] = scopes as string[]
    }
    out.push(entry)
  }
  return out
}

/** `{var}` replaced by the variable's default; null when a variable has none. */
function expandServer(url: string, variables: Json): string | null {
  let out = ''
  let i = 0
  while (i < url.length) {
    const open = url.indexOf('{', i)
    if (open === -1) return out + url.slice(i)
    const close = url.indexOf('}', open)
    if (close === -1) return null
    const variable = isObject(variables) ? own(variables, url.slice(open + 1, close)) : undefined
    const value = isObject(variable) ? str(own(variable, 'default'), 256) : undefined
    if (value === undefined) return null
    out += url.slice(i, open) + value
    i = close + 1
  }
  return out
}

/** Path and host of a server URL (`https://api.x.com/v1`, `/v1`). The path must be literal. */
function splitServer(url: string): { path: string; host?: string } | null {
  let path: string
  let host: string | undefined
  const scheme = url.indexOf('://')
  if (url.startsWith('/')) path = url
  else if (scheme > 0) {
    const slash = url.indexOf('/', scheme + 3)
    host = url.slice(scheme + 3, slash === -1 ? undefined : slash)
    path = slash === -1 ? '/' : url.slice(slash)
  } else return null
  for (const cut of ['?', '#']) if (path.includes(cut)) path = path.slice(0, path.indexOf(cut))
  const parsed = toRoutePath(path)
  if (!parsed.ok || parsed.params.length > 0) return null
  return { path: parsed.path === '/' ? '' : parsed.path, ...(host ? { host: host.slice(0, 253) } : {}) }
}

function servers(tree: Obj, format: ParsedSpec['format'], notes: string[]): { basePaths: string[]; hosts: string[] } {
  const basePaths: string[] = []
  const hosts: string[] = []
  const add = (s: { path: string; host?: string } | null, raw: string) => {
    if (!s) return void notes.push(`server '${raw.slice(0, 80)}' ignored: its path is not a literal path`)
    if (!basePaths.includes(s.path)) basePaths.push(s.path)
    if (s.host && !hosts.includes(s.host)) hosts.push(s.host)
  }
  if (format === '2.0') {
    const host = str(own(tree, 'host'), 253)
    if (host) hosts.push(host)
    const base = str(own(tree, 'basePath'), LIMITS.pathLength)
    if (base) add(splitServer(base), base)
    return { basePaths, hosts }
  }
  const list = own(tree, 'servers')
  if (Array.isArray(list)) {
    for (const server of list.slice(0, 32)) {
      const url = isObject(server) ? str(own(server, 'url'), 2048) : undefined
      if (!url) continue
      const expanded = expandServer(url, own(server as Obj, 'variables'))
      add(expanded === null ? null : splitServer(expanded), url)
    }
  }
  return { basePaths, hosts }
}

function pathParams(root: Obj, list: Json, into: string[], notes: string[]): void {
  if (list === undefined) return
  if (!Array.isArray(list) || list.length > 256) throw specError('invalid_spec', 'parameters must be a list')
  for (const p of list) {
    const param = derefObject(root, p, 'a parameter')
    if (!param || own(param, 'in') !== 'path') continue
    const name = str(own(param, 'name'), 64)
    if (!name) notes.push('a path parameter without a usable name was ignored')
    else if (!into.includes(name)) into.push(name)
  }
}

function schemeNames(tree: Obj, format: ParsedSpec['format']): string[] {
  const holder = format === '2.0' ? own(tree, 'securityDefinitions') : isObject(own(tree, 'components')) ? own(own(tree, 'components') as Obj, 'securitySchemes') : undefined
  if (!isObject(holder)) return []
  // Resolved only to check each is a real scheme object; its content is not used.
  return Object.keys(holder).slice(0, 64).filter((k) => derefObject(tree, holder[k], 'a security scheme') !== null)
}

export function extract(tree: Json): ParsedSpec {
  if (!isObject(tree)) throw specError('invalid_spec', 'the spec must be an object')
  const format = version(tree)
  const notes: string[] = []
  const info = isObject(own(tree, 'info')) ? (own(tree, 'info') as Obj) : {}
  const rootExt = isObject(own(tree, 'x-w6d')) ? (own(tree, 'x-w6d') as Obj) : {}
  const rootSecurity = security(own(tree, 'security'))
  const paths = own(tree, 'paths')
  if (paths !== undefined && !isObject(paths)) throw specError('invalid_spec', 'paths must be an object')
  const entries = Object.entries(paths ?? {})
  if (entries.length > LIMITS.paths) throw specError('too_many_paths', `more than ${LIMITS.paths} paths`)
  const webhooks = own(tree, 'webhooks')
  const operations: SpecOperation[] = []
  let ignoredMethods = 0
  for (const [path, rawItem] of entries) {
    const item = derefObject(tree, rawItem, `path item ${path.slice(0, 80)}`)
    if (!item) continue
    const itemParams: string[] = []
    pathParams(tree, own(item, 'parameters'), itemParams, notes)
    const itemExt = extensionsOf(item)
    for (const key of Object.keys(item)) {
      const method = key.toUpperCase() as SpecMethod
      if (!SPEC_METHODS.includes(method)) {
        if (key === 'trace' || key === 'query') ignoredMethods++
        continue
      }
      if (operations.length >= LIMITS.operations) throw specError('too_many_operations', `more than ${LIMITS.operations} operations`)
      const op = item[key]
      if (!isObject(op)) throw specError('invalid_spec', `${key} ${path.slice(0, 80)} must be an object`)
      const opNotes: string[] = []
      const params = [...itemParams]
      pathParams(tree, own(op, 'parameters'), params, opNotes)
      const rawId = own(op, 'operationId')
      const operationId = typeof rawId === 'string' && /^[\x21-\x7e]{1,128}$/.test(rawId) ? rawId : undefined
      if (rawId !== undefined && !operationId) opNotes.push(`operationId ignored: 1-${LIMITS.operationId} printable characters, no spaces`)
      const tags = Array.isArray(own(op, 'tags')) ? (own(op, 'tags') as Json[]).map((t) => str(t, 64)).filter((t): t is string => !!t).slice(0, 8) : []
      const opSecurity = Object.hasOwn(op, 'security') ? security(op.security) : undefined
      if (Object.hasOwn(op, 'security') && !opSecurity) opNotes.push('security ignored: not a list of requirements')
      operations.push({
        method,
        path,
        ...(operationId ? { operationId } : {}),
        tags,
        ...(opSecurity ? { security: opSecurity } : rootSecurity ? { security: rootSecurity } : {}),
        securityFrom: opSecurity ? 'operation' : rootSecurity ? 'root' : 'none',
        params,
        deprecated: own(op, 'deprecated') === true,
        ext: { ...itemExt, ...extensionsOf(op) },
        notes: opNotes,
      })
    }
  }
  const { basePaths, hosts } = servers(tree, format, notes)
  return {
    format,
    title: str(own(info, 'title'), 200) ?? 'untitled',
    version: str(own(info, 'version'), 64) ?? '',
    basePaths,
    hosts,
    securitySchemes: schemeNames(tree, format),
    root: {
      ...(str(own(rootExt, 'resource'), 64) ? { resource: own(rootExt, 'resource') as string } : {}),
      ...(str(own(rootExt, 'defaultAccess'), 32) ? { defaultAccess: own(rootExt, 'defaultAccess') as string } : {}),
    },
    operations,
    counts: { paths: entries.length, operations: operations.length, webhooks: isObject(webhooks) ? Object.keys(webhooks).length : 0, ignoredMethods },
    notes,
  }
}

