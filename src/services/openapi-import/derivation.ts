// Permission derivation + OpenAPI→route path conversion for the spec importer.
//
// Precedence (first that resolves wins), mirroring the design:
//   1. x-rbac-public: true            → public (no permission)
//   2. x-rbac-permission: "<perm>"    → explicit permission
//   3. security scope → scopeMap      → mapped permission
//   4. resource(tag|path|operationId) + verb(method) → "<resource>:<verb>"
//   5. unmapped                       → forces an explicit choice in review
//
// Nothing is ever silently made public or allowed; an unresolved operation is
// returned with source "unmapped" so the UI must resolve it before apply.

export const PERMISSION_EXTENSION = 'x-rbac-permission'
export const PUBLIC_EXTENSION = 'x-rbac-public'

export const DEFAULT_VERB_MAP: Record<string, string> = {
  GET: 'read',
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  DELETE: 'delete',
  HEAD: 'read',
  OPTIONS: 'read',
}

export type ResourceFrom = 'tag' | 'path' | 'operationId'
export type PermSource =
  | 'public-extension'
  | 'extension'
  | 'scope'
  | 'tag'
  | 'path'
  | 'operationId'
  | 'unmapped'

export interface DerivationOptions {
  resourceFrom: ResourceFrom
  verbMap: Record<string, string>
  listAsRead: boolean
  honorExtension: boolean
  scopeMap?: Record<string, string>
}

export interface OperationInput {
  method: string // upper-case
  routePath: string // already converted to /:param canonical form
  operationId?: string
  tags?: string[]
  security?: Array<Record<string, string[]>>
  extensions?: Record<string, unknown> // the x-* keys of the operation
  isCollection: boolean // last path segment is NOT a param
}

export interface DerivedPermission {
  permission?: string
  public: boolean
  source: PermSource
}

// ── path conversion ──────────────────────────────────────────────────────────

/** Lower-case, non-alnum runs → single "_", trimmed. "API Keys" → "api_keys". */
export function slug(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
}

/**
 * Convert an OpenAPI path to a route_map path:
 *  - {param}            → :param
 *  - apply basePath per mode (prepend | strip | none)
 *  - collapse // and strip a trailing slash (canonical, matching the policy)
 */
export function openApiPathToRoute(
  specPath: string,
  basePath: string,
  mode: 'prepend' | 'strip' | 'none',
): string {
  let p = specPath
  if (mode === 'prepend' && basePath) {
    p = `${basePath.replace(/\/$/, '')}/${specPath.replace(/^\//, '')}`
  } else if (mode === 'strip' && basePath && specPath.startsWith(basePath)) {
    p = specPath.slice(basePath.length) || '/'
  }
  p = p.replace(/\{([^}]+)\}/g, (_m, name) => `:${name}`) // {id} → :id
  p = '/' + p.replace(/^\/+/, '') // ensure single leading slash
  p = p.replace(/\/{2,}/g, '/') // collapse //
  if (p.length > 1) p = p.replace(/\/+$/, '') // strip trailing slash
  return p
}

/** Route path segments, dropping the leading empty from the leading slash. */
function segments(routePath: string): string[] {
  return routePath.split('/').filter((s) => s.length > 0)
}

const NOISE = new Set(['api', 'v1', 'v2', 'v3', 'rest', 'public'])

/** Resource noun from a route path: last literal segment that isn't noise. */
export function resourceFromPath(routePath: string): string | undefined {
  const parts = segments(routePath).filter(
    (s) => !s.startsWith(':') && !NOISE.has(s) && !/^v\d+$/.test(s),
  )
  const last = parts[parts.length - 1]
  return last ? slug(last) : undefined
}

/** Resource noun from an operationId ("listInvoices"/"invoices_delete" → invoices). */
export function resourceFromOperationId(operationId?: string): string | undefined {
  if (!operationId) return undefined
  // split camelCase + snake/kebab, drop leading verb-ish tokens
  const tokens = operationId
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase())
  const verbs = new Set(['get', 'list', 'create', 'add', 'update', 'put', 'patch', 'delete', 'remove', 'fetch'])
  const nouns = tokens.filter((t) => !verbs.has(t))
  const pick = nouns[0] ?? tokens[tokens.length - 1]
  return pick ? slug(pick) : undefined
}

// ── verb + resource resolution ────────────────────────────────────────────────

function verbFor(op: OperationInput, opts: DerivationOptions): string {
  if (op.method === 'GET' && op.isCollection && !opts.listAsRead) return 'list'
  return opts.verbMap[op.method] ?? DEFAULT_VERB_MAP[op.method] ?? 'access'
}

function resourceFor(op: OperationInput, opts: DerivationOptions): { resource?: string; source: PermSource } {
  const order: ResourceFrom[] = [opts.resourceFrom, 'tag', 'path', 'operationId'].filter(
    (v, i, a) => a.indexOf(v) === i,
  ) as ResourceFrom[]
  for (const from of order) {
    if (from === 'tag' && op.tags && op.tags[0]) return { resource: slug(op.tags[0]), source: 'tag' }
    if (from === 'path') {
      const r = resourceFromPath(op.routePath)
      if (r) return { resource: r, source: 'path' }
    }
    if (from === 'operationId') {
      const r = resourceFromOperationId(op.operationId)
      if (r) return { resource: r, source: 'operationId' }
    }
  }
  return { source: 'unmapped' }
}

// ── the derivation ─────────────────────────────────────────────────────────────

export function derivePermission(op: OperationInput, opts: DerivationOptions): DerivedPermission {
  const ext = op.extensions ?? {}

  if (opts.honorExtension && ext[PUBLIC_EXTENSION] === true) {
    return { public: true, source: 'public-extension' }
  }
  if (opts.honorExtension && typeof ext[PERMISSION_EXTENSION] === 'string' && (ext[PERMISSION_EXTENSION] as string).trim()) {
    return { permission: (ext[PERMISSION_EXTENSION] as string).trim(), public: false, source: 'extension' }
  }
  if (opts.scopeMap && op.security) {
    for (const req of op.security) {
      for (const scopes of Object.values(req)) {
        for (const scope of scopes) {
          if (opts.scopeMap[scope]) return { permission: opts.scopeMap[scope], public: false, source: 'scope' }
        }
      }
    }
  }
  const { resource, source } = resourceFor(op, opts)
  if (resource) {
    return { permission: `${resource}:${verbFor(op, opts)}`, public: false, source }
  }
  return { public: false, source: 'unmapped' }
}
