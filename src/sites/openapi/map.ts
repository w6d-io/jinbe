import { derivePermission, DEFAULT_VERB_MAP, type ResourceFrom } from '../../services/openapi-import/derivation.js'
import type { Access } from '../schemas.js'
import type { ParsedSpec, SpecOperation } from './extract.js'
import { joinPaths, toRoutePath } from './path.js'

/**
 * One spec operation → the route the import proposes for it (site-ux §6.3, openapi-import.md §2).
 *
 * The spec is written by the upstream team, i.e. untrusted: its extensions are proposals. What it
 * may set directly is only what adds protection (a permission, deny, an org parameter, 2FA). What
 * would lower it — `public`, `signed-in`, `security: []`, another gate — is returned as a
 * `suggestion` that a human must confirm, and the proposal stays fail-closed. No security anywhere
 * means a derived permission, else deny: never public, never merely signed-in.
 *
 * Precedence: human decision (plan.ts) > x-w6d-* > scopeMap > derivation > deny (unmapped).
 */

export interface ImportOptions {
  /** Literal base path to use instead of the spec's first server path / basePath ('' = none). */
  basePath?: string
  basePathMode: 'prepend' | 'strip' | 'none'
  resourceFrom: ResourceFrom
  listAsRead: boolean
  /** OAuth scope → permission. */
  scopeMap?: Record<string, string>
  /** The path parameter carrying the organization, when the spec's names are not the usual ones. */
  orgParam?: string
  /** Gate of the imported routes (default: the catch-all gate — no gateway rule growth). */
  defaultGate?: string
}

export type ProposalSource = 'extension' | 'scope' | 'derived' | 'spec-default' | 'unmapped' | 'deprecated'

export interface Suggestion {
  access?: Access
  gate?: string
  twoFactor?: boolean
  from: string
  needsConfirm: true
}

export type Proposal =
  | { ok: false; op: SpecOperation; status: 'skipped' | 'unsupported'; reason: string }
  | {
      ok: true
      op: SpecOperation
      path: string
      params: string[]
      broadened: boolean
      access: Access
      source: ProposalSource
      orgParam?: string
      twoFactor?: boolean
      routeId?: string
      suggestion?: Suggestion
      reasons: string[]
    }

const PERMISSION = /^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/
const ROUTE_ID = /^[a-z][a-z0-9-]{0,31}$/
const ORG_PARAM = /^(org|organi[sz]ation|tenant)_?(id|uuid)?$/i

export const validPermission = (p: unknown): p is string => typeof p === 'string' && p.length <= 128 && PERMISSION.test(p)

/** The base path the routes are placed under: the explicit option, else the spec's first. */
export const basePathOf = (spec: ParsedSpec, options: ImportOptions) => options.basePath ?? spec.basePaths[0] ?? ''

function placed(specRoute: string, base: string, mode: ImportOptions['basePathMode']): string {
  if (!base || mode === 'none') return specRoute
  if (mode === 'strip') return specRoute === base ? '/' : specRoute.startsWith(`${base}/`) ? specRoute.slice(base.length) : specRoute
  return joinPaths(base, specRoute)
}

/** Whether the spec lets callers in without credentials: `security: []`, or an empty `{}` alternative. */
const anonymousAllowed = (op: SpecOperation) => op.securityFrom !== 'none' && (op.security!.length === 0 || op.security!.some((r) => Object.keys(r).length === 0))

function scoped(op: SpecOperation, scopeMap: Record<string, string> | undefined): string | undefined {
  if (!scopeMap || !op.security) return undefined
  for (const req of op.security) for (const scopes of Object.values(req)) for (const s of scopes) if (Object.hasOwn(scopeMap, s)) return scopeMap[s]
  return undefined
}

export function propose(op: SpecOperation, spec: ParsedSpec, options: ImportOptions, prefix: string | undefined): Proposal {
  const ext = op.ext
  if (ext['x-w6d-skip'] === true) return { ok: false, op, status: 'skipped', reason: 'x-w6d-skip' }
  const converted = toRoutePath(op.path)
  if (!converted.ok) return { ok: false, op, status: 'unsupported', reason: converted.reason }
  const path = placed(converted.path, basePathOf(spec, options), options.basePathMode)
  if (path.length > 512) return { ok: false, op, status: 'unsupported', reason: 'longer than 512 characters with its base path' }
  if (prefix && path !== prefix && !path.startsWith(`${prefix}/`)) {
    return { ok: false, op, status: 'unsupported', reason: `${path} is outside the site prefix ${prefix}; set the base path` }
  }
  const reasons: string[] = []
  if (converted.broadened) reasons.push('a partial template became a whole-segment parameter')

  // ── access: only what adds protection is taken from the spec ──
  const rawAccess = ext['x-w6d-access']
  const extAccess = typeof rawAccess === 'string' ? rawAccess : ext['x-rbac-public'] === true ? 'public' : undefined
  const extPermission = [(rawAccess as { permission?: unknown } | undefined)?.permission, ext['x-w6d-permission'], ext['x-rbac-permission']].find((p) => p !== undefined)
  if (extPermission !== undefined && !validPermission(extPermission)) reasons.push('the permission named by the spec is not a resource:verb permission; ignored')
  let access: Access | undefined
  let source: ProposalSource = 'unmapped'
  const mapped = scoped(op, options.scopeMap)
  if (extAccess === 'deny') [access, source] = [{ kind: 'deny' }, 'extension']
  else if (validPermission(extPermission)) [access, source] = [{ kind: 'permission', permission: extPermission }, 'extension']
  else if (validPermission(mapped)) [access, source] = [{ kind: 'permission', permission: mapped }, 'scope']
  else if (spec.root.defaultAccess === 'deny') [access, source] = [{ kind: 'deny' }, 'spec-default']
  else {
    const derived = derivePermission(
      { method: op.method, routePath: path, operationId: op.operationId, tags: spec.root.resource ? [spec.root.resource] : op.tags, isCollection: !(path.split('/').at(-1) ?? '').startsWith(':') },
      { resourceFrom: spec.root.resource ? 'tag' : options.resourceFrom, verbMap: DEFAULT_VERB_MAP, listAsRead: options.listAsRead, honorExtension: false },
    )
    if (validPermission(derived.permission)) [access, source] = [{ kind: 'permission', permission: derived.permission }, 'derived']
  }
  if (!access) {
    access = { kind: 'deny' }
    reasons.push('no permission could be derived: denied until you decide')
  }
  if (op.deprecated && access.kind !== 'deny') {
    reasons.push(`deprecated: denied (the spec's access would be ${access.kind === 'permission' ? access.permission : access.kind})`)
    ;[access, source] = [{ kind: 'deny' }, 'deprecated']
  }

  // ── what would lower protection: suggestions, never applied ──
  let suggestion: Suggestion | undefined
  if (extAccess === 'public' || extAccess === 'signed-in') {
    suggestion = { access: { kind: extAccess }, from: typeof rawAccess === 'string' ? 'x-w6d-access' : 'x-rbac-public', needsConfirm: true }
  } else if (anonymousAllowed(op)) {
    suggestion = { access: { kind: 'public' }, from: 'security: []', needsConfirm: true }
  } else if (extAccess !== undefined && extAccess !== 'deny') reasons.push(`x-w6d-access '${String(extAccess).slice(0, 40)}' is not public | signed-in | deny | {permission}; ignored`)
  const gate = ext['x-w6d-gate']
  if (typeof gate === 'string' && gate !== options.defaultGate) suggestion = { ...(suggestion ?? { from: 'x-w6d-gate', needsConfirm: true }), gate }

  // ── additions the spec may make directly ──
  const named = [ext['x-w6d-org-param'], options.orgParam].find((p) => typeof p === 'string' && converted.params.includes(p)) as string | undefined
  const guessed = converted.params.filter((p) => ORG_PARAM.test(p))
  const orgParam = named ?? (guessed.length === 1 ? guessed[0] : undefined)
  if (orgParam && !named) reasons.push(`'${orgParam}' looks like the organization parameter`)
  const routeId = typeof ext['x-w6d-route-id'] === 'string' && ROUTE_ID.test(ext['x-w6d-route-id']) ? ext['x-w6d-route-id'] : undefined

  return {
    ok: true, op, path, params: converted.params, broadened: converted.broadened, access, source,
    ...(orgParam ? { orgParam } : {}),
    ...(ext['x-w6d-2fa'] === true ? { twoFactor: true } : {}),
    ...(routeId ? { routeId } : {}),
    ...(suggestion ? { suggestion } : {}),
    reasons,
  }
}

/** Lowercase, dash-separated, starting with a letter, at most 32 characters: a route id. */
export function slugId(raw: string): string {
  const s = raw.slice(0, 128).replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  const lettered = /^[a-z]/.test(s) ? s : `op-${s}`
  return lettered.slice(0, 32).replace(/-+$/, '') || 'op'
}

