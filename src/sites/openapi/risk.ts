import { routeSpecificity } from '../../policy/route-ties.js'
import { pathsOverlap } from '../patterns.js'
import type { Route } from '../schemas.js'

/**
 * Risk of each imported route and of the import as a whole (openapi-import.md §3). Pure: the rows
 * are judged on what the draft would hold after the import, against what it held before.
 *
 *   high   — public write, public admin-looking path, public wildcard, access lowered on the spec's
 *            word, permission or org scope removed, a tie with another site, > 20 routes opened.
 *   medium — permission no role grants, signed-in write, broadened template, parameter-only path,
 *            same-rank overlap inside the site, deprecated operation still allowed.
 *   low    — a new permission-gated route.
 */

export type Level = 'low' | 'medium' | 'high'
export interface RiskFlag { code: string; level: Level; message: string }

const READS = new Set(['GET', 'HEAD', 'OPTIONS'])
const SENSITIVE = new Set(['admin', 'internal', 'debug', 'actuator', 'metrics', 'env', 'config', 'backup', 'export', 'graphql', 'swagger'])
export const BULK_PUBLIC = 20

/** Who can be handed a permission: every non-`*` grant of the site's roles (`res:*` covers `res:verb`). */
export function grantedBy(roles: Record<string, string[]>): (permission: string) => boolean {
  const grants = Object.values(roles).flat().filter((p) => p !== '*')
  return (permission) => grants.some((g) => g === permission || (g.endsWith(':*') && permission.startsWith(g.slice(0, -1))))
}

export const sensitivePath = (path: string) => path.split('/').some((s) => SENSITIVE.has(s.toLowerCase()) || (s.startsWith('_') && s.length > 1))

export interface RowContext {
  before?: Route
  broadened: boolean
  deprecated: boolean
  /** The access came from a spec suggestion a human confirmed. */
  fromSpec: boolean
  granted: (permission: string) => boolean
}

export function routeRisks(route: Route, ctx: RowContext): RiskFlag[] {
  const flags: RiskFlag[] = []
  const flag = (code: string, level: Level, message: string) => flags.push({ code, level, message })
  const where = `${route.methods.join(',')} ${route.path}`
  const access = route.access
  const writes = route.methods.some((m) => !READS.has(m))
  if (access.kind === 'public') {
    if (writes) flag('public_write', 'high', `${where} lets anyone write`)
    if (sensitivePath(route.path)) flag('public_sensitive_path', 'high', `${where} looks administrative and becomes public`)
    if (route.path.endsWith(':any*')) flag('public_wildcard', 'high', `everything under ${route.path.slice(0, -6) || '/'} becomes public`)
  }
  if (ctx.fromSpec && (access.kind === 'public' || access.kind === 'signed-in')) flag('spec_lowers_protection', 'high', `${where} is ${access.kind} because the spec says so`)
  const old = ctx.before
  if (old?.access.kind === 'permission' && access.kind !== 'permission' && access.kind !== 'deny') flag('permission_removed', 'high', `${where} no longer needs ${old.access.permission}`)
  if (old?.orgParam && !route.orgParam) flag('org_scope_removed', 'high', `${where} is no longer limited to one organization`)
  if (access.kind === 'permission' && !ctx.granted(access.permission)) flag('permission_not_granted', 'medium', `no role of the site grants ${access.permission} (only "everything" roles get in)`)
  if (access.kind === 'signed-in' && writes) flag('signed_in_write', 'medium', `${where} lets any signed-in account write`)
  if (ctx.broadened) flag('broadened', 'medium', `${where} matches more than the spec's template`)
  if (route.path.split('/').filter(Boolean).every((s) => s.startsWith(':'))) flag('param_only_path', 'medium', `${where} is made only of parameters`)
  if (ctx.deprecated && access.kind !== 'deny') flag('deprecated_allowed', 'medium', `${where} is deprecated but stays reachable`)
  if (!old && access.kind === 'permission') flag('new_route', 'low', `${where} needs ${access.permission}`)
  return flags
}

/**
 * Same-method routes of the site that overlap at the same rank (the policy's `route_specificity`):
 * which one answers is then not what the author meant. Bucketed by method and depth, so 2 000 routes
 * are not 4 million comparisons.
 */
export function sameRankOverlaps(routes: readonly Route[]): Map<string, string> {
  const out = new Map<string, string>()
  const buckets = new Map<string, Route[]>()
  for (const r of routes) {
    if (r.access.kind === 'deny') continue
    for (const m of r.methods) {
      const key = `${m} ${r.path.includes(':any*') ? '*' : r.path.split('/').length} ${routeSpecificity(r.path)}`
      const bucket = buckets.get(key)
      if (bucket) bucket.push(r)
      else buckets.set(key, [r])
    }
  }
  for (const group of buckets.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        if (group[i].path !== group[j].path && pathsOverlap(group[i].path, group[j].path)) {
          out.set(group[i].id, group[j].path)
          out.set(group[j].id, group[i].path)
        }
      }
    }
  }
  return out
}

const rank: Record<Level, number> = { low: 0, medium: 1, high: 2 }
export const maxLevel = (flags: readonly RiskFlag[]): Level => flags.reduce<Level>((m, f) => (rank[f.level] > rank[m] ? f.level : m), 'low')
