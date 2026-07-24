// Reconcile derived (spec) routes against the service's live route_map.
// Keyed at (method, path) granularity, comparing the permission SET so that a
// route which currently carries several permission rules (OR semantics) is
// reported as "changed" rather than silently collapsed.

import type { RouteRule } from '../redis-rbac.repository.js'
import type { PermSource } from './derivation.js'

export interface DerivedRoute {
  method: string
  path: string
  permission?: string
  public: boolean
  source: PermSource
  operationId?: string
  summary?: string
}

export interface ChangedRoute {
  method: string
  path: string
  from: (string | null)[] // current permission(s); null = public
  to: DerivedRoute
}

export interface StaleRoute {
  method: string
  path: string
  permission?: string
  isCatchall: boolean
}

export interface RouteDiff {
  add: DerivedRoute[]
  changed: ChangedRoute[]
  unchanged: DerivedRoute[]
  stale: StaleRoute[]
}

const mpKey = (method: string, path: string) => `${method.toUpperCase()} ${path}`
const permOf = (r: RouteRule): string | null => (r.permission && r.permission.trim() ? r.permission : null)

export function diffRoutes(derived: DerivedRoute[], current: RouteRule[]): RouteDiff {
  const currentByMP = new Map<string, RouteRule[]>()
  for (const r of current) {
    const k = mpKey(r.method, r.path)
    ;(currentByMP.get(k) ?? currentByMP.set(k, []).get(k)!).push(r)
  }

  const diff: RouteDiff = { add: [], changed: [], unchanged: [], stale: [] }
  const covered = new Set<string>()

  for (const d of derived) {
    const k = mpKey(d.method, d.path)
    const cur = currentByMP.get(k)
    if (!cur) {
      diff.add.push(d)
      continue
    }
    covered.add(k)
    const curPerms = cur.map(permOf)
    const target = d.public ? null : (d.permission ?? null)
    if (curPerms.length === 1 && curPerms[0] === target) {
      diff.unchanged.push(d)
    } else {
      diff.changed.push({ method: d.method, path: d.path, from: curPerms, to: d })
    }
  }

  // Anything in the live map whose (method, path) the spec never mentions is
  // stale — this is exactly where :any* catch-alls surface for removal.
  for (const [k, rules] of currentByMP) {
    if (covered.has(k)) continue
    for (const r of rules) {
      diff.stale.push({
        method: r.method.toUpperCase(),
        path: r.path,
        permission: r.permission,
        isCatchall: r.path.includes(':any*'),
      })
    }
  }

  return diff
}
