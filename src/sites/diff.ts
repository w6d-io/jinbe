import type { Rendered } from './render.js'
import type { Site } from './schemas.js'
import { stableStringify } from './render.js'

/**
 * What a change does, for the Review screen: per-artefact before/after with changed fields, and the
 * risk flags that make a reviewer look twice. Pure.
 */

export interface FieldChange { path: string; before: unknown; after: unknown }
export interface ArtefactDiff { kind: string; id: string; before: unknown; after: unknown; fields: FieldChange[] }
export interface Risk { level: 'low' | 'medium' | 'high'; flags: Array<{ code: string; level: 'low' | 'medium' | 'high'; message: string }> }

export function fieldChanges(before: unknown, after: unknown, path = ''): FieldChange[] {
  if (stableStringify(before) === stableStringify(after)) return []
  const isObj = (v: unknown) => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (isObj(before) && isObj(after)) {
    const b = before as Record<string, unknown>
    const a = after as Record<string, unknown>
    return [...new Set([...Object.keys(b), ...Object.keys(a)])].sort().flatMap((k) => fieldChanges(b[k], a[k], path ? `${path}.${k}` : k))
  }
  return [{ path: path || '.', before, after }]
}

type Artefacts = Pick<Rendered, 'routeMap' | 'roles' | 'groups' | 'orgServiceMap' | 'rules'>

export function diffArtefacts(name: string, before: Artefacts | null, after: Artefacts): ArtefactDiff[] {
  const byId = (rules: Artefacts['rules']) => Object.fromEntries(rules.map((r) => [r.id, r]))
  const pairs: Array<[string, unknown, unknown]> = [
    ['routeMap', before?.routeMap ?? null, after.routeMap],
    ['roles', before?.roles ?? null, after.roles],
    ['groups', before?.groups ?? null, after.groups],
    ['orgServiceMap', before?.orgServiceMap ?? null, after.orgServiceMap],
    ['rules', before ? byId(before.rules) : null, byId(after.rules)],
  ]
  return pairs
    .map(([kind, b, a]) => ({ kind, id: name, before: b, after: a, fields: fieldChanges(b, a) }))
    .filter((d) => d.fields.length > 0)
}

const rank = { low: 0, medium: 1, high: 2 } as const

export function riskOf(before: Site | null, after: Site): Risk {
  const flags: Risk['flags'] = []
  const flag = (code: string, level: 'low' | 'medium' | 'high', message: string) => flags.push({ code, level, message })
  const routes = (s: Site | null) => new Map((s?.routes.items ?? []).map((r) => [r.id, r]))
  const b = routes(before)
  const a = routes(after)

  if (!before) flag('new_site', 'medium', `a new site on ${after.address.host}`)
  if (before && before.address.host !== after.address.host) flag('host_changed', 'high', `the host moves from ${before.address.host} to ${after.address.host}`)
  if (after.routes.catchAll.access.kind === 'public' && before?.routes.catchAll.access.kind !== 'public') {
    flag('opened_to_public', 'high', 'every unlisted path becomes open to anyone')
  }
  for (const [id, route] of a) {
    const old = b.get(id)
    if (route.access.kind === 'public' && old?.access.kind !== 'public') flag('opened_to_public', 'high', `${route.path} becomes public`)
    if (old?.access.kind === 'permission' && route.access.kind !== 'permission' && route.access.kind !== 'deny') {
      flag('permission_removed', 'high', `${route.path} no longer needs ${old.access.permission}`)
    }
    if (old?.orgParam && !route.orgParam) flag('org_scope_removed', 'high', `${route.path} is no longer limited to one organization`)
  }
  for (const [id, route] of b) if (!a.has(id)) flag('route_removed', 'low', `${route.path} is removed`)

  const star = (s: Site | null) => {
    if (!s) return new Set<string>()
    const roles = typeof s.roles === 'string' ? (s.roles === 'readonly' ? {} : { admin: ['*'] }) : s.roles
    return new Set(Object.entries(s.groups.platform).filter(([, rs]) => rs.some((r) => roles[r]?.includes('*'))).map(([g]) => g))
  }
  const starBefore = star(before)
  for (const g of star(after)) if (!starBefore.has(g)) flag('grants_everything', 'high', `group ${g} gets every permission on the site`)

  const gates = (s: Site | null) => new Map((s?.gates ?? []).map((g) => [g.id, stableStringify(g.authenticators)]))
  const gb = gates(before)
  for (const [id, authn] of gates(after)) {
    if (gb.has(id) && gb.get(id) !== authn) flag('sign_in_changed', 'medium', `gate ${id} changes how callers sign in`)
  }
  if (after.state === 'paused' && before?.state !== 'paused') flag('paused', 'medium', 'the site stops answering')

  const level = flags.reduce<Risk['level']>((m, f) => (rank[f.level] > rank[m] ? f.level : m), 'low')
  return { level, flags }
}
