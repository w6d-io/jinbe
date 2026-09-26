import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { Site } from './schemas.js'
import { render, stableStringify, type Rendered, type SiteCr } from './render.js'
import { sitesRepository, type SiteDraft, type SiteRecord } from './repository.js'
import { loadPlatform } from './platform.js'
import { kubeSites, type SiteCrObject } from './kube-sites.js'
import { withVersion } from './applies.js'
import { assertNotSystem, siteError } from './checks.js'
import { getRecord } from './sites.service.js'
import type { Actor } from './audit.js'

/**
 * Status and drift (site-ux §10.2): the Site CR's status as the operator reports it, and what
 * differs between what kuma last applied and what is live — the Site CR spec (kubectl edits), its
 * conditions, and the permissions in Redis (route map, roles, groups, org map).
 */

const IMPORTANT = ['Validated', 'RulesSynced', 'RulesLoaded', 'Ready'] as const

export async function siteStatus(name: string) {
  await getRecord(name)
  const cr = await kubeSites().get(name)
  if (!cr) return { exists: false, generation: null, observedGeneration: null, conditions: [], children: [] }
  return {
    exists: true,
    generation: cr.metadata.generation ?? null,
    observedGeneration: cr.status?.observedGeneration ?? null,
    version: Number(cr.metadata.annotations?.['auth.w6d.io/version'] ?? 0) || null,
    conditions: cr.status?.conditions ?? [],
    // The operator reports each child's own hash only; per-child conditions and per-pod loading are
    // not in the Site status (RulesLoaded covers every pod), so they are null/empty here.
    children: (cr.status?.children ?? []).map((c) => ({ kind: c.kind, name: c.name, specHash: c.specHash, expectedHash: null, conditions: [], loadedOn: null })),
  }
}

export interface DriftItem { artefact: string; field: string; expected: unknown; actual: unknown }

const isEmpty = (v: unknown) => v === undefined || v === null || v === false || v === '' || (Array.isArray(v) && v.length === 0) || (typeof v === 'object' && v !== null && Object.keys(v).length === 0)

/** Field paths where `actual` differs from `expected`. Gates are keyed by name; empty extras are defaults, not drift. */
export function specDiff(expected: unknown, actual: unknown, path: string): Array<{ field: string; expected: unknown; actual: unknown }> {
  if (stableStringify(expected) === stableStringify(actual)) return []
  const named = (v: unknown) => Array.isArray(v) && v.every((x) => x && typeof x === 'object' && typeof (x as { name?: unknown }).name === 'string')
  if (named(expected) && named(actual)) {
    const e = new Map((expected as Array<{ name: string }>).map((x) => [x.name, x]))
    const a = new Map((actual as Array<{ name: string }>).map((x) => [x.name, x]))
    return [...new Set([...e.keys(), ...a.keys()])].flatMap((k) => specDiff(e.get(k), a.get(k), `${path}[${k}]`))
  }
  const obj = (v: unknown) => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (obj(expected) && obj(actual)) {
    const e = expected as Record<string, unknown>
    const a = actual as Record<string, unknown>
    return [...new Set([...Object.keys(e), ...Object.keys(a)])]
      .filter((k) => !(e[k] === undefined && isEmpty(a[k])))
      .flatMap((k) => specDiff(e[k], a[k], `${path}.${k}`))
  }
  if (expected === undefined && isEmpty(actual)) return []
  return [{ field: path, expected, actual }]
}

/** What kuma applied, rendered as it would be written now (with the current run state). */
export async function expectedOf(record: SiteRecord): Promise<{ site: Site; rendered: Rendered; cr: SiteCr } | null> {
  if (!record.applied) return null
  const v = await sitesRepository.version(record.site.name, record.applied.version)
  if (!v) return null
  const site = { ...v.site, state: record.site.state }
  const rendered = render(site, await loadPlatform())
  return { site, rendered, cr: withVersion(rendered.siteCr, record.applied.version) }
}

function crItems(name: string, expected: SiteCr, cr: SiteCrObject | null): DriftItem[] {
  const artefact = `Site/${name}`
  if (!cr) return [{ artefact, field: '*', expected: 'present', actual: 'missing' }]
  const items: DriftItem[] = specDiff(expected.spec, cr.spec, 'spec').map((d) => ({ artefact, ...d }))
  for (const type of IMPORTANT) {
    const c = cr.status?.conditions?.find((x) => x.type === type)
    if (c && c.status !== 'True') items.push({ artefact, field: `status.conditions.${type}`, expected: 'True', actual: `${c.status}${c.reason ? ` (${c.reason})` : ''}${c.message ? `: ${c.message}` : ''}` })
  }
  return items
}

async function permissionItems(name: string, rendered: Rendered): Promise<DriftItem[]> {
  const items: DriftItem[] = []
  const same = (a: unknown, b: unknown) => stableStringify(a ?? null) === stableStringify(b ?? null)
  const routeMap = (await redisRbacRepository.getRouteMap(name))?.rules ?? []
  if (!same(routeMap, rendered.routeMap)) items.push({ artefact: `route_map/${name}`, field: 'rules', expected: rendered.routeMap, actual: routeMap })
  const roles = (await redisRbacRepository.getRoles(name)) ?? {}
  if (!same(roles, rendered.roles)) items.push({ artefact: `roles/${name}`, field: '*', expected: rendered.roles, actual: roles })
  const groups = await redisRbacRepository.getGroups()
  const wanted = { ...rendered.groups.platform, ...rendered.groups.orgGrantable }
  for (const [g, def] of Object.entries(wanted)) {
    if (!same(groups[g]?.[name], def[name])) items.push({ artefact: `group/${g}`, field: name, expected: def[name], actual: groups[g]?.[name] ?? null })
  }
  for (const [g, def] of Object.entries(groups)) {
    if (!wanted[g] && name in def) items.push({ artefact: `group/${g}`, field: name, expected: null, actual: def[name] })
  }
  const orgMap = await redisRbacRepository.getOrgServiceMap()
  const liveOrgs = Object.entries(orgMap).filter(([, svcs]) => svcs.includes(name)).map(([o]) => o).sort()
  const wantedOrgs = Object.keys(rendered.orgServiceMap).sort()
  if (!same(liveOrgs, wantedOrgs)) items.push({ artefact: 'org_service_map', field: name, expected: wantedOrgs, actual: liveOrgs })
  return items
}

export async function drift(name: string) {
  const record = await getRecord(name)
  const expected = await expectedOf(record)
  if (!expected) return { appliedVersion: null, checkedAt: new Date().toISOString(), items: [] as DriftItem[] }
  const cr = await kubeSites().get(name)
  const items = [...crItems(name, expected.cr, cr), ...(await permissionItems(name, expected.rendered))]
  return { appliedVersion: record.applied!.version, checkedAt: new Date().toISOString(), items }
}

/**
 * "Accept into the site": fold what is live into a draft (based on the applied version) for review.
 * Only what the intent can hold is folded — upstream, run state, roles, platform groups, orgs; a
 * rendered rule edited by hand (match, handlers) has no place in the intent and is listed instead.
 */
export async function acceptDrift(name: string, actor: Actor): Promise<{ draft: SiteDraft; folded: string[]; notFolded: string[] }> {
  assertNotSystem(name)
  const record = await getRecord(name)
  const expected = await expectedOf(record)
  if (!expected) throw siteError(409, 'not_applied', 'Nothing was applied, so nothing can drift')
  const cr = await kubeSites().get(name)
  const site: Site = structuredClone(expected.site)
  const folded: string[] = []
  const notFolded: string[] = []

  if (cr) {
    for (const d of specDiff(expected.cr.spec, cr.spec, 'spec')) {
      if (d.field.startsWith('spec.upstream.')) continue
      if (d.field === 'spec.paused') {
        site.state = cr.spec.paused ? 'paused' : 'active'
        folded.push('state')
      } else notFolded.push(d.field)
    }
    const u = cr.spec.upstream
    const upstream = { service: u.service, namespace: u.namespace, port: u.port, ...(u.scheme ? { scheme: u.scheme } : {}), ...(u.preserveHost ? { preserveHost: true } : {}), ...(u.stripPath ? { stripPath: u.stripPath } : {}) }
    if (specDiff(expected.cr.spec.upstream, u, 'u').length > 0) {
      site.upstream = upstream
      folded.push('upstream')
    }
  }

  const roles = await redisRbacRepository.getRoles(name)
  if (roles && stableStringify(roles) !== stableStringify(expected.rendered.roles)) {
    site.roles = roles
    folded.push('roles')
  }
  const groups = await redisRbacRepository.getGroups()
  const platform = Object.fromEntries(Object.entries(groups).filter(([g, def]) => name in def && !site.groups.orgGrantable[g]).map(([g, def]) => [g, def[name]]))
  if (stableStringify(platform) !== stableStringify(site.groups.platform)) {
    site.groups = { ...site.groups, platform }
    folded.push('groups.platform')
  }
  const orgMap = await redisRbacRepository.getOrgServiceMap()
  const orgs = Object.entries(orgMap).filter(([, svcs]) => svcs.includes(name)).map(([o]) => o)
  if (stableStringify([...orgs].sort()) !== stableStringify([...site.orgs].sort())) {
    site.orgs = orgs
    folded.push('orgs')
  }
  const routeMap = (await redisRbacRepository.getRouteMap(name))?.rules ?? []
  if (stableStringify(routeMap) !== stableStringify(expected.rendered.routeMap)) notFolded.push('route_map')

  const draft = await sitesRepository.putDraft(name, { site, baseVersion: record.applied!.version, updatedBy: actor.email ?? 'unknown' })
  return { draft, folded, notFolded }
}
