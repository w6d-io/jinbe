import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { routeSpecificity } from '../policy/route-ties.js'
import type { RouteRule } from '../services/redis-rbac.repository.js'
import { siteSchema, type Site } from './schemas.js'
import { render, type Rendered } from './render.js'
import { sitesRepository, type SiteRecord, type SiteDraft } from './repository.js'
import { sitesConfig } from './config.js'
import { loadPlatform, loadZones } from './platform.js'
import { assertNotSystem, contextChecks, errorsOf, gatekitChecks, hostOwner, liveRules, siteError } from './checks.js'
import { diffArtefacts, riskOf } from './diff.js'
import { gatekit, type RenderSample } from './gatekit.client.js'
import { placeHost, zonesView } from './host.js'
import { auditSite, type Actor } from './audit.js'

/**
 * Reading and editing Sites: list, get, drafts, preview, diff, save, and the editor's helpers
 * (check-host, match, render). Nothing here reaches the gateway — apply.service.ts does.
 */

export type SiteStatus = 'draft' | 'live' | 'attention' | 'paused'

export function statusOf(r: SiteRecord): SiteStatus {
  if (r.site.state === 'paused') return 'paused'
  if (!r.applied) return 'draft'
  return r.applied.version === r.version ? 'live' : 'attention'
}

export async function listSites() {
  const records = await sitesRepository.list()
  return Promise.all(records.map(async (r) => {
    const draft = await sitesRepository.getDraft(r.site.name)
    return {
      name: r.site.name,
      displayName: r.site.displayName,
      host: r.site.address.host,
      status: statusOf(r),
      version: r.version,
      appliedVersion: r.applied?.version ?? null,
      appliedAt: r.applied?.at ?? null,
      appliedBy: r.applied?.by ?? null,
      orgs: r.site.orgs.length,
      ...(draft ? { draft: { by: draft.updatedBy, at: draft.updatedAt } } : {}),
    }
  }))
}

export async function getRecord(name: string): Promise<SiteRecord> {
  const record = await sitesRepository.get(name)
  if (!record) throw siteError(404, 'not_found', `Site not found: ${name}`)
  return record
}

export async function getSite(name: string) {
  const r = await getRecord(name)
  return { site: r.site, version: r.version, etag: r.etag, status: statusOf(r), savedAt: r.savedAt, savedBy: r.savedBy, applied: r.applied ? { version: r.applied.version, at: r.applied.at, by: r.applied.by, rules: r.applied.rules.map((x) => x.id) } : null }
}

// ── drafts ────────────────────────────────────────────────────

export async function getDraft(name: string): Promise<SiteDraft> {
  const draft = await sitesRepository.getDraft(name)
  if (!draft) throw siteError(404, 'not_found', `No draft for ${name}`)
  return draft
}

export async function putDraft(name: string, body: { site?: unknown; baseVersion?: number }, actor: Actor): Promise<SiteDraft> {
  assertNotSystem(name)
  // A draft may be incomplete — it is autosaved while typing — but it must be about this site.
  const site = body.site as { name?: unknown } | null
  if (!site || typeof site !== 'object' || Array.isArray(site)) throw siteError(400, 'invalid_draft', 'draft.site must be an object')
  if (site.name !== undefined && site.name !== name) throw siteError(400, 'name_mismatch', `draft names '${String(site.name)}', not '${name}'`)
  if (JSON.stringify(site).length > 256 * 1024) throw siteError(413, 'draft_too_large', 'draft exceeds 256 KiB')
  const current = await sitesRepository.get(name)
  return sitesRepository.putDraft(name, { site, baseVersion: body.baseVersion ?? current?.version ?? 0, updatedBy: actor.email ?? 'unknown' })
}

export async function deleteDraft(name: string): Promise<void> {
  assertNotSystem(name)
  await sitesRepository.deleteDraft(name)
}

// ── preview, diff, save ───────────────────────────────────────

/** The render of the version the gateway has now, or null when nothing was applied. */
export async function appliedRender(record: SiteRecord | null): Promise<{ site: Site; rendered: Rendered } | null> {
  if (!record?.applied) return null
  const v = await sitesRepository.version(record.site.name, record.applied.version)
  if (!v) return null
  return { site: v.site, rendered: render(v.site, await loadPlatform()) }
}

export async function preview(site: Site) {
  assertNotSystem(site.name)
  const records = await sitesRepository.list()
  const rendered = render(site, await loadPlatform())
  // gatekit first: when it cannot answer there is no preview at all (no JS approximation).
  const gk = await gatekitChecks(site, rendered, records)
  const ctx = await contextChecks(site, rendered, records)
  const before = await appliedRender(records.find((r) => r.site.name === site.name) ?? null)
  const risk = riskOf(before?.site ?? null, site)
  const { checks, ...artefacts } = rendered
  return { artefacts, checks: [...checks, ...ctx, ...gk], risk, words: risk.flags.map((f) => f.message) }
}

export async function diff(name: string, candidate?: Site) {
  const record = await sitesRepository.get(name)
  let site = candidate
  if (!site) {
    const draft = await sitesRepository.getDraft(name)
    const parsed = draft ? siteSchema.safeParse(draft.site) : null
    site = parsed?.success ? parsed.data : record?.site
  }
  if (!site) throw siteError(404, 'not_found', `Site not found: ${name}`)
  if (site.name !== name) throw siteError(400, 'name_mismatch', `body names '${site.name}', not '${name}'`)
  const before = await appliedRender(record)
  const after = render(site, await loadPlatform())
  const risk = riskOf(before?.site ?? null, site)
  return { artefacts: diffArtefacts(name, before?.rendered ?? null, after), risk, words: risk.flags.map((f) => f.message) }
}

export async function save(name: string, site: Site, opts: { note?: string; ifMatch?: string; actor: Actor; kind?: 'save' | 'rollback' }): Promise<SiteRecord> {
  assertNotSystem(name)
  if (site.name !== name) throw siteError(400, 'name_mismatch', `body names '${site.name}', not '${name}'`)
  const rendered = render(site, await loadPlatform())
  const errors = errorsOf(rendered.checks)
  if (errors.length > 0) throw siteError(422, 'invalid_site', 'This version cannot be saved as it is', rendered.checks)
  const current = await sitesRepository.get(name)
  if (!current?.applied && (await redisRbacRepository.serviceExists(name))) {
    throw siteError(409, 'service_exists', `'${name}' is already a service not managed as a site; adopt it through the migration instead`)
  }
  const record = await sitesRepository.save(site, { by: opts.actor.email ?? 'unknown', note: opts.note, ifMatch: opts.ifMatch, kind: opts.kind })
  await sitesRepository.deleteDraft(name)
  auditSite('update', name, opts.actor, `saved version ${record.version}`, { version: record.version, kind: opts.kind ?? 'save' })
  return record
}

export async function versions(name: string) {
  await getRecord(name)
  return (await sitesRepository.versions(name)).map(({ site: _site, ...v }) => v)
}

export async function version(name: string, v: number) {
  const entry = await sitesRepository.version(name, v)
  if (!entry) throw siteError(404, 'not_found', `No version ${v} of ${name}`)
  return entry
}

// ── editor helpers ────────────────────────────────────────────

/** Resolve a host against the admin-defined zones: which zone, SSO coverage, which exposures, who owns it. */
export async function checkHost(body: { host: string; pathPrefix?: string; site?: string }) {
  const cfg = sitesConfig()
  const placement = placeHost(body.host, await loadZones(), cfg.SITES_COOKIE_DOMAIN)
  const reserved = cfg.SITES_RESERVED_HOSTS.includes(body.host)
  const records = await sitesRepository.list()
  const { owner, sharedWith } = hostOwner(body.host, body.pathPrefix, body.site, records)
  const legacy = (await redisRbacRepository.getAccessRules()).some((r) => r.match.url.includes(`://${body.host}/`) || r.match.url.includes(`://${body.host}<`))
  const checks = [
    ...(placement.tooDeep ? [{ level: 'error', code: 'host_too_deep', message: 'A site host must be exactly one label under a zone' }] : []),
    ...(placement.zone || placement.tooDeep ? [] : [{ level: 'error', code: 'host_outside_zones', message: 'No zone covers this host; sites are mapped under the configured wildcard zones only' }]),
    ...(reserved ? [{ level: 'error', code: 'host_reserved', message: 'This is a platform host' }] : []),
    ...(owner ? [{ level: 'error', code: 'host_taken', message: `Already served by site '${owner}'` }] : []),
    ...(legacy ? [{ level: 'warn', code: 'legacy_rules', message: 'Legacy gateway rules already serve this host; overlaps are checked at preview' }] : []),
    ...(placement.zone && !placement.sso ? [{ level: 'warn', code: 'no_sso', message: 'The login cookie does not reach this zone; browser sign-in will not work there' }] : []),
  ]
  return {
    available: !!placement.zone && !reserved && !owner,
    ...(owner ? { owner } : {}),
    sharedWith,
    zone: placement.zone,
    sso: placement.sso,
    cookieDomain: placement.cookieDomain,
    modes: placement.modes,
    tls: placement.tls,
    reserved,
    checks,
  }
}

export async function zones() {
  return zonesView(await loadZones(), sitesConfig().SITES_COOKIE_DOMAIN)
}

/** Best route-map row for a path, by the policy's specificity (rbac.rego `route_specificity`). */
function bestRoute(rows: RouteRule[], method: string, path: string): RouteRule | undefined {
  const matches = (pattern: string) => {
    const p = pattern.split('/')
    const u = path.split('/')
    if (p.at(-1) === ':any*') {
      const fixed = p.slice(0, -1)
      const trimmed = fixed.at(-1) === '' ? fixed.slice(0, -1) : fixed
      return u.length >= trimmed.length && trimmed.every((s, i) => s.startsWith(':') || s === u[i])
    }
    return p.length === u.length && p.every((s, i) => s.startsWith(':') || s === u[i])
  }
  return rows
    .filter((r) => r.method === method && matches(r.path))
    .sort((a, b) => routeSpecificity(b.path) - routeSpecificity(a.path))[0]
}

export async function match(body: { method: string; url: string; against: 'draft' | 'live'; site?: Site }) {
  const records = await sitesRepository.list()
  const url = new URL(body.url)
  const host = url.hostname.toLowerCase()
  const draft = body.against === 'draft' && body.site ? body.site : null
  const platform = await loadPlatform()
  const rules = [...(await liveRules(draft?.name, records)), ...(draft ? render(draft, platform).rules : [])]
  const result = await gatekit.match(rules, body.method, body.url)
  const site = draft && draft.address.host === host ? draft : records.find((r) => r.site.address.host === host)?.site
  const rows = site ? (draft === site ? render(site, platform).routeMap : (await redisRbacRepository.getRouteMap(site.name))?.rules ?? render(site, platform).routeMap) : []
  const route = bestRoute(rows, body.method, url.pathname)
  const org = route?.org_param ? url.pathname.split('/')[route.path.split('/').indexOf(`:${route.org_param}`)] : undefined
  return {
    gateway: { rules: result.matched, verdict: result.verdict, ...(result.errors?.length ? { errors: result.errors } : {}) },
    site: site?.name ?? null,
    ...(route ? { route, needs: route.permission ?? 'signed-in' } : { needs: 'no route: refused' }),
    ...(org ? { org } : {}),
  }
}

export async function renderTemplate(body: { template: string; kind: string; name?: string; sample: RenderSample }) {
  return gatekit.render(body)
}

export type { Actor }
