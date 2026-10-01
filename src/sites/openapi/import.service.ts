import { getRedisClient } from '../../services/redis-client.service.js'
import { withRedisLock } from '../../services/redis-lock.js'
import { findRouteTies, loadPublishedRouteRules, describeRouteTie } from '../../policy/route-ties.js'
import { expandRoles, render, sha256, type Check } from '../render.js'
import { siteSchema, type Site } from '../schemas.js'
import { sitesRepository } from '../repository.js'
import { sitesConfig } from '../config.js'
import { loadPlatform } from '../platform.js'
import { assertNotSystem, pinnedHostsOf, siteError } from '../checks.js'
import { liveAddresses } from '../address.js'
import { auditSite, type Actor } from '../audit.js'
import { draftMaxBytes } from '../sites.service.js'
import { loadSpec, specSha256 } from './load.js'
import { basePathOf } from './map.js'
import { plan, type BaseSite, type Plan, type Row } from './plan.js'
import { maxLevel } from './risk.js'
import type { ParsedSpec } from './extract.js'
import type { ImportCommitBody, ImportPreviewBody } from './schemas.js'

/**
 * OpenAPI → Site routes (openapi-import.md §3). `preview` reads the spec (bounded worker), keeps its
 * exact bytes and their SHA-256 24 h (one pending upload per site), and answers the plan; it writes
 * nothing else. `commit` re-reads
 * THOSE bytes — the sha the preview answered, never a new upload — re-plans with the human's decisions
 * and writes the DRAFT only: never a saved version, never an apply. Save, four-eyes and apply stay the
 * normal path, with their own checks.
 */

const IMPORT_TTL_SECONDS = 24 * 3600
/**
 * High-risk rows a human must confirm one by one (`confirm: true` in the row's decision), owner
 * decision: public writes, admin-looking public paths, public wildcards, protection lowered on the
 * spec's word, conflicts with another site.
 */
export const CONFIRM_RISKS: ReadonlySet<string> = new Set(['public_write', 'public_sensitive_path', 'public_wildcard', 'spec_lowers_protection', 'route_tie'])

/** Routes on gates other than the catch-all's (deny included) are enumerated in gateway regexes. */
export const MAX_ENUMERATED = 100
// One pending upload per site (the latest preview), so Redis holds at most one spec per site.
const importKey = (name: string) => `rbac:sites:import:${name}`

type Raw = Record<string, unknown>
const isObject = (v: unknown): v is Raw => v !== null && typeof v === 'object' && !Array.isArray(v)

interface Base { raw: Raw; site: BaseSite; full: Site | null; etag: string; from: 'draft' | 'saved'; baseVersion: number }

/** What the import is merged into: the draft when there is one, else the saved intent. */
async function loadBase(name: string): Promise<Base> {
  const [draft, record] = await Promise.all([sitesRepository.getDraft(name), sitesRepository.get(name)])
  const raw = (draft?.site ?? record?.site ?? null) as unknown
  if (!isObject(raw)) throw siteError(404, 'not_found', `No site or draft named ${name}: start the site (address and gates) before importing routes`)
  if (raw.name !== undefined && raw.name !== name) throw siteError(400, 'name_mismatch', `the draft names '${String(raw.name)}', not '${name}'`)
  const routes = isObject(raw.routes) ? raw.routes : {}
  const gates = (Array.isArray(raw.gates) ? raw.gates : []).filter((g): g is Raw => isObject(g) && typeof g.id === 'string')
  const parsed = siteSchema.safeParse(raw)
  const roles = parsed.success ? expandRoles(parsed.data) : isObject(raw.roles) ? (raw.roles as Record<string, string[]>) : {}
  const prefix = isObject(raw.address) && typeof raw.address.pathPrefix === 'string' ? raw.address.pathPrefix : undefined
  return {
    raw,
    full: parsed.success ? parsed.data : null,
    etag: sha256(raw).slice(0, 16),
    from: draft ? 'draft' : 'saved',
    baseVersion: draft?.baseVersion ?? record?.version ?? 0,
    site: {
      prefix,
      gates: gates.map((g) => ({ id: g.id as string, anonymous: Array.isArray(g.authenticators) && g.authenticators.some((a) => isObject(a) && (a.handler === 'anonymous' || a.handler === 'noop')) })),
      catchAllGate: isObject(routes.catchAll) && typeof routes.catchAll.gate === 'string' ? routes.catchAll.gate : undefined,
      items: Array.isArray(routes.items) ? routes.items : [],
      roles: Object.fromEntries(Object.entries(roles).filter(([, v]) => Array.isArray(v))),
      hasLogin: isObject(raw.login) && isObject(raw.login.twoFactor),
    },
  }
}

/** The draft after the import. */
function merged(base: Base, p: Plan, spec: ParsedSpec, sha: string, actor: Actor): Raw {
  const routes = isObject(base.raw.routes) ? base.raw.routes : {}
  const site: Raw = {
    ...base.raw,
    routes: { ...routes, items: p.items, openapi: { sha256: sha, title: spec.title, version: spec.version, source: 'upload', importedAt: new Date().toISOString(), importedBy: actor.email ?? 'unknown' } },
  }
  if (p.twoFactorRoutes.length > 0 && isObject(base.raw.login) && isObject(base.raw.login.twoFactor)) {
    const tf = base.raw.login.twoFactor
    const current = Array.isArray(tf.routes) ? (tf.routes as string[]) : []
    site.login = { ...base.raw.login, twoFactor: { ...tf, routes: [...new Set([...current, ...p.twoFactorRoutes])] } }
  }
  return site
}

const enumerated = (items: unknown[], catchAll: string | undefined) =>
  items.filter((r) => isObject(r) && ((isObject(r.access) && r.access.kind === 'deny') || r.gate !== catchAll)).length

/**
 * The checks that need the whole candidate: render (incl. match_url_too_long) and ties with the
 * routes other sites and services publish. Only when the draft is complete enough to render.
 */
async function candidateChecks(name: string, candidate: Raw, rows: Row[]): Promise<{ checks: Check[]; notes: string[] }> {
  const parsed = siteSchema.safeParse(candidate)
  if (!parsed.success) return { checks: [], notes: [`cross-site checks run once the draft is a complete site (${parsed.error.issues[0]?.path.join('.') || 'site'}: ${parsed.error.issues[0]?.message})`] }
  try {
    const rendered = render(parsed.data, await loadPlatform())
    const records = await sitesRepository.list()
    const ties = findRouteTies(name, rendered.routeMap, await loadPublishedRouteRules(), pinnedHostsOf(records, parsed.data, await liveAddresses(records)))
    const byRoute = new Map(rows.filter((r) => r.route).map((r) => [`${r.route!.methods[0]} ${r.route!.path}`, r]))
    for (const tie of ties) byRoute.get(`${tie.method} ${tie.path}`)?.risk.push({ code: 'route_tie', level: 'high', message: describeRouteTie(tie) })
    return { checks: rendered.checks, notes: [] }
  } catch {
    return { checks: [], notes: ['cross-site checks are unavailable right now; the normal preview runs them before save'] }
  }
}

function rowView(r: Row) {
  return {
    op: r.op, ...(r.operationId ? { operationId: r.operationId } : {}), method: r.method, ...(r.specPath ? { specPath: r.specPath } : {}),
    status: r.status, source: r.source ?? null,
    route: r.route ? { id: r.route.id, path: r.route.path, gate: r.route.gate, access: r.route.access, ...(r.route.orgParam ? { orgParam: r.route.orgParam } : {}), ...(r.route.pinned ? { pinned: true } : {}) } : null,
    current: r.current ? { id: r.current.id, path: r.current.path, gate: r.current.gate, access: r.current.access, ...(r.current.orgParam ? { orgParam: r.current.orgParam } : {}) } : null,
    ...(r.suggestion ? { suggestion: r.suggestion } : {}),
    reasons: r.reasons, risk: r.risk, ...(r.needsConfirm ? { needsConfirm: true } : {}), ...(r.blocking ? { blocking: r.blocking } : {}),
  }
}

async function evaluate(name: string, spec: ParsedSpec, sha: string, body: Pick<ImportCommitBody, 'options' | 'decisions'> & { acceptDenied?: boolean }, actor: Actor) {
  const base = await loadBase(name)
  const p = plan(spec, base.site, body.options, body.decisions, { acceptDenied: body.acceptDenied })
  const candidate = merged(base, p, spec, sha, actor)
  const { checks, notes } = await candidateChecks(name, candidate, p.rows)
  // After candidateChecks: route_tie is only known once the whole candidate is rendered.
  const confirmed = new Set(body.decisions.filter((d) => d.confirm).map((d) => d.op))
  for (const row of p.rows) {
    const risky = row.risk.filter((f) => CONFIRM_RISKS.has(f.code))
    if (risky.length === 0) continue
    row.needsConfirm = true
    // Already refused for the same missing confirm (a lowering decision): said once.
    if (confirmed.has(row.op) || row.blocking?.code === 'confirmation_required') continue
    const message = `${row.op}: confirm this high-risk route (${risky.map((f) => f.code).join(', ')}) with confirm: true`
    if (!row.blocking) row.blocking = { code: 'risk_unconfirmed', message }
    p.blocking.push({ op: row.op, code: 'risk_unconfirmed', message })
  }
  const max = sitesConfig().SITES_MAX_ROUTES
  const catchAll = base.site.catchAllGate
  const caps = { maxRoutes: max, routes: p.items.length, maxEnumerated: MAX_ENUMERATED, enumerated: enumerated(p.items, catchAll), enumeratedBefore: enumerated(base.site.items, catchAll) }
  if (caps.routes > max) p.blocking.push({ op: '*', code: 'too_many_routes', message: `${caps.routes} routes; a site holds at most ${max} (SITES_MAX_ROUTES)` })
  if (caps.enumerated > MAX_ENUMERATED && caps.enumerated > caps.enumeratedBefore) {
    p.blocking.push({ op: '*', code: 'too_many_enumerated_routes', message: `${caps.enumerated} routes off the catch-all gate (deny included); at most ${MAX_ENUMERATED}: keep imported routes on the catch-all gate` })
  }
  const flags = p.rows.flatMap((r) => r.risk).concat(p.risk.flags.filter((f) => f.code === 'bulk_public'))
  const previous = isObject(base.raw.routes) && isObject(base.raw.routes.openapi) ? base.raw.routes.openapi : null
  return { base, p, candidate, checks, notes, caps, risk: { level: maxLevel(flags), flags }, previous }
}

export async function previewImport(name: string, body: ImportPreviewBody, actor: Actor) {
  assertNotSystem(name)
  if (!('content' in body.source)) throw siteError(422, 'url_import_disabled', 'importing a spec by URL is not available yet: paste or upload its content')
  const { content, format } = body.source
  const sha = specSha256(content)
  const spec = await loadSpec(content, format)
  const out = await evaluate(name, spec, sha, body, actor)
  // Kept for the commit, which must re-read these exact bytes.
  await getRedisClient().set(importKey(name), JSON.stringify({ sha256: sha, content, format }), 'EX', IMPORT_TTL_SECONDS)
  return {
    spec: { title: spec.title, version: spec.version, format: spec.format, sha256: sha, counts: spec.counts, basePaths: spec.basePaths, hosts: spec.hosts, securitySchemes: spec.securitySchemes, notes: spec.notes },
    base: { from: out.base.from, etag: out.base.etag, complete: out.base.full !== null },
    options: { ...body.options, basePath: basePathOf(spec, body.options), defaultGate: body.options.defaultGate ?? out.base.site.catchAllGate ?? null },
    previous: out.previous,
    sameSpec: (out.previous as { sha256?: unknown } | null)?.sha256 === sha,
    rows: out.p.rows.map(rowView),
    reimport: out.p.counts,
    risk: out.risk,
    caps: out.caps,
    checks: out.checks,
    blocking: out.p.blocking,
    notes: out.notes,
    expiresInSeconds: IMPORT_TTL_SECONDS,
  }
}

export async function commitImport(name: string, body: ImportCommitBody, actor: Actor) {
  assertNotSystem(name)
  const stored = await getRedisClient().get(importKey(name))
  const { sha256: pending, content, format } = stored ? (JSON.parse(stored) as { sha256: string; content: string; format: 'auto' | 'json' | 'yaml' }) : { sha256: '', content: '', format: 'auto' as const }
  if (!stored || pending !== body.specSha256 || specSha256(content) !== body.specSha256) {
    throw siteError(409, 'spec_not_previewed', 'this spec is not the one last previewed for this site in the last 24 hours: preview it again')
  }
  const spec = await loadSpec(content, format)
  return withRedisLock(`sites:${name}:import`, async () => {
    const out = await evaluate(name, spec, body.specSha256, body, actor)
    if (out.base.etag !== body.baseEtag) throw siteError(409, 'stale_base', 'the draft changed since the preview: preview the import again')
    if (out.p.blocking.length > 0) {
      throw Object.assign(siteError(422, 'import_blocked', `${out.p.blocking.length} row(s) need a decision before the import`), { checks: out.p.blocking.map((b) => ({ level: 'error', code: b.code, message: b.message, path: b.op })) })
    }
    if (!out.p.changed && (out.previous as { sha256?: unknown } | null)?.sha256 === body.specSha256) {
      return { changed: false, counts: out.p.counts, etag: out.base.etag }
    }
    if (JSON.stringify(out.candidate).length > draftMaxBytes()) throw siteError(413, 'draft_too_large', `the draft would exceed ${Math.round(draftMaxBytes() / 1024)} KiB`)
    // The base etag is the draft etag when the base is the draft: an autosave since is 412, not lost.
    const draft = await sitesRepository.putDraft(name, { site: out.candidate, baseVersion: out.base.baseVersion, updatedBy: actor.email ?? 'unknown' }, { ifMatch: out.base.from === 'draft' ? out.base.etag : undefined })
    const riskFlags = [...new Set(out.risk.flags.filter((f) => f.level !== 'low').map((f) => f.code))]
    auditSite('import', name, actor, `imported ${spec.title} ${spec.version} into the draft: +${out.p.counts.added} ~${out.p.counts.changed} −${out.p.counts.removed}`.trim(), {
      sha256: body.specSha256, counts: out.p.counts, risk: out.risk.level, riskFlags, overrides: out.p.counts.overrides,
    })
    return { changed: true, counts: out.p.counts, risk: out.risk, etag: draft.etag, draft: { updatedAt: draft.updatedAt, updatedBy: draft.updatedBy, baseVersion: draft.baseVersion } }
  })
}
