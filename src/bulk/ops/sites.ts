import { z } from 'zod'
import { routeSchema, SITE_NAME_PATTERN, type Route } from '../../sites/schemas.js'
import { sitesRepository } from '../../sites/repository.js'
import { assertNotSystem, siteError } from '../../sites/checks.js'
import { putDraft } from '../../sites/sites.service.js'
import { auditSite } from '../../sites/audit.js'
import type { BulkOp, Outcome } from '../types.js'

type Params = { site: string }
type DraftSite = { name?: string; gates?: Array<{ id?: string }>; routes?: { items?: Route[] } & Record<string, unknown> } & Record<string, unknown>
type State = { site: DraftSite; baseVersion: number; changed: number; draftEtag?: string }

const siteName = z.string().regex(SITE_NAME_PATTERN)

function canonical(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonical)
  return Object.fromEntries(Object.keys(value as object).sort().map((k) => [k, canonical((value as Record<string, unknown>)[k])]))
}
const same = (a: unknown, b: unknown) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b))

const itemsOf = (site: DraftSite): Route[] => (Array.isArray(site.routes?.items) ? site.routes!.items! : [])

/**
 * Map many routes on a site's DRAFT at once (create, or replace by route id), with their access
 * (public / signed-in / a permission / deny) and gate. Never a version, never an apply: saving and
 * publishing keep their own routes and gates. The whole job is ONE draft write, made after every item
 * was judged (commit), from the draft as it is then — or the saved version when there is no draft.
 */
export const sitesRoutesUpsert: BulkOp<Route, Params, State> = {
  permission: 'sites:write',
  item: routeSchema,
  params: z.object({ site: siteName }).strict(),
  key: (item) => item.id,

  async load(_caller, params) {
    assertNotSystem(params.site)
    const [record, draft] = await Promise.all([sitesRepository.get(params.site), sitesRepository.getDraft(params.site)])
    const base = (draft?.site ?? record?.site) as DraftSite | undefined
    if (!base || typeof base !== 'object') throw siteError(404, 'not_found', `No site or draft named ${params.site}`)
    return { site: structuredClone(base), baseVersion: draft?.baseVersion ?? record?.version ?? 0, changed: 0, draftEtag: draft?.etag }
  },

  async plan(_caller, _params, state, item): Promise<Outcome> {
    const gates = Array.isArray(state.site.gates) ? state.site.gates.map((g) => g?.id) : []
    if (!gates.includes(item.gate)) return { status: 'refused', reason: `unknown_gate:${item.gate}` }
    const items = itemsOf(state.site)
    const existing = items.find((r) => r.id === item.id)
    if (existing?.pinned) return { status: 'refused', reason: 'pinned' }
    const clash = items.find((r) => r.id !== item.id && r.path === item.path && r.methods.some((m) => item.methods.includes(m)))
    if (clash) return { status: 'refused', reason: `same_route_as:${clash.id}` }
    if (existing && same(existing, item)) return { status: 'skip', reason: 'unchanged' }
    return { status: 'ok', action: existing ? 'update' : 'create' }
  },

  async run(_caller, _params, state, item) {
    const items = [...itemsOf(state.site)]
    const at = items.findIndex((r) => r.id === item.id)
    if (at >= 0) items[at] = item
    else items.push(item)
    state.site.routes = { ...(state.site.routes ?? {}), items }
    state.changed += 1
    return { status: 'done', action: at >= 0 ? 'update' : 'create' }
  },

  async commit(caller, params, state, ctx) {
    if (state.changed === 0) return
    // The draft as loaded: an autosave since then is 412 stale_draft (every item failed), not overwritten.
    await putDraft(params.site, { site: state.site, baseVersion: state.baseVersion }, caller.siteActor, { ifMatch: state.draftEtag })
    auditSite('draft', params.site, caller.siteActor, `${state.changed} route(s) mapped in bulk`, { bulk: ctx.jobId, routes: state.changed })
  },
}
