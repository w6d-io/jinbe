import * as sources from '../sources.js'
import { ensureLabels, person, UNKNOWN_USER } from '../labels.js'
import { auditQuery, regexAlternation } from '../../audit/query/logql.js'
import { msToNs } from '../../audit/query/loki.js'
import { matches, parseLine } from '../../audit/query/reader.js'
import type { Changes } from '../types.js'
import type { HomeView } from '../scope.js'
import { CHANGE_CATEGORIES, auditSourceFor } from './activity.js'
import { DAY, ok, src, type ModuleDef } from './common.js'

/**
 * The last ten changes (home-data §3.5 changes). audit/v1 events from Loki, org-scoped inside the
 * query; interim, the legacy Redis stream (platform only), with every address mapped to a display
 * name server-side. Tier C: refreshed off the request.
 */

type Item = Changes['items'][number]
const LIMIT = 10
const SCAN = 50
const LOOKBACK_MS = 30 * DAY

const ACTOR_TYPES = new Set(['user', 'service', 'system', 'anonymous'])

function targetLabel(type: string, id: string | null): string {
  if (type === 'user') return person(id).label
  return id ?? type
}

async function fromLoki(view: HomeView, now: number): Promise<Changes> {
  const orgs = view.kind === 'orgs' ? view.orgs : undefined
  const filter = { result: 'success', ...(orgs ? { orgs } : {}) }
  const query = `${auditQuery(filter, sources.lokiNamespace())} | category=~${regexAlternation(CHANGE_CATEGORIES)}`
  const entries = await sources.loki().queryRange({ query, startNs: msToNs(now - LOOKBACK_MS), endNs: msToNs(now + 1), limit: SCAN, direction: 'backward' })
  const items: Item[] = []
  for (const entry of entries) {
    const e = parseLine(entry.line)
    // The second lock on scope, as the audit reader does: what the query let through is filtered again.
    if (!e || !matches(e, filter, entry.line) || !CHANGE_CATEGORIES.includes(e.category)) continue
    items.push({
      eventId: e.event_id,
      ts: e.ts,
      event: e.event,
      category: e.category,
      result: e.result,
      actor: { ...person(e.actor.id), type: e.actor.type },
      ...(e.target ? { target: { type: e.target.type, id: e.target.id, label: targetLabel(e.target.type, e.target.id) } } : {}),
      ...(e.site ? { site: e.site } : {}),
      ...(e.org_id ? { orgId: e.org_id } : {}),
      link: { page: 'audit', params: { eventId: e.event_id, ts: e.ts } },
    })
    if (items.length === LIMIT) break
  }
  return { items, source: 'loki' }
}

async function fromLegacy(): Promise<Changes> {
  const events = await sources.legacyChanges(LIMIT)
  return {
    source: 'redis-legacy',
    items: events.map((e): Item => {
      const actorType = e.who === 'system' ? 'system' : e.who === 'anon' ? 'anonymous' : 'user'
      const actor = actorType === 'user' ? person(e.who) : { id: null, label: actorType === 'system' ? 'System' : UNKNOWN_USER }
      let target: Item['target']
      if (e.targetType && e.targetId) {
        target = { type: e.targetType, id: e.targetId.includes('@') ? null : e.targetId, label: targetLabel(e.targetType, e.targetId) }
      } else if (e.target) {
        // `user:alice@example.com` and friends: the address never leaves, the name does.
        const bare = e.target.startsWith('user:') ? e.target.slice(5) : e.target
        target = bare.includes('@') || e.target.startsWith('user:')
          ? { type: 'user', id: null, label: person(bare).label }
          : { type: 'resource', id: e.target, label: e.target }
      }
      return {
        eventId: e.id,
        ts: e.ts,
        event: `${e.category}.${e.verb}`,
        category: e.category,
        result: e.result,
        actor: { ...actor, type: ACTOR_TYPES.has(actorType) ? actorType : 'user' },
        ...(target ? { target } : {}),
        link: { page: 'audit', params: { eventId: e.id, ts: e.ts } },
      }
    }),
  }
}

export const changesModule: ModuleDef<Changes> = {
  name: 'changes',
  tier: 'background',
  freshMs: 60_000,
  timeoutMs: 150,
  async compute(ctx) {
    const which = auditSourceFor(ctx.view)
    if (typeof which !== 'string') return which
    await ensureLabels().catch(() => {})
    if (which === 'loki') return ok(await fromLoki(ctx.view, ctx.now), { loki: src('ok') })
    return ok(await fromLegacy(), { audit_legacy: src('ok') })
  },
}

