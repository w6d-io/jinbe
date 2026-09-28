import { createHash } from 'node:crypto'
import { stableStringify } from '../render.js'
import { routeSchema, type Access, type Route } from '../schemas.js'
import type { ParsedSpec } from './extract.js'
import { propose, slugId, type ImportOptions, type ProposalSource, type Suggestion } from './map.js'
import { shapeOf } from './path.js'
import { BULK_PUBLIC, grantedBy, maxLevel, routeRisks, sameRankOverlaps, type Level, type RiskFlag } from './risk.js'

/**
 * The import plan: every spec operation proposed (map.ts), the human's decisions applied, merged
 * into the draft's routes (re-import by `op`), judged (risk.ts). Pure — preview and commit run the
 * same function, so what was reviewed is what is written.
 *
 * Re-import: a `pinned` route is never touched ("kept your change"); a route written by hand is
 * never replaced by an imported one; an operation gone from the spec is proposed as `deny`, not
 * deleted — a deleted route falls to the catch-all, which may be weaker than what it replaced — unless
 * the human asks to remove it. A decision that changes a row pins it, so the next import keeps it.
 */

export interface Decision { op: string; access?: Access; gate?: string; orgParam?: string | null; skip?: boolean; remove?: boolean; confirm?: boolean }

export interface BaseSite {
  prefix?: string
  gates: Array<{ id: string; anonymous: boolean }>
  catchAllGate?: string
  /** The draft's route items as stored (an item that is not a valid route is kept untouched). */
  items: unknown[]
  roles: Record<string, string[]>
  hasLogin: boolean
}

export type RowStatus = 'added' | 'changed' | 'unchanged' | 'removed' | 'pinned' | 'manual' | 'skipped' | 'unsupported'
export interface Row {
  op: string
  operationId?: string
  method: string
  specPath?: string
  status: RowStatus
  /** What the draft holds after the import (absent: nothing, or the row is not imported). */
  route?: Route
  current?: Route
  source?: ProposalSource | 'decision' | 'removed'
  suggestion?: Suggestion & { risk: RiskFlag[] }
  reasons: string[]
  risk: RiskFlag[]
  blocking?: { code: string; message: string }
  /** A high-risk row: the commit needs `confirm: true` in its decision. */
  needsConfirm?: true
}

export interface Plan {
  rows: Row[]
  items: unknown[]
  twoFactorRoutes: string[]
  blocking: Array<{ op: string; code: string; message: string }>
  risk: { level: Level; flags: RiskFlag[] }
  counts: Record<RowStatus | 'suggestions' | 'overrides', number>
  changed: boolean
}

const lowers = (a: Access | undefined) => a?.kind === 'public' || a?.kind === 'signed-in'
const sameRoute = (a: Route, b: Route) => stableStringify({ ...a, pinned: !!a.pinned }) === stableStringify({ ...b, pinned: !!b.pinned })

/** The wanted id, or it cut to 25 characters plus a hash of the operation when it is taken. */
function uniqueId(wanted: string, op: string, used: Set<string>): string {
  let id = wanted
  for (let n = 0; used.has(id); n++) id = `${wanted.slice(0, 25).replace(/-+$/, '')}-${createHash('sha256').update(`${op}#${n}`).digest('hex').slice(0, 6)}`
  used.add(id)
  return id
}

export function plan(spec: ParsedSpec, base: BaseSite, options: ImportOptions, decisions: Decision[], opts: { acceptDenied?: boolean } = {}): Plan {
  const rows: Row[] = []
  const blocking: Plan['blocking'] = []
  const block = (row: Row | null, op: string, code: string, message: string) => {
    if (row && !row.blocking) row.blocking = { code, message }
    blocking.push({ op, code, message })
  }
  const gates = new Map(base.gates.map((g) => [g.id, g]))
  const defaultGate = options.defaultGate ?? base.catchAllGate ?? base.gates[0]?.id ?? ''
  if (!gates.has(defaultGate)) block(null, '*', 'unknown_gate', `gate '${defaultGate}' does not exist on this site`)
  const decided = new Map(decisions.map((d) => [d.op, d]))
  const usedDecisions = new Set<string>()
  const decisionFor = (op: string) => (decided.has(op) ? (usedDecisions.add(op), decided.get(op)) : undefined)

  const parsed = base.items.map((raw) => routeSchema.safeParse(raw)).map((r) => (r.success ? r.data : null))
  const byOp = new Map<string, number>()
  const byKey = new Map<string, number>()
  const manual = new Set<string>()
  parsed.forEach((r, i) => {
    if (!r) return
    if (r.source === 'openapi' && r.op) byOp.set(r.op, i)
    if (r.source === 'openapi' && r.methods.length === 1) byKey.set(`${r.methods[0]} ${r.path}`, i)
    if (r.source !== 'openapi') for (const m of r.methods) manual.add(`${m} ${r.path}`)
  })
  const used = new Set(base.items.map((r) => (r as { id?: unknown } | null)?.id).filter((id): id is string => typeof id === 'string'))
  const matched = new Set<number>()
  const replaced = new Map<number, Route | null>()
  const added: Route[] = []
  const twoFactorRoutes: string[] = []
  const granted = grantedBy(base.roles)
  const seenOps = new Set<string>()
  const meta = new Map<Row, { broadened: boolean; deprecated: boolean; fromSpec: boolean }>()

  for (const op of spec.operations) {
    let key = op.operationId ?? `${op.method} ${op.path}`
    const reasons: string[] = [...op.notes]
    if (seenOps.has(key)) {
      reasons.push(`operationId '${key}' is used twice in the spec; keyed by method and path`)
      key = `${op.method} ${op.path}`
    }
    if (seenOps.has(key)) continue
    seenOps.add(key)
    const row: Row = { op: key, ...(op.operationId ? { operationId: op.operationId } : {}), method: op.method, specPath: op.path, status: 'unsupported', reasons, risk: [] }
    rows.push(row)
    const p = propose(op, spec, { ...options, defaultGate }, base.prefix)
    const decision = decisionFor(key)
    // A decision that only confirms changes nothing (a pinned route stays pinned).
    const acts = !!decision && (decision.access !== undefined || decision.gate !== undefined || decision.orgParam !== undefined || !!decision.skip || !!decision.remove)
    if (!p.ok) {
      row.status = p.status
      reasons.push(p.reason)
      if (decision && !decision.skip) block(row, key, 'not_importable', `${key} cannot be imported: ${p.reason}`)
      continue
    }
    reasons.push(...p.reasons)
    const routeKey = `${op.method} ${p.path}`
    const idx = byOp.get(key) ?? byKey.get(routeKey)
    if (idx !== undefined) matched.add(idx)
    const current = idx !== undefined ? parsed[idx]! : undefined
    if (current) row.current = current
    if (decision?.skip) {
      row.status = 'skipped'
      reasons.push('skipped as you asked')
      continue
    }
    if (idx === undefined && manual.has(routeKey)) {
      row.status = 'manual'
      reasons.push(`a route written by hand already serves ${routeKey}; kept`)
      continue
    }
    if (current?.pinned && !acts) {
      row.status = 'pinned'
      row.route = current
      reasons.push('kept your change')
      continue
    }
    let access = p.access
    let gate = defaultGate
    let orgParam = p.orgParam
    let overridden = false
    let fromSpec = false
    row.source = p.source
    if (decision?.access) {
      if (lowers(decision.access) && !decision.confirm) block(row, key, 'confirmation_required', `${key}: ${decision.access.kind} must be confirmed (confirm: true)`)
      fromSpec = lowers(decision.access) && p.suggestion?.access?.kind === decision.access.kind
      access = decision.access
      overridden = true
      row.source = 'decision'
    }
    if (decision?.gate !== undefined) {
      if (!gates.has(decision.gate)) block(row, key, 'unknown_gate', `${key}: gate '${decision.gate}' does not exist on this site`)
      gate = decision.gate
      overridden = true
    } else if (access.kind === 'public' && !gates.get(gate)?.anonymous) {
      const open = base.gates.find((g) => g.anonymous)
      if (open) gate = open.id
      else block(row, key, 'no_public_gate', `${key}: no gate of this site lets anonymous callers in`)
    }
    if (decision?.orgParam === null && (orgParam || current?.orgParam)) {
      if (!decision.confirm) block(row, key, 'confirmation_required', `${key}: removing the organization parameter must be confirmed (confirm: true)`)
      orgParam = undefined
      overridden = true
    } else if (typeof decision?.orgParam === 'string') {
      if (!p.params.includes(decision.orgParam)) block(row, key, 'invalid_org_param', `${key}: '${decision.orgParam}' is not a parameter of ${p.path}`)
      orgParam = decision.orgParam
      overridden = true
    }
    const id = current?.id ?? uniqueId(p.routeId ?? slugId(op.operationId ?? `${op.method}-${p.path}`), key, used)
    const route: Route = {
      id, methods: [op.method], path: p.path, gate, access,
      ...(orgParam ? { orgParam } : {}),
      source: 'openapi', op: key,
      ...(overridden || current?.pinned ? { pinned: true } : {}),
    }
    row.route = route
    row.status = !current ? 'added' : sameRoute(current, route) ? 'unchanged' : 'changed'
    if (current) replaced.set(idx!, route)
    else added.push(route)
    if (p.twoFactor && base.hasLogin) twoFactorRoutes.push(id)
    else if (p.twoFactor) reasons.push('the spec asks for 2FA here: set up the site sign-in first')
    if (p.suggestion) row.suggestion = { ...p.suggestion, risk: [] }
    if (p.source === 'unmapped' && !decision?.access && !opts.acceptDenied) block(row, key, 'unmapped', `${key}: no permission could be derived; decide, or leave it denied (acceptDenied)`)
    meta.set(row, { broadened: p.broadened, deprecated: op.deprecated, fromSpec })
  }

  // Operations gone from the spec: denied, not deleted (unless asked), pinned ones kept.
  parsed.forEach((r, i) => {
    if (!r || r.source !== 'openapi' || !r.op || matched.has(i)) return
    const decision = decisionFor(r.op)
    const row: Row = { op: r.op, method: r.methods.join(','), status: 'unchanged', current: r, route: r, source: 'removed', reasons: ['no longer in the spec'], risk: [] }
    rows.push(row)
    if (r.pinned && !decision?.remove) [row.status, row.reasons] = ['pinned', ['no longer in the spec; kept your change']]
    else if (decision?.remove) {
      ;[row.status, row.route] = ['removed', undefined]
      replaced.set(i, null)
      row.reasons.push('removed as you asked')
    } else if (r.access.kind !== 'deny') {
      row.route = { ...r, access: { kind: 'deny' } }
      row.status = 'removed'
      replaced.set(i, row.route)
      row.reasons.push('denied rather than deleted: without it the catch-all would answer')
    }
  })
  for (const d of decisions) if (!usedDecisions.has(d.op)) block(null, d.op, 'unknown_op', `no operation '${d.op.slice(0, 120)}' in this import`)

  // Two operations on one shape (`/a/{id}`, `/a/{name}`): one route if they agree, a decision if not.
  const shapes = new Map<string, Row[]>()
  for (const row of rows) {
    if (!row.route || row.source === 'removed' || row.status === 'pinned') continue
    const k = `${row.method} ${shapeOf(row.route.path)}`
    const group = shapes.get(k)
    if (group) group.push(row)
    else shapes.set(k, [row])
  }
  for (const group of shapes.values()) {
    if (group.length < 2) continue
    const agree = group.every((r) => stableStringify(r.route!.access) === stableStringify(group[0].route!.access))
    for (const row of group.slice(1)) {
      const at = added.indexOf(row.route!)
      if (agree && at >= 0) {
        added.splice(at, 1)
        ;[row.status, row.route] = ['skipped', undefined]
        row.reasons.push(`same route as ${group[0].op}`)
      } else if (!agree) block(row, row.op, 'shape_conflict', `${row.op} and ${group[0].op} are the same route with different access: skip one`)
    }
    if (!agree) block(group[0], group[0].op, 'shape_conflict', `${group[0].op} shares its route with other operations that have different access`)
  }

  const items = base.items.flatMap((raw, i) => (replaced.has(i) ? (replaced.get(i) ? [replaced.get(i)!] : []) : [raw])).concat(added)
  const overlaps = sameRankOverlaps(items.map((raw) => routeSchema.safeParse(raw)).flatMap((r) => (r.success ? [r.data] : [])))
  let opened = 0
  for (const row of rows) {
    const m = meta.get(row) ?? { broadened: false, deprecated: false, fromSpec: false }
    if (row.route && row.status !== 'pinned' && row.status !== 'unchanged') row.risk = routeRisks(row.route, { before: row.current, granted, ...m })
    if (row.route && overlaps.has(row.route.id)) row.risk.push({ code: 'same_rank_overlap', level: 'medium', message: `${row.route.path} overlaps ${overlaps.get(row.route.id)} at the same rank` })
    if (row.suggestion?.access && row.route) row.suggestion.risk = routeRisks({ ...row.route, access: row.suggestion.access }, { before: row.current, granted, ...m, fromSpec: true })
    if (row.route?.access.kind === 'public' && row.current?.access.kind !== 'public') opened++
  }
  const flags = rows.flatMap((r) => r.risk)
  if (opened > BULK_PUBLIC) flags.push({ code: 'bulk_public', level: 'high', message: `${opened} routes become public in one import` })
  const counts = { added: 0, changed: 0, unchanged: 0, removed: 0, pinned: 0, manual: 0, skipped: 0, unsupported: 0, suggestions: 0, overrides: 0 }
  for (const row of rows) {
    counts[row.status]++
    if (row.suggestion) counts.suggestions++
    if (row.source === 'decision') counts.overrides++
  }
  const ids = new Set(items.map((r) => (r as { id?: unknown }).id))
  return {
    rows, items, twoFactorRoutes: twoFactorRoutes.filter((id) => ids.has(id)), blocking, risk: { level: maxLevel(flags), flags }, counts,
    changed: counts.added + counts.changed + counts.removed > 0 || twoFactorRoutes.length > 0,
  }
}
