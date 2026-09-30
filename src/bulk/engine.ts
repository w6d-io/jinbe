import { createHash, randomUUID } from 'node:crypto'
import { auditEventService } from '../services/audit-event.service.js'
import { componentLogger } from '../telemetry/logger.js'
import { groupsMembersAdd } from './ops/groups.js'
import { sitesRoutesUpsert } from './ops/sites.js'
import { usersInvite, usersVerification } from './ops/users.js'
import { claimLease, getJob, getPlan, putJob, putPlan, releaseLease, renewLease, PLAN_TTL_S, type Job, type JobItem, type StoredPlan } from './store.js'
import { BULK_MAX_ITEMS, type BulkOp, type Caller, type ItemResult, type Outcome } from './types.js'

/**
 * Plan, execute, follow a bulk operation. Nothing here deletes: the four operations create, add or
 * send, and each item is judged again, by its own guards, right before it runs.
 */

export const OPS = {
  'sites.routes.upsert': sitesRoutesUpsert,
  'users.invite': usersInvite,
  'users.verification': usersVerification,
  'groups.members.add': groupsMembersAdd,
} as const

export type OpName = keyof typeof OPS
export const OP_NAMES = Object.keys(OPS) as OpName[]

export class BulkError extends Error {
  constructor(public statusCode: number, public code: string, message: string, public extra: Record<string, unknown> = {}) {
    super(message)
  }
}

const log = () => componentLogger('bulk')
const PLAN_CONCURRENCY = 10

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const opOf = (name: OpName) => OPS[name] as unknown as BulkOp<any, any, any>

function canonical(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonical)
  return Object.fromEntries(Object.keys(value as object).sort().map((k) => [k, canonical((value as Record<string, unknown>)[k])]))
}
const hashOf = (value: unknown) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex')

async function pool<T, R>(values: T[], size: number, fn: (v: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(values.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(size, values.length) }, async () => {
    while (next < values.length) {
      const i = next++
      out[i] = await fn(values[i], i)
    }
  }))
  return out
}

/** Judges every item for this caller now: the items as parsed, and what each would do. */
async function judge(caller: Caller, name: OpName, rawItems: unknown[], rawParams: unknown) {
  const op = opOf(name)
  const params = op.params.parse(rawParams ?? {})
  const state = await op.load(caller, params)
  const seen = new Set<string>()
  const parsed = rawItems.map((raw) => op.item.safeParse(raw))
  const items = parsed.map((p, i) => (p.success ? p.data : rawItems[i]))
  const outcomes = await pool(parsed, PLAN_CONCURRENCY, async (p): Promise<Outcome> => {
    if (!p.success) {
      const issue = p.error.issues[0]
      return { status: 'refused', reason: `invalid:${issue.path.join('.') || 'item'}:${issue.message}` }
    }
    const key = op.key(p.data)
    if (seen.has(key)) return { status: 'refused', reason: 'duplicate' }
    seen.add(key)
    return op.plan(caller, params, state, p.data)
  })
  const warnings = op.warnings?.(caller, params, outcomes) ?? []
  return { params, items, outcomes, warnings, planHash: hashOf({ op: name, params, items, outcomes }) }
}

export function planView(plan: StoredPlan) {
  const counts: Record<string, number> = { ok: 0, skip: 0, refused: 0, not_found: 0 }
  for (const o of plan.outcomes) counts[o.status] += 1
  return {
    planId: plan.planId,
    planHash: plan.planHash,
    op: plan.op,
    expiresAt: plan.expiresAt,
    counts,
    items: plan.outcomes.map((outcome, index) => ({ index, outcome })),
    warnings: plan.warnings,
  }
}

export function jobView(job: Job) {
  const counts: Record<string, number> = { pending: 0, done: 0, skipped: 0, refused: 0, failed: 0 }
  for (const item of job.items) counts[item.status] += 1
  const { owner: _owner, ...rest } = job
  return { ...rest, counts }
}

export async function planBulk(caller: Caller, name: OpName, body: { items?: unknown; params?: unknown }): Promise<StoredPlan> {
  if (!Array.isArray(body.items) || body.items.length === 0 || body.items.length > BULK_MAX_ITEMS) {
    throw new BulkError(400, 'invalid_request', `items must hold 1 to ${BULK_MAX_ITEMS} entries`)
  }
  const judged = await judge(caller, name, body.items, body.params)
  const now = Date.now()
  const plan: StoredPlan = {
    planId: randomUUID(),
    op: name,
    owner: { id: caller.id, clientId: caller.clientId },
    params: judged.params,
    items: judged.items,
    outcomes: judged.outcomes,
    planHash: judged.planHash,
    warnings: judged.warnings,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + PLAN_TTL_S * 1000).toISOString(),
  }
  await putPlan(plan)
  return plan
}

/** Jobs this process is running, by id (a test seam, and "already running here"). */
export const running = new Map<string, Promise<void>>()

const initialStatus = (o: Outcome): JobItem['status'] => (o.status === 'ok' ? 'pending' : o.status === 'skip' ? 'skipped' : 'refused')
const reasonOf = (o: Outcome) => (o.status === 'skip' || o.status === 'refused' ? o.reason : o.status === 'not_found' ? 'not_found' : undefined)

/**
 * Executes a plan: refused unless `planHash` is the plan's, and — for a new job — unless planning it
 * again now gives the same hash (409 plan_changed, with the new plan to review). Answers the job; the
 * items run after the answer. A plan already executed answers its job, resumed when its runner died.
 */
export async function executeBulk(caller: Caller, name: OpName, body: { planId?: unknown; planHash?: unknown }): Promise<{ job: Job; started: boolean }> {
  const plan = typeof body.planId === 'string' ? await getPlan(body.planId) : null
  if (!plan || plan.op !== name || plan.owner.id !== caller.id) throw new BulkError(404, 'plan_not_found', 'No such plan (plans are kept one hour).')
  if (body.planHash !== plan.planHash) throw new BulkError(409, 'plan_hash_mismatch', 'planHash is not the hash of this plan.')

  const existing = await getJob(plan.planId)
  if (existing) {
    if (existing.state !== 'running' || running.has(existing.id)) return { job: existing, started: false }
    if (!(await claimLease(existing.id, caller.id))) return { job: existing, started: false }
    start(caller, name, plan, existing)
    return { job: existing, started: true }
  }

  const again = await judge(caller, name, plan.items, plan.params)
  if (again.planHash !== plan.planHash) {
    const fresh = await planBulk(caller, name, { items: plan.items, params: plan.params })
    throw new BulkError(409, 'plan_changed', 'What this plan would do has changed since it was made. Review the new plan and execute it.', { plan: planView(fresh) })
  }

  const now = new Date().toISOString()
  const job: Job = {
    id: plan.planId,
    op: name,
    owner: plan.owner,
    planHash: plan.planHash,
    state: 'running',
    total: plan.items.length,
    items: plan.outcomes.map((o, index) => ({ index, status: initialStatus(o), ...(reasonOf(o) ? { reason: reasonOf(o) } : {}) })),
    createdAt: now,
    updatedAt: now,
  }
  if (!(await claimLease(job.id, caller.id))) throw new BulkError(409, 'job_running', 'This plan is already being executed.')
  await putJob(job)
  start(caller, name, plan, job)
  return { job, started: true }
}

function start(caller: Caller, name: OpName, plan: StoredPlan, job: Job): void {
  const run = runJob(caller, name, plan, job)
    .catch((err) => log().error({ err: (err as Error).message, job: job.id }, '[bulk] job stopped'))
    .finally(() => running.delete(job.id))
  running.set(job.id, run)
}

const toJobItem = (index: number, r: ItemResult): JobItem =>
  r.status === 'done' ? { index, status: 'done', action: r.action } : { index, status: r.status, reason: r.reason }

async function runJob(caller: Caller, name: OpName, plan: StoredPlan, job: Job): Promise<void> {
  const op = opOf(name)
  const ctx = { jobId: job.id }
  try {
    const state = await op.load(caller, plan.params)
    const held: JobItem[] = []
    for (const slot of job.items) {
      if (slot.status !== 'pending') continue
      const item = plan.items[slot.index]
      let result: ItemResult
      try {
        // Judged again right before it runs: a right lost, a member added since the plan, is honoured.
        const now = await op.plan(caller, plan.params, state, item)
        result = now.status === 'ok'
          ? await op.run(caller, plan.params, state, item, ctx)
          : { status: now.status === 'skip' ? 'skipped' : 'refused', reason: reasonOf(now) ?? 'not_found' }
      } catch (err) {
        log().warn({ err: (err as Error).message, job: job.id, index: slot.index }, '[bulk] item failed')
        result = { status: 'failed', reason: 'error' }
      }
      if (op.commit) {
        held.push(toJobItem(slot.index, result))
      } else {
        job.items[slot.index] = toJobItem(slot.index, result)
        await putJob(job)
        await renewLease(job.id)
      }
    }
    if (op.commit) {
      try {
        await op.commit(caller, plan.params, state, ctx)
        for (const item of held) job.items[item.index] = item
      } catch (err) {
        log().warn({ err: (err as Error).message, job: job.id }, '[bulk] commit failed')
        for (const item of held) job.items[item.index] = { index: item.index, status: 'failed', reason: (err as { code?: string }).code ?? 'commit_failed' }
      }
    }
    job.state = 'done'
  } catch (err) {
    job.state = 'failed'
    job.error = (err as { code?: string }).code ?? 'error'
    for (const slot of job.items) if (slot.status === 'pending') Object.assign(slot, { status: 'failed', reason: job.error })
  }
  job.finishedAt = new Date().toISOString()
  await putJob(job)
  await releaseLease(job.id)

  auditEventService.emit({
    category: 'system',
    kind: 'change',
    verb: 'bulk_execute',
    target: `bulk:${job.id}`,
    targetType: 'bulk',
    targetId: job.id,
    result: job.state === 'done' ? 'applied' : 'failed',
    severity: 'warn',
    actor: caller.audit,
    requestId: caller.audit.requestId,
    source: 'jinbe-api',
    v1Event: 'bulk.executed',
    details: { op: name, counts: jobView(job).counts, total: job.total },
  }).catch(() => {})
}

/** A job for its owner; anybody else is told there is none. */
export async function jobFor(caller: Caller, id: string): Promise<Job> {
  const job = await getJob(id)
  if (!job || job.owner.id !== caller.id) throw new BulkError(404, 'job_not_found', 'No such job (jobs are kept one day).')
  return job
}
