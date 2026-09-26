import { randomUUID } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { riskOf, type Risk } from './diff.js'
import type { SiteRecord } from './repository.js'
import { appliedRender, getRecord } from './sites.service.js'
import { applyRecord } from './apply.service.js'
import { assertNotSystem, siteError } from './checks.js'
import { sitesConfig } from './config.js'
import { auditSite, type Actor } from './audit.js'

/**
 * Apply requests (site-ux §9.1b, owner decision D2): someone asks for a saved version to be
 * applied; a super_admin approves (and that approval applies it, with their own recent MFA) or
 * rejects it.
 *
 * Four-eyes (SITES_FOUR_EYES, off by default): `high-risk` — a version whose risk is high may only
 * be applied through a request approved by ANOTHER super_admin; `all` — every version. With it off,
 * requests still work and anyone allowed to apply may approve, the requester included.
 *
 *   rbac:sites:requests → Hash: { id: JSON(ApplyRequest) }
 */

export type RequestState = 'pending' | 'applied' | 'rejected'

export interface ApplyRequest {
  id: string
  site: string
  version: number
  /** The etag of the version asked for: a newer save makes the request stale. */
  etag: string
  note?: string
  requestedBy: string
  requestedAt: string
  state: RequestState
  risk: Risk
  needsSecondApprover: boolean
  decidedBy?: string
  decidedAt?: string
  reason?: string
  applyId?: string
}

const KEY = 'rbac:sites:requests'

export async function riskFor(record: SiteRecord): Promise<Risk> {
  return riskOf((await appliedRender(record))?.site ?? null, record.site)
}

export function fourEyesRequired(risk: Risk): boolean {
  const mode = sitesConfig().SITES_FOUR_EYES
  return mode === 'all' || (mode === 'high-risk' && risk.level === 'high')
}

/** Direct apply: refused when four-eyes wants this version to go through an approved request. */
export async function assertNoApprovalNeeded(record: SiteRecord): Promise<void> {
  const risk = await riskFor(record)
  if (fourEyesRequired(risk)) {
    throw siteError(409, 'approval_required', `Four-eyes is on and this change is ${risk.level} risk: another super admin needs to approve it. Send it as a request.`)
  }
}

async function load(id: string): Promise<ApplyRequest> {
  const raw = await getRedisClient().hget(KEY, id)
  if (!raw) throw siteError(404, 'not_found', `No request ${id}`)
  return JSON.parse(raw) as ApplyRequest
}

const store = (r: ApplyRequest) => getRedisClient().hset(KEY, r.id, JSON.stringify(r))

export async function createRequest(name: string, body: { version: number; note?: string }, actor: Actor): Promise<ApplyRequest> {
  assertNotSystem(name)
  const record = await getRecord(name)
  if (body.version !== record.version) throw siteError(409, 'version_mismatch', `Version ${record.version} is the saved one; request that`)
  const risk = await riskFor(record)
  const request: ApplyRequest = {
    id: randomUUID(),
    site: name,
    version: record.version,
    etag: record.etag,
    ...(body.note ? { note: body.note } : {}),
    requestedBy: actor.email ?? 'unknown',
    requestedAt: new Date().toISOString(),
    state: 'pending',
    risk,
    needsSecondApprover: fourEyesRequired(risk),
  }
  await store(request)
  auditSite('request', name, actor, `asked to apply version ${record.version}`, { requestId: request.id, risk: risk.level })
  return request
}

export async function listRequests(filter: { state?: string; site?: string }): Promise<ApplyRequest[]> {
  const all = Object.values(await getRedisClient().hgetall(KEY)).map((raw) => JSON.parse(raw) as ApplyRequest)
  return all
    .filter((r) => (!filter.state || r.state === filter.state) && (!filter.site || r.site === filter.site))
    .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
}

export async function approveRequest(id: string, actor: Actor): Promise<ApplyRequest> {
  const request = await load(id)
  if (request.state !== 'pending') throw siteError(409, 'request_decided', `This request is already ${request.state}`)
  const record = await getRecord(request.site)
  if (record.version !== request.version || record.etag !== request.etag) {
    throw siteError(409, 'stale_request', `Version ${record.version} was saved after this request; ask again for it`)
  }
  // Re-evaluated now as well: turning four-eyes on after a request was made still applies to it.
  const needsSecond = request.needsSecondApprover || fourEyesRequired(await riskFor(record))
  if (needsSecond && actor.email === request.requestedBy) {
    throw siteError(403, 'second_approver_required', 'Four-eyes: another super admin must approve this request')
  }
  const applied = await applyRecord(record, actor, `approved request ${id} and applied`)
  const done: ApplyRequest = { ...request, state: 'applied', decidedBy: actor.email ?? 'unknown', decidedAt: new Date().toISOString(), applyId: applied.applyId }
  await store(done)
  auditSite('approve', request.site, actor, `approved version ${request.version} requested by ${request.requestedBy}`, { requestId: id, applyId: applied.applyId })
  return done
}

export async function rejectRequest(id: string, actor: Actor, reason?: string): Promise<ApplyRequest> {
  const request = await load(id)
  if (request.state !== 'pending') throw siteError(409, 'request_decided', `This request is already ${request.state}`)
  const done: ApplyRequest = { ...request, state: 'rejected', decidedBy: actor.email ?? 'unknown', decidedAt: new Date().toISOString(), ...(reason ? { reason } : {}) }
  await store(done)
  auditSite('reject', request.site, actor, `rejected version ${request.version}`, { requestId: id, ...(reason ? { reason } : {}) })
  return done
}
