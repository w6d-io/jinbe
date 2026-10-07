import { randomUUID } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { withRedisLock } from '../services/redis-lock.js'
import { riskOf, type Risk } from './diff.js'
import type { SiteRecord } from './repository.js'
import { appliedRender, getRecord } from './sites.service.js'
import { applyRecord, assertAcknowledged } from './apply.service.js'
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
 * One pending request per site and saved version: asking again (a double click, a retry) answers
 * the pending one. A pending request whose version was saved over, or overtaken by an applied one, is
 * closed as `superseded` — on the next request for the site and whenever requests are listed — so the
 * queue never shows versions nobody can approve any more.
 *
 *   rbac:sites:requests → Hash: { id: JSON(ApplyRequest) }
 */

export type RequestState = 'pending' | 'applied' | 'rejected' | 'superseded'

export interface ApplyRequest {
  id: string
  site: string
  version: number
  /** The etag of the version asked for: a newer save makes the request stale. */
  etag: string
  note?: string
  /** Codes of the confirm findings the requester acknowledged (findings.ts); re-checked at approval. */
  acknowledge?: string[]
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

const allRequests = async (): Promise<ApplyRequest[]> => Object.values(await getRedisClient().hgetall(KEY)).map((raw) => JSON.parse(raw) as ApplyRequest)

/** Why a pending request can no longer be approved, or null while it can. */
function staleness(r: ApplyRequest, record: SiteRecord | null): string | null {
  if (!record) return 'the site is gone'
  if (record.applied && record.applied.version >= r.version) return `version ${record.applied.version} is applied`
  if (record.etag !== r.etag || record.version !== r.version) return `version ${record.version} was saved since`
  return null
}

/** Closes the pending requests of these requests' sites that can no longer be approved; returns them all, updated. */
async function closeStale(requests: ApplyRequest[]): Promise<ApplyRequest[]> {
  const sites = [...new Set(requests.filter((r) => r.state === 'pending').map((r) => r.site))]
  const records = new Map(await Promise.all(sites.map(async (site) => [site, await getRecord(site).catch(() => null)] as const)))
  const now = new Date().toISOString()
  return Promise.all(requests.map(async (r) => {
    if (r.state !== 'pending' || !records.has(r.site)) return r
    const why = staleness(r, records.get(r.site) ?? null)
    if (!why) return r
    const closed: ApplyRequest = { ...r, state: 'superseded', decidedBy: 'jinbe', decidedAt: now, reason: why }
    await store(closed)
    return closed
  }))
}

export async function createRequest(name: string, body: { version: number; note?: string; acknowledge?: string[] }, actor: Actor): Promise<ApplyRequest> {
  assertNotSystem(name)
  const record = await getRecord(name)
  if (body.version !== record.version) throw siteError(409, 'version_mismatch', `Version ${record.version} is the saved one; request that`)
  // A request nobody could approve is refused now, not at approval.
  await assertAcknowledged(record, body.acknowledge ?? [])
  return withRedisLock(`site-requests:${name}`, async () => {
    const mine = await closeStale((await allRequests()).filter((r) => r.site === name))
    // Asked again (a double click, a retry): the pending request for this very version answers.
    const same = mine.find((r) => r.state === 'pending' && r.version === record.version && r.etag === record.etag)
    if (same) return same
    const risk = await riskFor(record)
    const request: ApplyRequest = {
      id: randomUUID(),
      site: name,
      version: record.version,
      etag: record.etag,
      ...(body.note ? { note: body.note } : {}),
      ...(body.acknowledge?.length ? { acknowledge: [...new Set(body.acknowledge)] } : {}),
      requestedBy: actor.email ?? 'unknown',
      requestedAt: new Date().toISOString(),
      state: 'pending',
      risk,
      needsSecondApprover: fourEyesRequired(risk),
    }
    await store(request)
    auditSite('request', name, actor, `asked to apply version ${record.version}`, { requestId: request.id, risk: risk.level, ...(request.acknowledge ? { acknowledged: request.acknowledge } : {}) })
    return request
  })
}

export async function listRequests(filter: { state?: string; site?: string }): Promise<ApplyRequest[]> {
  const all = await closeStale(await allRequests())
  return all
    .filter((r) => (!filter.state || r.state === filter.state) && (!filter.site || r.site === filter.site))
    .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
}

export async function approveRequest(id: string, actor: Actor, acknowledge: readonly string[] = []): Promise<ApplyRequest> {
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
  // Findings again, now: the groups or the WAF may have changed. The approver may acknowledge more.
  const acknowledged = [...new Set([...(request.acknowledge ?? []), ...acknowledge])]
  await assertAcknowledged(record, acknowledged)
  const applied = await applyRecord(record, actor, `approved request ${id} and applied`, acknowledged.length > 0 ? { acknowledged } : {})
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
