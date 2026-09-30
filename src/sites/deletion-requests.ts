import { randomUUID } from 'node:crypto'
import { withRedisLock } from '../services/redis-lock.js'
import { deletionStore, type DeletionRequest } from './lifecycle-store.js'
import { getRecord } from './sites.service.js'
import { remove } from './apply.service.js'
import { assertNotSystem, siteError } from './checks.js'
import { auditSite, type Actor } from './audit.js'

/**
 * Deletion requests (wave 19, owner-approved: MCP never deletes, humans decide). Anyone with
 * sites:write — a key included — may ask for a site to be deleted; a person holding sites:delete
 * approves (which runs the ordinary delete: rules out, then permissions, a 30-day snapshot) or
 * rejects it. Always four-eyes: the requester never approves their own request. Never through a key:
 * the route's permission is sites:delete (delegable 'never', step-up), refused by the delegation
 * gate, and refused here again when the actor acted through a client.
 *
 * Like apply requests (requests.ts), one Redis hash; one pending request per site at a time.
 */

const lockOf = (site: string) => `sites:deletion:${site}`

export async function createDeletionRequest(name: string, body: { reason?: string }, actor: Actor): Promise<DeletionRequest> {
  assertNotSystem(name)
  await getRecord(name)
  return withRedisLock(lockOf(name), async () => {
    const open = (await deletionStore.all()).find((r) => r.site === name && r.state === 'pending')
    if (open) throw siteError(409, 'deletion_request_pending', `A deletion of ${name} is already waiting for a decision (${open.id})`)
    const request: DeletionRequest = {
      id: randomUUID(),
      site: name,
      ...(body.reason ? { reason: body.reason } : {}),
      requestedBy: actor.email ?? 'unknown',
      requesterId: actor.id ?? null,
      ...(actor.act ? { requestedVia: actor.act.client_id } : {}),
      requestedAt: new Date().toISOString(),
      state: 'pending',
    }
    await deletionStore.put(request)
    auditSite('deletion_request', name, actor, `asked for ${name} to be deleted`, { requestId: request.id, ...(body.reason ? { reason: body.reason } : {}) })
    return request
  })
}

export async function listDeletionRequests(filter: { state?: string; site?: string }): Promise<DeletionRequest[]> {
  return (await deletionStore.all())
    .filter((r) => (!filter.state || r.state === filter.state) && (!filter.site || r.site === filter.site))
    .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
}

/** The inbox: pending requests, oldest first, each saying whether this caller may decide it. */
export async function pendingDeletionRequests(actor: Actor) {
  return (await listDeletionRequests({ state: 'pending' }))
    .reverse()
    .map((r) => ({ ...r, requestedByYou: isRequester(r, actor) }))
}

function isRequester(r: DeletionRequest, actor: Actor): boolean {
  if (r.requesterId && actor.id) return r.requesterId === actor.id
  return !!actor.email && r.requestedBy === actor.email
}

async function pending(id: string): Promise<DeletionRequest> {
  const request = await deletionStore.get(id)
  if (!request) throw siteError(404, 'not_found', `No deletion request ${id}`)
  if (request.state !== 'pending') throw siteError(409, 'request_decided', `This request is already ${request.state}`)
  return request
}

/** A decision is a person's, in a browser: never a client acting for them (the gate refuses it first). */
function assertPerson(actor: Actor): void {
  if (actor.act) throw siteError(403, 'delegation_refused', 'A deletion is decided by a person in the console, not through a key')
}

export async function approveDeletionRequest(id: string, actor: Actor) {
  assertPerson(actor)
  const first = await pending(id)
  return withRedisLock(lockOf(first.site), async () => {
    const request = await pending(id)
    if (isRequester(request, actor)) throw siteError(403, 'second_approver_required', 'Four-eyes: someone other than the requester must approve a deletion')
    const deleted = await remove(request.site, actor, { approvedRequest: id })
    const done: DeletionRequest = { ...request, state: 'approved', decidedBy: actor.email ?? 'unknown', decidedAt: new Date().toISOString() }
    await deletionStore.put(done)
    auditSite('deletion_approve', request.site, actor, `approved the deletion requested by ${request.requestedBy}`, { requestId: id })
    return { request: done, ...deleted }
  }, { ttlMs: 60_000 })
}

export async function rejectDeletionRequest(id: string, actor: Actor, reason?: string): Promise<DeletionRequest> {
  assertPerson(actor)
  const first = await pending(id)
  return withRedisLock(lockOf(first.site), async () => {
    const request = await pending(id)
    const done: DeletionRequest = { ...request, state: 'rejected', decidedBy: actor.email ?? 'unknown', decidedAt: new Date().toISOString(), ...(reason ? { decisionReason: reason } : {}) }
    await deletionStore.put(done)
    auditSite('deletion_reject', request.site, actor, `rejected the deletion requested by ${request.requestedBy}`, { requestId: id, ...(reason ? { reason } : {}) })
    return done
  })
}
