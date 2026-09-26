import { randomUUID } from 'crypto'
import { getRedisClient } from '../../services/redis-client.service.js'
import type { Filters } from './params.js'
import type { AuditScope } from './scope.js'

/**
 * Saved audit views (§4.4): personal, or shared within one org. Workflow data, not audit — one Redis
 * hash, small by nature. Only the owner deletes one.
 */

const KEY = 'auth:audit:saved-queries'

interface Stored { id: string; owner: string; name: string; filters: Filters; shared: boolean; orgId: string | null; createdAt: string }
export type SavedQuery = Omit<Stored, 'owner'> & { mine: boolean }

const view = (s: Stored, subject: string): SavedQuery => {
  const { owner, ...rest } = s
  return { ...rest, mine: owner === subject }
}

export async function createSaved(owner: string, input: { name: string; filters: Filters; shared: boolean; orgId?: string }): Promise<SavedQuery> {
  const stored: Stored = { id: randomUUID(), owner, name: input.name, filters: input.filters, shared: input.shared, orgId: input.orgId ?? null, createdAt: new Date().toISOString() }
  await getRedisClient().hset(KEY, stored.id, JSON.stringify(stored))
  return view(stored, owner)
}

/** Mine, plus those shared in an org inside the caller's scope (every shared one for a platform reader). */
export async function listSaved(subject: string, scope: AuditScope): Promise<SavedQuery[]> {
  const all = Object.values(await getRedisClient().hgetall(KEY)).map((raw) => JSON.parse(raw) as Stored)
  return all
    .filter((s) => s.owner === subject || (s.shared && (scope.platform || (s.orgId !== null && scope.orgs.includes(s.orgId)))))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((s) => view(s, subject))
}

export async function deleteSaved(subject: string, id: string): Promise<boolean> {
  const raw = await getRedisClient().hget(KEY, id)
  if (!raw || (JSON.parse(raw) as Stored).owner !== subject) return false
  await getRedisClient().hdel(KEY, id)
  return true
}
