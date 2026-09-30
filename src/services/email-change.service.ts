import { createHmac } from 'node:crypto'
import { env } from '../config/index.js'
import { KratosApiError, kratosService } from './kratos.service.js'
import { withRedisLock } from './redis-lock.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'

/**
 * An administrator changes somebody's sign-in address (POST /admin/users/:id/email).
 *
 * The new address replaces `traits.email` in ONE Kratos JSON patch, under the identity's lock (the
 * same lock and the same one-patch rule as every metadata_admin writer, kratos.service
 * updateAdminState): Kratos recomputes the verifiable addresses, so the new one starts UNVERIFIED.
 * The same patch appends the previous address to `metadata_admin.email_history` as a keyed digest,
 * never in clear, so a revert can be proven ("it was this address") without keeping the address.
 *
 * An address another identity holds answers `AddressUnavailableError` — the route says 409 without
 * naming the account, so the endpoint is no oracle for who is registered.
 */

export const EMAIL_HISTORY_DAYS = 30
export const EMAIL_HISTORY_MAX = 10

export class AddressUnavailableError extends Error {}
export class SameAddressError extends Error {}
export class NoAddressError extends Error {}

export interface EmailHistoryEntry {
  digest: string
  changedAt: string
  /** The identity id of whoever made the change. */
  by: string | null
}

export const normaliseAddress = (address: string) => address.trim().toLowerCase()

/**
 * A keyed digest of an address: the audit key when set (so the trail and the history correlate),
 * else the service's own encryption key. Never reversible without the key.
 */
export function addressDigest(address: string): string {
  const key = env.AUDIT_HMAC_KEY ?? env.ENCRYPTION_KEY
  return `hmac-sha256:${createHmac('sha256', key).update(normaliseAddress(address)).digest('hex').slice(0, 32)}`
}

function history(meta: Record<string, unknown> | null, now: number): EmailHistoryEntry[] {
  const raw = Array.isArray(meta?.email_history) ? (meta!.email_history as EmailHistoryEntry[]) : []
  const cutoff = now - EMAIL_HISTORY_DAYS * 24 * 3600 * 1000
  return raw.filter((e) => e && typeof e.digest === 'string' && Date.parse(e.changedAt) >= cutoff)
}

export interface EmailChanged {
  identity: KratosIdentity
  previousDigest: string
  nextDigest: string
}

export async function changeEmail(identityId: string, newAddress: string, by: string | null, now = Date.now()): Promise<EmailChanged> {
  const next = normaliseAddress(newAddress)
  return withRedisLock(`identity:${identityId}`, async () => {
    const current = await kratosService.getIdentity(identityId)
    const previous = typeof current.traits?.email === 'string' ? current.traits.email : null
    if (!previous) throw new NoAddressError('The user has no email address to change')
    if (normaliseAddress(previous) === next) throw new SameAddressError('That is already the user\'s address')

    const holder = await kratosService.findByEmail(next)
    if (holder && holder.id !== identityId) throw new AddressUnavailableError('address_unavailable')

    const raw = current.metadata_admin
    const meta = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null
    const previousDigest = addressDigest(previous)
    const entries = [...history(meta, now), { digest: previousDigest, changedAt: new Date(now).toISOString(), by }].slice(-EMAIL_HISTORY_MAX)

    const patches = [
      { op: 'replace', path: '/traits/email', value: next },
      meta
        ? { op: 'add', path: '/metadata_admin/email_history', value: entries }
        : { op: 'add', path: '/metadata_admin', value: { email_history: entries } },
    ]
    let identity: KratosIdentity
    try {
      identity = await kratosService.patchIdentity(identityId, patches)
    } catch (err) {
      // Taken between the lookup and the write: Kratos' own uniqueness check, same generic answer.
      if (err instanceof KratosApiError && err.statusCode === 409) throw new AddressUnavailableError('address_unavailable')
      throw err
    }
    // The RBAC bindings are keyed on the address: the directory copy must be re-read.
    kratosService.invalidateGroupsCache()
    return { identity, previousDigest, nextDigest: addressDigest(next) }
  })
}
