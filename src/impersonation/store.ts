import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'

/**
 * Impersonation grants, in Redis.
 *
 *   jinbe:impersonation:grant:<sha256(token)>   → String: JSON(ImpersonationGrant), EX = its lifetime
 *   jinbe:impersonation:session:<adminSession>  → String: sha256(token), same EX
 *
 * The token is the impersonation cookie's value: 32 random bytes, handed to the browser once and
 * never stored — Redis holds its hash, so a dump of the store opens nothing. One grant per
 * administrator SESSION: starting another replaces it, and the session index lets the console read
 * and stop the grant without the cookie (which the console's own host may not even receive).
 *
 * A grant ends by its TTL, by Stop, or with the administrator's session (the gateway check refuses
 * it then; a session ended through jinbe also deletes it here).
 */

export interface ImpersonationGrant {
  id: string
  adminId: string
  adminEmail: string
  adminSessionId: string
  targetId: string
  targetEmail: string
  targetName: string
  reason: string
  /** RFC 3339. */
  startedAt: string
  expiresAt: string
}

export type NewGrant = Omit<ImpersonationGrant, 'id' | 'startedAt' | 'expiresAt'>

const grantKey = (hash: string) => `jinbe:impersonation:grant:${hash}`
const sessionKey = (sessionId: string) => `jinbe:impersonation:session:${sessionId}`

export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex')

function parse(raw: string | null, now: number): ImpersonationGrant | null {
  if (!raw) return null
  try {
    const grant = JSON.parse(raw) as ImpersonationGrant
    // The TTL removes it; the date is checked too, so a clock or a TTL that slipped never extends one.
    return typeof grant?.id === 'string' && new Date(grant.expiresAt).getTime() > now ? grant : null
  } catch {
    return null
  }
}

export const impersonationStore = {
  /** A new grant for this administrator session, replacing the one it had. Returns the cookie value once. */
  async start(input: NewGrant, ttlSeconds: number, now: number = Date.now()): Promise<{ grant: ImpersonationGrant; token: string; replaced: ImpersonationGrant | null }> {
    const redis = getRedisClient()
    const replaced = await this.endForSession(input.adminSessionId, now)
    const token = randomBytes(32).toString('base64url')
    const hash = hashToken(token)
    const grant: ImpersonationGrant = {
      id: randomUUID(),
      ...input,
      startedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlSeconds * 1000).toISOString(),
    }
    await redis.set(grantKey(hash), JSON.stringify(grant), 'EX', ttlSeconds)
    await redis.set(sessionKey(input.adminSessionId), hash, 'EX', ttlSeconds)
    return { grant, token, replaced }
  },

  /** The live grant behind a cookie value, or null (unknown, expired, stopped). */
  async byToken(token: string, now: number = Date.now()): Promise<ImpersonationGrant | null> {
    if (!token) return null
    return parse(await getRedisClient().get(grantKey(hashToken(token))), now)
  },

  /** The live grant of an administrator session, or null. */
  async bySession(sessionId: string, now: number = Date.now()): Promise<ImpersonationGrant | null> {
    const redis = getRedisClient()
    const hash = await redis.get(sessionKey(sessionId))
    return hash ? parse(await redis.get(grantKey(hash)), now) : null
  },

  /** Ends the grant of an administrator session. Returns the grant that was live, or null. */
  async endForSession(sessionId: string, now: number = Date.now()): Promise<ImpersonationGrant | null> {
    const redis = getRedisClient()
    const hash = await redis.get(sessionKey(sessionId))
    if (!hash) return null
    const grant = parse(await redis.get(grantKey(hash)), now)
    await redis.del(grantKey(hash), sessionKey(sessionId))
    return grant
  },
}
