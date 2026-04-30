import { getRedisClient } from '../services/redis-client.service.js'

export const LOCK_KEY = 'rbac:bootstrap:lock'
export const LOCK_TTL_SECONDS = 600

/**
 * Acquire a Redis SETNX lock for the bootstrap CLI.
 *
 * Returns the lock value (used as a guard during release) on success,
 * or null if the lock is already held by another runner.
 *
 * The lock has a 600s TTL so a crashed CLI can never hold it forever.
 */
export async function acquireLock(holder: string): Promise<string | null> {
  const result = await getRedisClient().set(LOCK_KEY, holder, 'EX', LOCK_TTL_SECONDS, 'NX')
  return result === 'OK' ? holder : null
}

/**
 * Release the lock if and only if it is still held by the given holder.
 * Uses a Lua CAS script to avoid releasing a lock that has expired and
 * been re-acquired by another runner.
 */
export async function releaseLock(holder: string): Promise<boolean> {
  const lua = `
    if redis.call('get', KEYS[1]) == ARGV[1] then
      return redis.call('del', KEYS[1])
    else
      return 0
    end
  `
  const result = (await getRedisClient().eval(lua, 1, LOCK_KEY, holder)) as number
  return result === 1
}

export function generateHolderId(): string {
  const host = process.env.HOSTNAME || 'unknown-host'
  return `${host}-${process.pid}-${Date.now()}`
}
