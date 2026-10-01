import { mkdir, readFile, writeFile } from 'fs/promises'
import { join } from 'path'
import type { Redis } from 'ioredis'
import { backupStore } from '../services/backup-store.service.js'

/**
 * A raw, exact snapshot of the RBAC store (every `rbac:*` key, the bootstrap marker included),
 * taken before `--apply` wipes and reseeds it. MANDATORY: the apply refuses to touch anything unless
 * the snapshot is written to a local file AND, when backup is configured, to S3.
 *
 * Raw on purpose, not an RBAC bundle: the previous release must find its data exactly as it left it
 * (its own key names, its own marker schema), which no bundle format of THIS release can promise.
 * Rollback (docs: authz-v2-design §9):
 *   1. restore with this release:  node dist/cli/bootstrap.js --restore-snapshot <file | s3 key>
 *   2. redeploy the previous release (its bootstrap finds its marker and no work to do).
 */

export interface StoreSnapshot {
  version: 1
  takenAt: string
  reason: string
  gitSha: string
  keys: Record<string, { type: 'string' | 'hash' | 'set' | 'list' | 'zset'; value: unknown }>
}

type Store = Pick<Redis, 'scan' | 'type' | 'get' | 'hgetall' | 'smembers' | 'lrange' | 'zrange' | 'multi'>

async function keysMatching(redis: Store, pattern: string): Promise<string[]> {
  const out = new Set<string>()
  let cursor = '0'
  do {
    const [next, batch] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500)
    for (const k of batch) out.add(k)
    cursor = next
  } while (cursor !== '0')
  return [...out].sort()
}

export async function takeSnapshot(redis: Store, reason: string, gitSha: string): Promise<StoreSnapshot> {
  const keys: StoreSnapshot['keys'] = {}
  for (const key of await keysMatching(redis, 'rbac:*')) {
    const type = await redis.type(key)
    if (type === 'string') keys[key] = { type, value: await redis.get(key) }
    else if (type === 'hash') keys[key] = { type, value: await redis.hgetall(key) }
    else if (type === 'set') keys[key] = { type, value: await redis.smembers(key) }
    else if (type === 'list') keys[key] = { type, value: await redis.lrange(key, 0, -1) }
    else if (type === 'zset') keys[key] = { type, value: await redis.zrange(key, 0, -1, 'WITHSCORES') }
  }
  return { version: 1, takenAt: new Date().toISOString(), reason, gitSha, keys }
}

/**
 * Writes the snapshot where a rollback can find it; returns where. Throws when any required copy
 * could not be written — the caller must then change nothing.
 */
export async function storeSnapshot(snapshot: StoreSnapshot, dir: string): Promise<{ file: string; s3?: string }> {
  const name = `rbac-pre-apply-${snapshot.takenAt.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}`
  const body = JSON.stringify(snapshot)
  await mkdir(dir, { recursive: true })
  const file = join(dir, `${name}.json`)
  await writeFile(file, body, { encoding: 'utf8', mode: 0o600 })
  if (!backupStore.enabled()) return { file }
  const { key } = await backupStore.putSnapshot(name, body)
  return { file, s3: key }
}

export async function loadSnapshot(from: string): Promise<StoreSnapshot> {
  const raw = from.endsWith('.json') && !from.includes('-snapshots/') ? await readFile(from, 'utf8') : await backupStore.getSnapshot(from)
  const parsed = JSON.parse(raw) as StoreSnapshot
  if (parsed?.version !== 1 || typeof parsed.keys !== 'object') throw new Error('Not a jinbe store snapshot')
  return parsed
}

/** Puts the store back EXACTLY as the snapshot holds it: every current `rbac:*` key goes, in one MULTI. */
export async function restoreSnapshot(redis: Store, snapshot: StoreSnapshot): Promise<{ restored: number; removed: number }> {
  const current = await keysMatching(redis, 'rbac:*')
  const tx = redis.multi()
  for (const key of current) tx.del(key)
  for (const [key, { type, value }] of Object.entries(snapshot.keys)) {
    if (type === 'string' && typeof value === 'string') tx.set(key, value)
    else if (type === 'hash' && value && Object.keys(value as object).length) tx.hset(key, value as Record<string, string>)
    else if (type === 'set' && Array.isArray(value) && value.length) tx.sadd(key, ...(value as string[]))
    else if (type === 'list' && Array.isArray(value) && value.length) tx.rpush(key, ...(value as string[]))
    else if (type === 'zset' && Array.isArray(value) && value.length) {
      const pairs = value as string[]
      for (let i = 0; i < pairs.length; i += 2) tx.zadd(key, pairs[i + 1], pairs[i])
    }
  }
  await tx.exec()
  return { restored: Object.keys(snapshot.keys).length, removed: current.length }
}
