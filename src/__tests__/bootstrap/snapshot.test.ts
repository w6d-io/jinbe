import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mkdtemp, readFile, stat } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'

// The rollback point of --apply: an exact snapshot of every rbac:* key, written before anything is
// wiped, restorable exactly — and the apply refuses unless a copy outlives the pod.

const s = vi.hoisted(() => ({ s3: false, puts: [] as string[], redisTouched: false }))

vi.mock('../../services/backup-store.service.js', () => ({
  backupStore: {
    enabled: () => s.s3,
    putSnapshot: vi.fn(async (name: string) => { s.puts.push(name); return { key: `jinbe-snapshots/${name}.json` } }),
    getSnapshot: vi.fn(),
  },
}))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => { s.redisTouched = true; throw new Error('the store was touched') },
}))
vi.mock('../../bootstrap/plan/run.js', () => ({ readInventory: vi.fn(async () => ({ unavailable: [] })), writePlan: vi.fn() }))
vi.mock('../../bootstrap/plan/review.js', () => ({ buildPlan: vi.fn(() => ({ planHash: 'h1' })) }))

import { EphemeralSnapshotError, restoreSnapshot, snapshotDurability, storeSnapshot, takeSnapshot } from '../../bootstrap/snapshot.js'
import { applyModel } from '../../bootstrap/apply.js'

/** A store with the few commands the snapshot uses. */
function memoryStore(init: Record<string, string | Record<string, string>>) {
  const data = new Map<string, string | Record<string, string>>(Object.entries(init))
  return {
    data,
    scan: async (_c: string, _m: string, pattern: string) => {
      const re = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`)
      return ['0', [...data.keys()].filter((k) => re.test(k))] as [string, string[]]
    },
    type: async (k: string) => (typeof data.get(k) === 'string' ? 'string' : data.has(k) ? 'hash' : 'none'),
    get: async (k: string) => data.get(k) as string,
    hgetall: async (k: string) => data.get(k) as Record<string, string>,
    smembers: async () => [], lrange: async () => [], zrange: async () => [],
    multi: () => {
      const ops: Array<() => void> = []
      const tx = {
        del: (k: string) => { ops.push(() => data.delete(k)); return tx },
        set: (k: string, v: string) => { ops.push(() => data.set(k, v)); return tx },
        hset: (k: string, v: Record<string, string>) => { ops.push(() => data.set(k, { ...v })); return tx },
        sadd: () => tx, rpush: () => tx, zadd: () => tx,
        exec: async () => { ops.forEach((o) => o()); return [] },
      }
      return tx
    },
  }
}

const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }

beforeEach(() => {
  s.s3 = false
  s.puts = []
  s.redisTouched = false
  vi.clearAllMocks()
})

describe('the store snapshot', () => {
  it('takes every rbac:* key and the marker, restores the store exactly (keys added since are removed)', async () => {
    const store = memoryStore({ 'rbac:groups': { ops: '{"jinbe":["ops"]}' }, 'rbac:bootstrap:state': '{"schemaVersion":7}', 'other:key': 'x' })
    const snap = await takeSnapshot(store as never, 'pre-apply', 'abc')
    expect(Object.keys(snap.keys).sort()).toEqual(['rbac:bootstrap:state', 'rbac:groups'])
    store.data.set('rbac:org_sites', { acme: '["jinbe"]' })
    store.data.delete('rbac:groups')
    await restoreSnapshot(store as never, snap)
    expect(store.data.get('rbac:groups')).toEqual({ ops: '{"jinbe":["ops"]}' })
    expect(store.data.has('rbac:org_sites')).toBe(false)
    expect(store.data.get('other:key')).toBe('x')
  })

  it('writes a 0600 file, and to S3 when backup is configured', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'snap-'))
    const snap = await takeSnapshot(memoryStore({ 'rbac:groups': {} }) as never, 'pre-apply', 'abc')
    const local = await storeSnapshot(snap, dir)
    expect(local.s3).toBeUndefined()
    expect((await stat(local.file)).mode & 0o777).toBe(0o600)
    expect(JSON.parse(await readFile(local.file, 'utf8')).keys).toHaveProperty('rbac:groups')
    s.s3 = true
    expect((await storeSnapshot(snap, dir)).s3).toMatch(/^jinbe-snapshots\//)
  })
})

describe('durability: a copy must outlive the pod', () => {
  it('S3 configured is durable', async () => {
    expect(await snapshotDurability('/tmp/x', false, true)).toMatchObject({ durable: true, where: ['s3'] })
  })

  it('a dir not declared durable, or declared but on the container filesystem, is not', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'snap-'))
    expect(await snapshotDurability(dir, false, false)).toMatchObject({ durable: false, why: expect.stringContaining('not declared durable') })
    // A fresh temp dir sits on the same filesystem as its parent: not a mounted volume.
    expect(await snapshotDurability(dir, true, false)).toMatchObject({ durable: false, why: expect.stringContaining('not a mounted volume') })
    expect(await snapshotDurability(join(dir, 'missing'), true, false)).toMatchObject({ durable: false, why: expect.stringContaining('cannot be read') })
  })
})

describe('--apply refuses an ephemeral snapshot', () => {
  const apply = (over: Record<string, unknown> = {}) => applyModel({
    logger: logger as never, expect: 'h1', firstRun: false, builtInRules: [], gitSha: 'abc', snapshotDir: '/tmp/jinbe-snapshots', ...over,
  })

  it('refuses before touching the store, naming the fix', async () => {
    const err = await apply().catch((e) => e)
    expect(err).toBeInstanceOf(EphemeralSnapshotError)
    expect(err.message).toMatch(/S3 backup|JINBE_SNAPSHOT_DIR_DURABLE|--allow-ephemeral-snapshot/)
    expect(s.redisTouched).toBe(false)
  })

  it('--allow-ephemeral-snapshot goes on, logged loudly', async () => {
    await expect(apply({ allowEphemeralSnapshot: true })).rejects.toThrow('the store was touched')
    expect(logger.error).toHaveBeenCalledWith(expect.anything(), expect.stringContaining('--allow-ephemeral-snapshot'))
  })

  it('S3 configured: no refusal, no warning', async () => {
    s.s3 = true
    await expect(apply()).rejects.toThrow('the store was touched')
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('a first run has nothing to roll back to', async () => {
    await expect(apply({ firstRun: true, expect: null })).rejects.toThrow('the store was touched')
  })
})
