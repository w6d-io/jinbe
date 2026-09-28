import { vi } from 'vitest'
import type { LokiClient } from '../../audit/query/loki.js'
import type { PromClient } from '../../telemetry/prom-query.js'

/**
 * A stand-in for src/home/sources.ts — every source the Home reads — as one mutable world, and a
 * minimal Redis for the SWR cache. Suites set what each source answers (or make it throw / hang).
 */

export const ORG_A = '11111111-1111-4111-8111-111111111111'
export const ORG_B = '22222222-2222-4222-8222-222222222222'
const NOW = () => Date.now()
const never = () => new Promise<never>(() => {})

type Fn = (...args: any[]) => any

function defaults() {
  return {
    bootstrapReady: true,
    kubeMode: 'off' as 'off' | 'in-cluster',
    auditSink: 'dual' as 'legacy' | 'dual' | 'v1',
    lokiConfigured: false,
    grafanaUrl: null as string | null,
    loki: null as LokiClient | null,
    prom: null as PromClient | null,
    stats: {
      total: 12, active: 10, fullAccess: 2, unassigned: 1,
      perGroup: { admins: 2, users: 12 }, perOrg: { [ORG_A]: 4, [ORG_B]: 3 }, perService: {},
      computedAt: new Date().toISOString(),
    } as Record<string, unknown> | null,
    siteRows: [
      { name: 'payroll', displayName: 'Payroll', host: 'payroll.example.com', status: 'live', version: 3, appliedVersion: 3, appliedAt: new Date(NOW() - 3_600_000).toISOString(), appliedBy: 'ada@example.com', orgs: 1 },
      { name: 'fleet', displayName: 'Fleet', host: 'fleet.example.com', status: 'attention', version: 5, appliedVersion: 4, appliedAt: new Date(NOW() - 7_200_000).toISOString(), appliedBy: 'bob@example.com', orgs: 1, draft: { by: 'bob@example.com', at: new Date(NOW() - 10 * 86_400_000).toISOString() } },
      { name: 'draft-only', displayName: 'Draft only', host: null, status: 'draft', version: 0, appliedVersion: null, appliedAt: null, appliedBy: null, orgs: 0, draft: { by: 'carol@example.com', at: new Date().toISOString() } },
    ] as Array<Record<string, any>>,
    siteRecords: [
      { site: { name: 'payroll', orgs: [ORG_A] } },
      { site: { name: 'fleet', orgs: [ORG_B] } },
    ] as Array<Record<string, any>>,
    requests: [
      { id: 'req-1', site: 'payroll', version: 4, requestedBy: 'ada@example.com', requestedAt: new Date(NOW() - 3_600_000).toISOString(), risk: { level: 'high', flags: [] }, needsSecondApprover: true, state: 'pending' },
      { id: 'req-2', site: 'fleet', version: 5, requestedBy: 'root@example.com', requestedAt: new Date(NOW() - 1_800_000).toISOString(), risk: { level: 'low', flags: [] }, needsSecondApprover: false, state: 'pending' },
    ] as Array<Record<string, any>>,
    campaigns: [] as Array<Record<string, any>>,
    inbox: {} as Record<string, Array<{ deadline: string }>>,
    outbox: { length: 0, oldestMs: null as number | null },
    identities: new Map<string, { id: string; name: string | null; active: boolean }>([
      ['ada@example.com', { id: 'id-ada', name: 'Ada Lovelace', active: true }],
      ['bob@example.com', { id: 'id-bob', name: 'Bob Chen', active: true }],
      ['root@example.com', { id: 'root', name: 'Root', active: true }],
      ['m1@example.com', { id: 'm1', name: 'Member One', active: true }],
      ['m2@example.com', { id: 'm2', name: 'Member Two', active: false }],
    ]),
    orgMembers: { [ORG_A]: ['m1', 'm2'], [ORG_B]: ['id-bob'] } as Record<string, string[]>,
    orgNames: { [ORG_A]: 'Acme', [ORG_B]: 'Globex' } as Record<string, string>,
    legacyRows: [] as Array<[string, string[]]>,
    legacyChanges: [] as Array<Record<string, any>>,
    /** Per-source overrides: throw, hang, or answer something else. */
    override: {} as Record<string, Fn>,
    calls: {} as Record<string, number>,
  }
}

export const world = defaults()

export function resetWorld(): void {
  Object.assign(world, defaults())
}

/** Makes a source reject. */
export const failing = (name: string) => { world.override[name] = async () => { throw new Error(`${name} down`) } }
/** Makes a source never answer. */
export const hanging = (name: string) => { world.override[name] = never }

function wrap<T extends Fn>(name: string, fn: T): T {
  return ((...args: unknown[]) => {
    world.calls[name] = (world.calls[name] ?? 0) + 1
    return (world.override[name] ?? fn)(...args)
  }) as T
}

export function sourcesMock() {
  const m = {
    bootstrapReady: () => world.bootstrapReady,
    commitSha: () => 'abcdef1234567',
    redisHealthy: async () => true,
    kratosReady: async () => 'ok' as const,
    environment: () => ({ name: 'test-env', production: false }),
    kubeMode: () => world.kubeMode,
    releaseNamespace: () => 'auth',
    gatewayRollout: async () => ({ managed: true, settled: true, rollout: { phase: 'Complete', since: new Date().toISOString(), message: null } }),
    siteCrs: async () => [
      { metadata: { name: 'payroll' }, status: { conditions: [{ type: 'Ready', status: 'True' }] } },
      { metadata: { name: 'fleet' }, status: { conditions: [{ type: 'Ready', status: 'False', reason: 'RulesNotLoaded', lastTransitionTime: new Date().toISOString() }] } },
    ],
    siteDrift: async () => ({ items: [], checkedAt: new Date().toISOString() }),
    servingRevision: async () => 'rev-abcdef12',
    servingSince: async () => NOW() - 60_000,
    engines: async () => [{ id: 'opa-1', revision: 'rev-abcdef12', activatedAt: null, heardAt: NOW() }],
    opalLastSuccess: async () => ({ bindings: NOW() - 30_000 }),
    rulesServed: async () => ({ at: NOW() - 2_000, count: 10, compileErrors: 0 }),
    auditSink: () => world.auditSink,
    outbox: async () => world.outbox,
    auditFailures: async () => 0,
    lokiConfigured: () => world.lokiConfigured,
    lokiNamespace: () => 'auth',
    loki: () => world.loki,
    lokiReady: async () => true,
    prom: () => world.prom,
    grafanaUrl: () => world.grafanaUrl,
    directoryStats: async () => (world.stats ? { stats: world.stats, computedAt: NOW() } : null),
    accessReviewSummary: async () => ({ totalPrivileged: 3, total: 3, canDoAnything: 2, selfGranted: 0, dormant: 1, noMfa: 2, withoutMfa: 2, mfa: { enrolled: 9, identities: 12 }, computedAt: new Date().toISOString() }),
    siteRows: async () => world.siteRows,
    siteRecords: async () => world.siteRecords,
    deletedSites: async () => 1,
    pendingRequests: async () => world.requests,
    migration: async () => ({ state: 'not-started' }),
    campaigns: async () => world.campaigns,
    inbox: async (email: string) => world.inbox[email] ?? [],
    legacyChanges: async () => world.legacyChanges,
    legacyRows: async () => world.legacyRows,
    orgNames: async (ids: string[]) => Object.fromEntries(ids.filter((i) => world.orgNames[i]).map((i) => [i, world.orgNames[i]])),
    orgMembers: async (id: string) => world.orgMembers[id] ?? [],
    identityDirectory: async () => world.identities,
  }
  return Object.fromEntries(Object.entries(m).map(([k, fn]) => [k, wrap(k, fn as Fn)]))
}

/** Enough of ioredis for the SWR cache, the leader lock and the job keys (PX/EX honoured). */
export class MemoryRedis {
  kv = new Map<string, { v: string; exp: number | null }>()
  private live(key: string) {
    const e = this.kv.get(key)
    if (e && e.exp !== null && Date.now() >= e.exp) {
      this.kv.delete(key)
      return undefined
    }
    return e
  }
  async get(key: string) { return this.live(key)?.v ?? null }
  async mget(...keys: string[]) { return keys.map((k) => this.live(k)?.v ?? null) }
  async set(key: string, value: string, ...args: Array<string | number>) {
    if (args.includes('NX') && this.live(key)) return null
    let exp: number | null = null
    const px = args.indexOf('PX')
    const ex = args.indexOf('EX')
    if (px >= 0) exp = Date.now() + Number(args[px + 1])
    if (ex >= 0) exp = Date.now() + Number(args[ex + 1]) * 1000
    this.kv.set(key, { v: value, exp })
    return 'OK'
  }
  async del(...keys: string[]) { let n = 0; for (const k of keys) if (this.kv.delete(k)) n++; return n }
  async incr(key: string) { const n = Number(this.live(key)?.v ?? 0) + 1; this.kv.set(key, { v: String(n), exp: null }); return n }
  async expire() { return 1 }
  async hset() { return 1 }
  async hgetall() { return {} }
}

export const redisHolder = { redis: new MemoryRedis() }

export function redisMock() {
  return { getRedisClient: () => redisHolder.redis, redisClientService: { isHealthy: vi.fn(async () => true), getClient: () => redisHolder.redis } }
}

/** Lets fire-and-forget refreshes settle. */
export async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setImmediate(r))
}
