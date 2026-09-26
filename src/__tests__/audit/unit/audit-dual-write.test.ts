import { describe, it, expect, beforeEach, vi } from 'vitest'

// The admin write under test is a real one: userGroupsService.applyGroupUpdate with the REAL
// rbacService (its notifyBindingsChanged fan-out) and the REAL auditEventService. Only storage and
// the policy engine are stubbed.
const { redis } = vi.hoisted(() => {
  const r = {
    streams: new Map<string, number>(),
    async xadd(key: string) { r.streams.set(key, (r.streams.get(key) ?? 0) + 1); return `${Date.now()}-0` },
    async expire() { return 1 },
    async hset() { return 1 },
  }
  return { redis: r }
})
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => redis }))
vi.mock('../../../services/group-catalogue.js', async () =>
  (await import('../../helpers/group-catalogue-mock.js')).groupCatalogueMock())
vi.mock('../../../services/organisation-store.js', () => ({
  applyGroupChange: vi.fn().mockResolvedValue(undefined),
  groupsForSubjects: vi.fn().mockResolvedValue(new Map()),
  allGroupMemberships: vi.fn().mockResolvedValue([]),
  organisationStoreConfigured: vi.fn().mockReturnValue(true),
}))
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => unknown) => fn() }))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: { updateUserGroups: vi.fn().mockResolvedValue(undefined), hasMFA: vi.fn().mockResolvedValue(true) },
}))
vi.mock('../../../services/opa.service.js', () => ({ opaService: { canGrant: vi.fn().mockResolvedValue(true) } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { invalidateBundleEtag: vi.fn().mockResolvedValue(undefined), invalidateStats: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/access-review.service.js', () => ({ accessReviewService: { invalidate: vi.fn() } }))
vi.mock('../../../services/realtime.service.js', () => ({ realtimeService: { publish: vi.fn() } }))

import { env } from '../../../config/env.js'
import { auditLog, type AuditEventV1 } from '../../../audit/v1/index.js'
import { auditEventService } from '../../../services/audit-event.service.js'
import { userGroupsService } from '../../../services/user-groups.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { realtimeService } from '../../../services/realtime.service.js'

const lines: AuditEventV1[] = []
const outbox: AuditEventV1[] = []
auditLog.useSinks({ write: (e) => lines.push(e), outbox: { append: async (e) => { outbox.push(e); return '1-0' } } })

const ACTOR = {
  id: 'admin-uuid-1', email: 'admin@example.com', name: 'Ada', ip: '10.1.2.3', ua: 'Firefox',
  sessionId: 'sess-1', requestId: 'req-42', aal: 'aal2', authenticatedAt: new Date(), secondFactorAt: new Date(),
}

function setSink(sink: 'legacy' | 'dual' | 'v1') {
  ;(env as { AUDIT_SINK: string }).AUDIT_SINK = sink
}

describe('one admin write → exactly one audit/v1 event (AUD-2, AUD-3, AUD-5)', () => {
  beforeEach(() => {
    lines.length = 0
    outbox.length = 0
    redis.streams.clear()
    setSink('dual')
  })

  it('a group change emits one v1 event carrying the actor id, the request id and no email', async () => {
    const result = await userGroupsService.applyGroupUpdate({
      identity: { id: 'target-uuid-1', email: 'target@example.com', organizationId: 'org-1' },
      newGroups: ['users'],
      actor: ACTOR,
      privilegePolicy: { kind: 'super_admin_required' },
      auditEventType: 'user.groups_changed',
    })
    expect(result.ok).toBe(true)
    await new Promise((r) => setImmediate(r)) // the fire-and-forget emits settle

    expect(lines).toHaveLength(1)
    const [e] = lines
    expect(e.event).toBe('rbac.user_groups.changed')
    expect(e.actor.id).toBe('admin-uuid-1')
    expect(e.target).toMatchObject({ type: 'user', id: 'target-uuid-1' })
    expect(e.request_id).toBe('req-42')
    expect(e.changes?.added).toEqual(['users'])
    expect(JSON.stringify(e)).not.toContain('@')
    expect(outbox.map((o) => o.event_id)).toEqual([e.event_id])
    // The OPAL/real-time side effects of notifyBindingsChanged still happen — only its audit row went.
    expect(realtimeService.publish).toHaveBeenCalledWith('user.groups_changed')
  })

  it('notifyBindingsChanged alone writes no audit row, legacy or v1', async () => {
    await rbacService.notifyBindingsChanged('metadata_updated', ACTOR)
    expect(lines).toHaveLength(0)
    expect(redis.streams.get('auth:audit:events')).toBeUndefined()
  })
})

describe('AUDIT_SINK (AUD-2)', () => {
  beforeEach(() => {
    lines.length = 0
    redis.streams.clear()
  })
  const emit = () => auditEventService.emit({ type: 'api_key.created', actor: ACTOR, target: { type: 'oauth2_client', id: 'c-1' }, details: { organizationId: 'org-9' } })

  it('dual writes the Redis stream and one v1 line', async () => {
    setSink('dual')
    await emit()
    expect(redis.streams.get('auth:audit:events')).toBe(1)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatchObject({ event: 'apikey.created', org_id: 'org-9' })
  })

  it('legacy writes only the Redis stream', async () => {
    setSink('legacy')
    await emit()
    expect(redis.streams.get('auth:audit:events')).toBe(1)
    expect(lines).toHaveLength(0)
  })

  it('v1 writes only the v1 line and returns its event_id', async () => {
    setSink('v1')
    const id = await emit()
    expect(redis.streams.get('auth:audit:events')).toBeUndefined()
    expect(lines).toHaveLength(1)
    expect(id).toBe(lines[0].event_id)
  })
})
