import { describe, it, expect, beforeEach, vi } from 'vitest'

// AUD-4: the commands that emitted nothing — recert campaign create/delete, org roster and service
// map changes without a diff, the access check, API-key use — and the Site helper the sites module
// calls. Each asserts the catalog key the event lands on, not only that "something" was written.

const h = vi.hoisted(() => {
  const campaigns = new Map<string, Record<string, unknown>>()
  const kv = new Map<string, string>()
  return {
    emit: vi.fn(async () => '1-0'),
    campaigns,
    kv,
    orgAdmins: { 'org-1': ['a@example.com', 'b@example.com'] } as Record<string, string[]>,
    orgServices: { 'org-1': ['kuma'] } as Record<string, string[]>,
  }
})

vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    async set(key: string, value: string, ...args: string[]) {
      if (args.includes('NX') && h.kv.has(key)) return null
      h.kv.set(key, value)
      return 'OK'
    },
  }),
}))
vi.mock('../../../services/redis-recert.repository.js', () => ({
  redisRecertRepository: {
    setCampaign: vi.fn(async (c: Record<string, unknown>) => { h.campaigns.set(c.id as string, c) }),
    getCampaign: vi.fn(async (id: string) => h.campaigns.get(id) ?? null),
    getItems: vi.fn(async () => []),
    removeFromInbox: vi.fn(),
    deleteItems: vi.fn(),
    deleteCampaign: vi.fn(async (id: string) => { h.campaigns.delete(id) }),
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => ({})),
    serviceExists: vi.fn(async () => true),
    getOrgAdmins: vi.fn(async (org: string) => h.orgAdmins[org] ?? []),
    setOrgAdmins: vi.fn(async (org: string, admins: string[]) => { h.orgAdmins[org] = admins }),
    getOrgServiceMap: vi.fn(async () => h.orgServices),
    setOrgServiceMapping: vi.fn(async (org: string, s: string[]) => { h.orgServices[org] = s }),
    deleteOrgServiceMapping: vi.fn(async (org: string) => { const had = org in h.orgServices; delete h.orgServices[org]; return had }),
    invalidateBundleEtag: vi.fn(),
    invalidateStats: vi.fn(async () => {}),
  },
}))
vi.mock('../../../services/access-review.service.js', () => ({ accessReviewService: { invalidate: vi.fn() } }))
vi.mock('../../../services/realtime.service.js', () => ({ realtimeService: { publish: vi.fn() } }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: {} }))
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => unknown) => fn() }))

import { recertService } from '../../../services/recert.service.js'
import { rbacService } from '../../../services/rbac.service.js'
import { auditSite, auditAccessCheck, recordApiKeyUse } from '../../../audit/record.js'
import { legacyToV1 } from '../../../audit/v1/legacy-map.js'
import type { AuditEvent } from '../../../services/audit-types.js'

const ACTOR = { id: 'admin-1', email: 'admin@example.com', ip: '10.0.0.1', ua: 'Firefox', sessionId: 's', requestId: 'req-1' }
const lastEvent = () => (h.emit.mock.calls.at(-1) as unknown as [Record<string, any>])[0]
const settle = () => new Promise((r) => setImmediate(r))

describe('recert campaign create and delete are audited', () => {
  beforeEach(() => { h.emit.mockClear(); h.campaigns.clear() })

  it('create → recert.campaign.created with the campaign id and the actor id', async () => {
    const c = await recertService.createCampaign({ name: 'Q3', reviewers: ['r@example.com'], deadline: new Date(Date.now() + 86_400_000).toISOString(), onExpiry: 'flag' } as never, ACTOR)
    await settle()
    expect(h.emit).toHaveBeenCalledTimes(1)
    expect(lastEvent()).toMatchObject({ v1Event: 'recert.campaign.created', targetType: 'campaign', targetId: c.id, actor: { id: 'admin-1' }, requestId: 'req-1' })
    expect(c.createdBy).toBe('admin@example.com')
  })

  it('delete → recert.campaign.deleted (deleting evidence is itself evidence)', async () => {
    const c = await recertService.createCampaign({ name: 'Q3', reviewers: ['r@example.com'], deadline: new Date(Date.now() + 86_400_000).toISOString(), onExpiry: 'flag' } as never, ACTOR)
    h.emit.mockClear()
    await recertService.deleteCampaign(c.id, ACTOR)
    await settle()
    expect(h.emit).toHaveBeenCalledTimes(1)
    expect(lastEvent()).toMatchObject({ v1Event: 'recert.campaign.deleted', targetId: c.id, actor: { id: 'admin-1' } })
  })
})

describe('org roster and service map changes carry a diff', () => {
  beforeEach(() => h.emit.mockClear())

  it('setOrgAdmins → org.admins.changed with added/removed', async () => {
    await rbacService.setOrgAdmins('org-1', ['b@example.com', 'c@example.com'], ACTOR)
    await settle()
    // Legacy type → org.admins.changed through the v1 legacy map.
    expect(lastEvent()).toMatchObject({
      type: 'rbac.org_admins_set',
      changes: { resource: 'org_admin_map', id: 'org-1', added: ['c@example.com'], removed: ['a@example.com'] },
    })
  })

  it('setOrgServiceMapping / delete → org.services.changed with added/removed', async () => {
    await rbacService.setOrgServiceMapping('org-1', ['kuma', 'grafana'], ACTOR)
    await settle()
    expect(lastEvent()).toMatchObject({ type: 'rbac.org_service_mapping_set', changes: { added: ['grafana'], removed: [] } })
    await rbacService.deleteOrgServiceMapping('org-1', ACTOR)
    await settle()
    expect(lastEvent()).toMatchObject({ type: 'rbac.org_service_mapping_deleted', changes: { added: [], removed: ['kuma', 'grafana'] } })
  })
})

describe('access check, API-key use, sites', () => {
  beforeEach(() => { h.emit.mockClear(); h.kv.clear() })

  it('auditAccessCheck → access.checked naming who was asked about (by HMAC in v1) and the route', async () => {
    auditAccessCheck(ACTOR, { email: 'target@example.com', method: 'GET', path: '/api/x' }, { allow: false, reason: 'forbidden' })
    await settle()
    expect(lastEvent()).toMatchObject({
      v1Event: 'access.checked', targetType: 'user', result: 'ok', actor: { id: 'admin-1' },
      details: { targetEmail: 'target@example.com', route: 'GET /api/x', allow: false, verdict: 'forbidden' },
    })
  })

  it('recordApiKeyUse → apikey.used once per client per day', async () => {
    await recordApiKeyUse('client-1', 'org-9')
    await recordApiKeyUse('client-1', 'org-9')
    await recordApiKeyUse('client-2', 'org-9')
    await settle()
    expect(h.emit).toHaveBeenCalledTimes(2)
    expect((h.emit.mock.calls[0] as unknown as [Record<string, any>])[0]).toMatchObject({
      v1Event: 'apikey.used', targetType: 'oauth2_client', targetId: 'client-1', details: { organizationId: 'org-9' },
    })
  })

  it('auditSite maps each Site command onto its own catalog key', async () => {
    const expected = { draft: 'site.draft_saved', discard: 'site.draft_discarded', save: 'site.saved', apply: 'site.applied', rollback: 'site.rolled_back', pause: 'site.paused', resume: 'site.resumed', delete: 'site.deleted' } as const
    for (const [command, key] of Object.entries(expected)) {
      auditSite(command as keyof typeof expected, 'payroll', ACTOR, { summary: `${command} v3`, version: 3 })
      await settle()
      expect(lastEvent()).toMatchObject({ v1Event: key, targetType: 'site', targetId: 'payroll', service: 'payroll', actor: { id: 'admin-1' } })
    }
  })

  it('the sites module\'s current emits (category service, target site:<name>) no longer land on system.unmapped', () => {
    const rich = (verb: string): AuditEvent => ({ category: 'service', kind: 'change', verb, target: 'site:payroll', targetType: 'site', targetId: 'payroll', result: 'ok', actor: { email: null } })
    expect(legacyToV1(rich('apply')).event).toBe('site.applied')
    expect(legacyToV1(rich('pause')).event).toBe('site.paused')
    expect(legacyToV1(rich('resume')).event).toBe('site.resumed')
    expect(legacyToV1(rich('delete')).event).toBe('site.deleted')
    expect(legacyToV1(rich('update')).event).toBe('site.saved')
  })
})
