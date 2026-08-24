import { describe, it, expect, beforeEach, vi } from 'vitest'

// ── Hoisted mocks (re-primed per test — setup.ts clears all mocks) ────────────
const H = vi.hoisted(() => {
  // Minimal in-memory Redis covering the recert repository + scheduler claim key.
  const hashes = new Map<string, Map<string, string>>()
  const sets = new Map<string, Set<string>>()
  const strings = new Map<string, string>()
  const hash = (k: string) => {
    let h = hashes.get(k)
    if (!h) { h = new Map(); hashes.set(k, h) }
    return h
  }
  const redis = {
    hgetall: async (k: string) => Object.fromEntries(hashes.get(k) ?? []),
    hget: async (k: string, f: string) => hashes.get(k)?.get(f) ?? null,
    hset: async (k: string, ...args: string[]) => {
      const h = hash(k)
      for (let i = 0; i < args.length; i += 2) h.set(args[i], args[i + 1])
      return args.length / 2
    },
    hsetnx: async (k: string, f: string, v: string) => {
      const h = hash(k)
      if (h.has(f)) return 0
      h.set(f, v)
      return 1
    },
    hdel: async (k: string, f: string) => (hashes.get(k)?.delete(f) ? 1 : 0),
    hlen: async (k: string) => hashes.get(k)?.size ?? 0,
    del: async (k: string) => (hashes.delete(k) || sets.delete(k) ? 1 : 0),
    sadd: async (k: string, m: string) => {
      let s = sets.get(k)
      if (!s) { s = new Set(); sets.set(k, s) }
      s.add(m)
      return 1
    },
    srem: async (k: string, m: string) => (sets.get(k)?.delete(m) ? 1 : 0),
    smembers: async (k: string) => [...(sets.get(k) ?? [])],
    set: async (k: string, v: string, ...opts: unknown[]) => {
      if (opts.includes('NX') && strings.has(k)) return null
      strings.set(k, v)
      return 'OK'
    },
    _reset: () => { hashes.clear(); sets.clear(); strings.clear() },
  }
  return {
    redis,
    getAllIdentitiesWithGroups: vi.fn(),
    getUserGroups: vi.fn(),
    updateUserGroups: vi.fn(),
    getGroups: vi.fn(),
    getAccessReview: vi.fn(),
    emit: vi.fn(),
  }
})

vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => H.redis,
}))
vi.mock('../../../services/redis-lock.js', () => ({
  withRedisLock: (_name: string, fn: () => Promise<unknown>) => fn(),
}))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithGroups: H.getAllIdentitiesWithGroups,
    getUserGroups: H.getUserGroups,
    updateUserGroups: H.updateUserGroups,
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getGroups: H.getGroups },
}))
vi.mock('../../../services/access-review.service.js', () => ({
  accessReviewService: { getAccessReview: H.getAccessReview },
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: H.emit },
}))

import { recertService, RecertError } from '../../../services/recert.service.js'
import { runRecertSweep } from '../../../services/recert-scheduler.service.js'
import { redisRecertRepository } from '../../../services/redis-recert.repository.js'

// ── Fixtures ──────────────────────────────────────────────────────────────────
const GROUPS = { finance: { billing: ['admin'] }, eng: { ci: ['dev'] }, users: {} }
const DIRECTORY = new Map<string, string[]>([
  ['alice@ex.com', ['users', 'finance']],
  ['bob@ex.com', ['users', 'finance', 'eng']],
  ['carol@ex.com', ['users', 'eng']],
])
const ACTOR = { email: 'admin@ex.com', ip: '127.0.0.1' }
const LOG = { info: vi.fn(), warn: vi.fn(), error: vi.fn() }

function prime() {
  H.redis._reset()
  H.getGroups.mockResolvedValue(GROUPS)
  H.getAllIdentitiesWithGroups.mockResolvedValue(new Map(DIRECTORY))
  H.getUserGroups.mockImplementation(async (email: string) => [...(DIRECTORY.get(email) ?? ['users'])])
  H.updateUserGroups.mockResolvedValue({})
  H.getAccessReview.mockResolvedValue({
    summary: {}, limits: {},
    identities: [{ email: 'bob@ex.com', tier: 1, flags: ['wildcard'], lastActive: '2026-08-01T00:00:00.000Z' }],
  })
  H.emit.mockResolvedValue(undefined)
}

const futureDeadline = () => new Date(Date.now() + 86_400_000).toISOString()

async function createActive(opts: Partial<{ groups: string[]; reviewers: string[]; onExpiry: 'revoke' | 'flag'; deadline: string }> = {}) {
  const campaign = await recertService.createCampaign(
    {
      name: 'Q3 review',
      scope: opts.groups ? { groups: opts.groups } : undefined,
      reviewers: opts.reviewers ?? ['rev1@ex.com', 'rev2@ex.com'],
      deadline: opts.deadline ?? futureDeadline(),
      onExpiry: opts.onExpiry ?? 'revoke',
    },
    'admin@ex.com',
  )
  await recertService.activateCampaign(campaign.id, ACTOR)
  return recertService.getCampaign(campaign.id)
}

// ── Item generation ───────────────────────────────────────────────────────────
describe('recertService — item generation', () => {
  beforeEach(prime)

  it('generates one item per (user, group) in scope and NEVER for the default users group', async () => {
    const { items } = await createActive() // no scope = all defined groups minus 'users'
    const pairs = items.map((i) => `${i.subject}:${i.entitlement.group}`).sort()
    expect(pairs).toEqual([
      'alice@ex.com:finance',
      'bob@ex.com:eng',
      'bob@ex.com:finance',
      'carol@ex.com:eng',
    ])
    expect(items.every((i) => i.entitlement.group !== 'users')).toBe(true)
    expect(items.every((i) => i.decision === 'pending')).toBe(true)
  })

  it('honours a groups scope filter', async () => {
    const { items } = await createActive({ groups: ['finance'] })
    expect(items.map((i) => i.subject).sort()).toEqual(['alice@ex.com', 'bob@ex.com'])
    expect(items.every((i) => i.entitlement.group === 'finance')).toBe(true)
  })

  it('rejects a campaign scoped to the users group or an unknown group', async () => {
    await expect(
      recertService.createCampaign({ name: 'x', scope: { groups: ['users'] }, reviewers: ['r@ex.com'], deadline: futureDeadline(), onExpiry: 'flag' }, null),
    ).rejects.toThrow(/outside revocable scope/)
    await expect(
      recertService.createCampaign({ name: 'x', scope: { groups: ['nope'] }, reviewers: ['r@ex.com'], deadline: futureDeadline(), onExpiry: 'flag' }, null),
    ).rejects.toThrow(/Unknown group/)
  })

  it('reassigns a self-review item to another reviewer', async () => {
    const { items } = await createActive({ reviewers: ['bob@ex.com', 'rev2@ex.com'] })
    const bobsItems = items.filter((i) => i.subject === 'bob@ex.com')
    expect(bobsItems.length).toBe(2)
    for (const item of bobsItems) {
      expect(item.reviewer).toBe('rev2@ex.com')
      expect(item.context.flags).not.toContain('self-review')
    }
  })

  it('flags self-review as blocking when no other reviewer exists', async () => {
    const { items } = await createActive({ groups: ['eng'], reviewers: ['bob@ex.com'] })
    const own = items.find((i) => i.subject === 'bob@ex.com')!
    expect(own.reviewer).toBe('bob@ex.com')
    expect(own.context.flags).toContain('self-review')
    // Other subjects keep the reviewer without the flag.
    const carol = items.find((i) => i.subject === 'carol@ex.com')!
    expect(carol.context.flags).not.toContain('self-review')
  })

  it('enriches items with the access-review snapshot (tier/flags/lastActive), best-effort', async () => {
    const { items } = await createActive()
    const bob = items.find((i) => i.subject === 'bob@ex.com')!
    expect(bob.context.tier).toBe(1)
    expect(bob.context.flags).toContain('wildcard')
    expect(bob.context.lastActive).toBe('2026-08-01T00:00:00.000Z')

    // A review outage must not block activation.
    H.getAccessReview.mockRejectedValue(new Error('review down'))
    const { items: items2 } = await createActive({ groups: ['finance'] })
    expect(items2.length).toBe(2)
    expect(items2[0].context.tier).toBeNull()
  })

  it('populates the reviewer inbox and refuses to re-activate', async () => {
    const { campaign } = await createActive({ groups: ['finance'] })
    const inbox1 = await recertService.getInbox('rev1@ex.com')
    const inbox2 = await recertService.getInbox('rev2@ex.com')
    expect(inbox1.length + inbox2.length).toBe(2)
    expect(inbox1[0]?.campaignName ?? inbox2[0]?.campaignName).toBe('Q3 review')
    await expect(recertService.activateCampaign(campaign.id, ACTOR)).rejects.toThrow(/not draft/)
  })
})

// ── Decisions ─────────────────────────────────────────────────────────────────
describe('recertService — decisions', () => {
  beforeEach(prime)

  it('records an approve (no Kratos write) and audits it', async () => {
    const { campaign, items } = await createActive({ groups: ['finance'] })
    const item = items.find((i) => i.subject === 'alice@ex.com')!
    const decided = await recertService.decide(campaign.id, item.id, 'approved', undefined, { email: item.reviewer })
    expect(decided.decision).toBe('approved')
    expect(decided.decidedBy).toBe(item.reviewer)
    expect(decided.decidedAt).toBeTruthy()
    expect(H.updateUserGroups).not.toHaveBeenCalled()
    expect(H.emit).toHaveBeenCalledWith(expect.objectContaining({
      category: 'access', verb: 'approve', target: `recert:${campaign.id}:${item.id}`,
    }))
  })

  it('applies a revoke IMMEDIATELY via updateUserGroups and requires a comment', async () => {
    const { campaign, items } = await createActive({ groups: ['finance'] })
    const item = items.find((i) => i.subject === 'alice@ex.com')!

    await expect(
      recertService.decide(campaign.id, item.id, 'revoked', '', { email: item.reviewer }),
    ).rejects.toThrow(/comment is required/)

    const decided = await recertService.decide(campaign.id, item.id, 'revoked', 'left the team', { email: item.reviewer })
    expect(decided.outcome).toBe('revoke-applied')
    expect(H.updateUserGroups).toHaveBeenCalledWith('alice@ex.com', ['users'])
    expect(H.emit).toHaveBeenCalledWith(expect.objectContaining({ verb: 'revoke', severity: 'warn' }))
  })

  it('blocks deciding your own item (self-review guard) and double decisions', async () => {
    const { campaign, items } = await createActive({ groups: ['finance'] })
    const item = items.find((i) => i.subject === 'alice@ex.com')!
    await expect(
      recertService.decide(campaign.id, item.id, 'approved', undefined, { email: 'alice@ex.com' }),
    ).rejects.toThrow(/Self-review is blocked/)

    await recertService.decide(campaign.id, item.id, 'approved', undefined, { email: item.reviewer })
    await expect(
      recertService.decide(campaign.id, item.id, 'approved', undefined, { email: item.reviewer }),
    ).rejects.toThrow(/already decided/)
  })

  it('completes the campaign and freezes the report when the last item is decided', async () => {
    const { campaign, items } = await createActive({ groups: ['finance'] })
    for (const item of items) {
      await recertService.decide(campaign.id, item.id, 'approved', undefined, { email: 'admin2@ex.com' })
    }
    const { campaign: after } = await recertService.getCampaign(campaign.id)
    expect(after.status).toBe('completed')
    expect(after.closedAt).toBeTruthy()
    const report = await recertService.getReport(campaign.id)
    expect(report.counts).toMatchObject({ total: 2, approved: 2, kept: 2, revoked: 0, autoRevoked: 0, flagged: 0 })
  })
})

// ── Expiry / close paths ──────────────────────────────────────────────────────
describe('recertService — expiry (onExpiry revoke | flag)', () => {
  beforeEach(prime)

  it("onExpiry 'revoke': pending items are auto-revoked and the group is really removed", async () => {
    const { campaign, items } = await createActive({ groups: ['eng'], onExpiry: 'revoke' })
    const bobItem = items.find((i) => i.subject === 'bob@ex.com')!
    await recertService.decide(campaign.id, bobItem.id, 'approved', undefined, { email: bobItem.reviewer })

    await recertService.closeCampaign(campaign.id, null, 'deadline')

    const { campaign: after, items: afterItems } = await recertService.getCampaign(campaign.id)
    expect(after.status).toBe('completed')
    expect(afterItems.find((i) => i.subject === 'bob@ex.com')!.outcome).toBe('kept')
    expect(afterItems.find((i) => i.subject === 'carol@ex.com')!.outcome).toBe('auto-revoked')
    // The pending item's group was really removed; the approved one untouched.
    expect(H.updateUserGroups).toHaveBeenCalledTimes(1)
    expect(H.updateUserGroups).toHaveBeenCalledWith('carol@ex.com', ['users'])
    // System-actor audit on the auto-revoke.
    expect(H.emit).toHaveBeenCalledWith(expect.objectContaining({
      verb: 'expire', severity: 'warn', actor: expect.objectContaining({ email: 'system' }),
    }))
  })

  it("onExpiry 'flag': memberships are untouched, items marked flagged", async () => {
    const { campaign } = await createActive({ groups: ['eng'], onExpiry: 'flag' })
    await recertService.closeCampaign(campaign.id, null, 'deadline')
    const { items } = await recertService.getCampaign(campaign.id)
    expect(items.every((i) => i.outcome === 'flagged')).toBe(true)
    expect(H.updateUserGroups).not.toHaveBeenCalled()
  })

  it('scheduler sweep closes only past-deadline active campaigns', async () => {
    // Campaigns can only be CREATED with a future deadline — simulate time
    // passing by rewinding the stored deadline before the sweep runs.
    const past = await createActive({ groups: ['finance'], onExpiry: 'flag' })
    await redisRecertRepository.setCampaign({ ...past.campaign, deadline: new Date(Date.now() - 1000).toISOString() })
    const future = await createActive({ groups: ['eng'], onExpiry: 'flag' })

    await runRecertSweep(LOG)

    expect((await recertService.getCampaign(past.campaign.id)).campaign.status).toBe('completed')
    expect((await recertService.getCampaign(future.campaign.id)).campaign.status).toBe('active')
  })
})

// ── Report freezing ───────────────────────────────────────────────────────────
describe('recertService — completion report', () => {
  beforeEach(prime)

  it('freezes a full report (counters, per-reviewer completion, compliance header, items)', async () => {
    const { campaign, items } = await createActive({ groups: ['finance'], onExpiry: 'flag' })
    const alice = items.find((i) => i.subject === 'alice@ex.com')!
    await recertService.decide(campaign.id, alice.id, 'revoked', 'offboarded', { email: alice.reviewer })
    await recertService.closeCampaign(campaign.id, ACTOR, 'manual')

    const report = await recertService.getReport(campaign.id)
    expect(report.campaignName).toBe('Q3 review')
    expect(report.compliance.iso27001).toContain('A.9.2.5')
    expect(report.compliance.soc2.join(' ')).toContain('CC6.2')
    expect(report.counts).toMatchObject({ total: 2, revoked: 1, flagged: 1, approved: 0 })
    expect(report.items.length).toBe(2)
    const revoked = report.items.find((i) => i.subject === 'alice@ex.com')!
    expect(revoked).toMatchObject({ decision: 'revoked', decidedBy: alice.reviewer, comment: 'offboarded', outcome: 'revoke-applied' })
    expect(Object.values(report.completionByReviewer).reduce((n, r) => n + r.total, 0)).toBe(2)
  })

  it('is write-once: a later write cannot overwrite the frozen report', async () => {
    const { campaign } = await createActive({ groups: ['finance'], onExpiry: 'flag' })
    await recertService.closeCampaign(campaign.id, ACTOR, 'manual')
    const frozen = await recertService.getReport(campaign.id)

    const overwritten = await redisRecertRepository.setReport({ ...frozen, campaignName: 'TAMPERED' })
    expect(overwritten).toBe(false)
    expect((await recertService.getReport(campaign.id)).campaignName).toBe('Q3 review')

    // Closing again is refused too — the campaign is no longer active.
    await expect(recertService.closeCampaign(campaign.id, ACTOR, 'manual')).rejects.toThrow(/not active/)
  })

  it('404s while the campaign is still running', async () => {
    const { campaign } = await createActive({ groups: ['finance'] })
    await expect(recertService.getReport(campaign.id)).rejects.toThrow(RecertError)
  })
})
