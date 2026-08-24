import { getRedisClient } from './redis-client.service.js'

/**
 * Redis Recertification Repository
 *
 * Storage for access-recertification campaigns (docs/specs/access-recertification.md).
 * Same style as redis-rbac.repository.ts; keys live under the rbac:recert:* namespace:
 *
 *   rbac:recert:campaigns              → Hash: { campaignId: JSON(RecertCampaign) }
 *   rbac:recert:items:{campaignId}     → Hash: { itemId: JSON(RecertItem) }
 *   rbac:recert:inbox:{reviewerEmail}  → Set:  [ "{campaignId}:{itemId}" ]  (inverse inbox index)
 *   rbac:recert:reports                → Hash: { campaignId: JSON(RecertReport) }  (frozen at close)
 *
 * No TTL: reports are audit evidence; purge is manual (archive + export first).
 * Item writes happen under withRedisLock(`recert:{campaignId}`) in recert.service.
 */

// ─────────────────────────────────────────────────────────────
// Types (spec §2 — phase 1: explicit reviewers, one-shot schedule)
// ─────────────────────────────────────────────────────────────

export type RecertOnExpiry = 'revoke' | 'flag'
export type RecertStatus = 'draft' | 'active' | 'closing' | 'completed' | 'archived'
export type RecertDecision = 'pending' | 'approved' | 'revoked'
export type RecertOutcome = 'kept' | 'auto-revoked' | 'flagged' | 'revoke-applied'

export interface RecertScope {
  /** Group names to review. Omitted/empty = all rbac:groups (minus the default 'users' group). */
  groups?: string[]
}

export interface RecertCampaign {
  id: string
  name: string
  scope: RecertScope
  reviewerPolicy: 'explicit'
  reviewers: string[]
  schedule: { kind: 'one-shot' }
  deadline: string            // ISO
  onExpiry: RecertOnExpiry
  status: RecertStatus
  createdBy: string | null
  createdAt: string
  closedAt?: string
}

export interface RecertItemContext {
  /** Access-review snapshot at generation time (null tier = not privileged / unavailable). */
  tier: number | null
  flags: string[]
  lastActive: string | null
}

export interface RecertItem {
  id: string
  campaignId: string
  subject: string             // email of the user under review
  entitlement: { kind: 'group-membership'; group: string }
  reviewer: string            // assigned reviewer email
  decision: RecertDecision
  decidedBy?: string
  decidedAt?: string
  comment?: string
  outcome?: RecertOutcome     // filled at close (or immediately on applied revoke)
  context: RecertItemContext
}

export interface RecertReport {
  campaignId: string
  campaignName: string
  generatedAt: string
  deadline: string
  onExpiry: RecertOnExpiry
  /** Compliance mapping header (ISO 27001 A.9.2.5 / SOC 2 CC6.2–CC6.3). */
  compliance: { iso27001: string; soc2: string[] }
  counts: {
    total: number
    approved: number
    revoked: number          // reviewer-decided revokes (applied immediately)
    autoRevoked: number
    flagged: number
    kept: number
  }
  completionByReviewer: Record<string, { decided: number; total: number }>
  items: RecertItem[]
}

const CAMPAIGNS_KEY = 'rbac:recert:campaigns'
const REPORTS_KEY = 'rbac:recert:reports'
const itemsKey = (campaignId: string) => `rbac:recert:items:${campaignId}`
const inboxKey = (reviewer: string) => `rbac:recert:inbox:${reviewer.toLowerCase()}`

// ─────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────

class RedisRecertRepository {
  private get redis() { return getRedisClient() }

  // ── Campaigns ──
  async getCampaigns(): Promise<RecertCampaign[]> {
    const raw = await this.redis.hgetall(CAMPAIGNS_KEY)
    return Object.values(raw).map((json) => JSON.parse(json) as RecertCampaign)
  }

  async getCampaign(id: string): Promise<RecertCampaign | null> {
    const raw = await this.redis.hget(CAMPAIGNS_KEY, id)
    return raw ? (JSON.parse(raw) as RecertCampaign) : null
  }

  async setCampaign(campaign: RecertCampaign): Promise<void> {
    await this.redis.hset(CAMPAIGNS_KEY, campaign.id, JSON.stringify(campaign))
  }

  async deleteCampaign(id: string): Promise<void> {
    await this.redis.hdel(CAMPAIGNS_KEY, id)
  }

  // ── Items ──
  async getItems(campaignId: string): Promise<RecertItem[]> {
    const raw = await this.redis.hgetall(itemsKey(campaignId))
    return Object.values(raw).map((json) => JSON.parse(json) as RecertItem)
  }

  async getItem(campaignId: string, itemId: string): Promise<RecertItem | null> {
    const raw = await this.redis.hget(itemsKey(campaignId), itemId)
    return raw ? (JSON.parse(raw) as RecertItem) : null
  }

  async setItem(item: RecertItem): Promise<void> {
    await this.redis.hset(itemsKey(item.campaignId), item.id, JSON.stringify(item))
  }

  async setItems(campaignId: string, items: RecertItem[]): Promise<void> {
    if (items.length === 0) return
    const flat: string[] = []
    for (const item of items) flat.push(item.id, JSON.stringify(item))
    await this.redis.hset(itemsKey(campaignId), ...flat)
  }

  async deleteItems(campaignId: string): Promise<void> {
    await this.redis.del(itemsKey(campaignId))
  }

  async countItems(campaignId: string): Promise<number> {
    return this.redis.hlen(itemsKey(campaignId))
  }

  // ── Reviewer inbox (inverse index: "{campaignId}:{itemId}") ──
  async addToInbox(reviewer: string, campaignId: string, itemId: string): Promise<void> {
    await this.redis.sadd(inboxKey(reviewer), `${campaignId}:${itemId}`)
  }

  async removeFromInbox(reviewer: string, campaignId: string, itemId: string): Promise<void> {
    await this.redis.srem(inboxKey(reviewer), `${campaignId}:${itemId}`)
  }

  async getInboxRefs(reviewer: string): Promise<Array<{ campaignId: string; itemId: string }>> {
    const members = await this.redis.smembers(inboxKey(reviewer))
    return members
      .map((m) => {
        const sep = m.indexOf(':')
        return sep > 0 ? { campaignId: m.slice(0, sep), itemId: m.slice(sep + 1) } : null
      })
      .filter((r): r is { campaignId: string; itemId: string } => r !== null)
  }

  // ── Reports (frozen — write-once at close) ──
  async getReport(campaignId: string): Promise<RecertReport | null> {
    const raw = await this.redis.hget(REPORTS_KEY, campaignId)
    return raw ? (JSON.parse(raw) as RecertReport) : null
  }

  /** Write-once: refuses to overwrite an existing (frozen) report. */
  async setReport(report: RecertReport): Promise<boolean> {
    const created = await this.redis.hsetnx(REPORTS_KEY, report.campaignId, JSON.stringify(report))
    return created === 1
  }

  async deleteReport(campaignId: string): Promise<void> {
    await this.redis.hdel(REPORTS_KEY, campaignId)
  }
}

export const redisRecertRepository = new RedisRecertRepository()
