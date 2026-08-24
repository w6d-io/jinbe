import { randomUUID } from 'node:crypto'
import { kratosService } from './kratos.service.js'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { accessReviewService } from './access-review.service.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'
import { withRedisLock } from './redis-lock.js'
import {
  redisRecertRepository,
  type RecertCampaign,
  type RecertItem,
  type RecertItemContext,
  type RecertOnExpiry,
  type RecertReport,
  type RecertScope,
} from './redis-recert.repository.js'

/**
 * Access Recertification service (docs/specs/access-recertification.md, phase 1).
 *
 * Campaigns turn the read-only access-review snapshot into decision items
 * (one per user × group in scope) assigned to explicit reviewers, with a
 * deadline and an on-expiry consequence (revoke | flag). Reviewer-decided
 * revokes are applied IMMEDIATELY (a validated revocation must not wait for
 * the deadline); pending items are resolved by the deadline job / manual close.
 *
 * Guard rails:
 * - the default 'users' group is NEVER in revocable scope (revoking a user's
 *   last group would leave them accessless — mirrors kratos.service's default);
 * - a reviewer cannot decide an item they are the SUBJECT of — the item is
 *   reassigned to another reviewer at generation; if none exists it carries a
 *   blocking 'self-review' flag and only another admin can decide it.
 */

/** Default group every identity implicitly holds — never revocable (spec §9). */
const DEFAULT_GROUP = 'users'

export class RecertError extends Error {
  statusCode: number
  constructor(statusCode: number, message: string) {
    super(message)
    this.statusCode = statusCode
  }
}

export interface CreateCampaignInput {
  name: string
  scope?: RecertScope
  reviewers: string[]
  deadline: string
  onExpiry: RecertOnExpiry
}

export interface CampaignSummary extends RecertCampaign {
  itemCount: number
  decidedCount: number
}

const norm = (email: string) => email.trim().toLowerCase()

class RecertService {
  // ── Campaign CRUD ──────────────────────────────────────────────────────────

  async createCampaign(input: CreateCampaignInput, createdBy: string | null): Promise<RecertCampaign> {
    const name = input.name?.trim()
    if (!name) throw new RecertError(400, 'name is required')
    const reviewers = [...new Set((input.reviewers ?? []).map(norm).filter(Boolean))]
    if (reviewers.length === 0) throw new RecertError(400, 'At least one reviewer email is required (phase 1: explicit reviewers).')
    const deadlineMs = Date.parse(input.deadline ?? '')
    if (Number.isNaN(deadlineMs)) throw new RecertError(400, 'deadline must be a valid ISO date')
    // A past deadline would make the hourly sweep close the campaign (and
    // apply onExpiry) before anyone could review a single item.
    if (deadlineMs <= Date.now()) throw new RecertError(400, 'deadline must be in the future')
    if (input.onExpiry !== 'revoke' && input.onExpiry !== 'flag') throw new RecertError(400, "onExpiry must be 'revoke' or 'flag'")

    const scopeGroups = (input.scope?.groups ?? []).map((g) => g.trim()).filter(Boolean)
    if (scopeGroups.includes(DEFAULT_GROUP)) {
      throw new RecertError(400, `The default '${DEFAULT_GROUP}' group is outside revocable scope and cannot be recertified.`)
    }
    if (scopeGroups.length > 0) {
      const known = await redisRbacRepository.getGroups()
      const missing = scopeGroups.filter((g) => !(g in known))
      if (missing.length > 0) throw new RecertError(400, `Unknown group(s): ${missing.join(', ')}`)
    }

    const campaign: RecertCampaign = {
      id: randomUUID(),
      name,
      scope: { groups: scopeGroups.length > 0 ? scopeGroups : undefined },
      reviewerPolicy: 'explicit',
      reviewers,
      schedule: { kind: 'one-shot' },
      deadline: new Date(deadlineMs).toISOString(),
      onExpiry: input.onExpiry,
      status: 'draft',
      createdBy,
      createdAt: new Date().toISOString(),
    }
    await redisRecertRepository.setCampaign(campaign)
    return campaign
  }

  async listCampaigns(): Promise<CampaignSummary[]> {
    const campaigns = await redisRecertRepository.getCampaigns()
    const out: CampaignSummary[] = []
    for (const c of campaigns) {
      const items = await redisRecertRepository.getItems(c.id)
      out.push({
        ...c,
        itemCount: items.length,
        decidedCount: items.filter((i) => i.decision !== 'pending').length,
      })
    }
    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }

  async getCampaign(id: string): Promise<{ campaign: RecertCampaign; items: RecertItem[] }> {
    const campaign = await redisRecertRepository.getCampaign(id)
    if (!campaign) throw new RecertError(404, `Campaign not found: ${id}`)
    const items = await redisRecertRepository.getItems(id)
    return { campaign, items }
  }

  async deleteCampaign(id: string): Promise<void> {
    const campaign = await redisRecertRepository.getCampaign(id)
    if (!campaign) throw new RecertError(404, `Campaign not found: ${id}`)
    if (campaign.status !== 'draft' && campaign.status !== 'archived') {
      throw new RecertError(409, `Only draft or archived campaigns can be deleted (status: ${campaign.status}).`)
    }
    const items = await redisRecertRepository.getItems(id)
    for (const item of items) await redisRecertRepository.removeFromInbox(item.reviewer, id, item.id)
    await redisRecertRepository.deleteItems(id)
    await redisRecertRepository.deleteCampaign(id)
  }

  // ── Item generation (activation) ───────────────────────────────────────────

  async activateCampaign(id: string, actor: AuditActorInput): Promise<{ campaign: RecertCampaign; itemCount: number }> {
    return withRedisLock(`recert:${id}`, async () => {
      const campaign = await redisRecertRepository.getCampaign(id)
      if (!campaign) throw new RecertError(404, `Campaign not found: ${id}`)
      if (campaign.status !== 'draft') throw new RecertError(409, `Campaign is not draft (status: ${campaign.status}).`)

      const items = await this.generateItems(campaign)
      await redisRecertRepository.setItems(id, items)
      for (const item of items) await redisRecertRepository.addToInbox(item.reviewer, id, item.id)

      campaign.status = 'active'
      await redisRecertRepository.setCampaign(campaign)

      auditEventService.emit({
        category: 'access', kind: 'change', verb: 'activate', target: `recert:${id}`,
        result: 'applied',
        actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId },
        requestId: actor.requestId,
        details: { campaign: campaign.name, items: items.length, reviewers: campaign.reviewers },
      }).catch(() => {})

      return { campaign, itemCount: items.length }
    })
  }

  /**
   * Walk groups→members via Kratos: one ReviewItem per (user, group) in scope.
   * - the default 'users' group is excluded (never revocable);
   * - scope.groups omitted = every group defined in rbac:groups;
   * - reviewers assigned round-robin, with the self-review guard: an item whose
   *   subject IS the assigned reviewer is reassigned to another reviewer, or
   *   carries a blocking 'self-review' context flag when no other exists.
   * Enriched with the access-review snapshot (tier/flags/lastActive), best-effort.
   */
  private async generateItems(campaign: RecertCampaign): Promise<RecertItem[]> {
    const definedGroups = new Set(Object.keys(await redisRbacRepository.getGroups()))
    definedGroups.delete(DEFAULT_GROUP)
    const scoped = campaign.scope.groups?.length
      ? campaign.scope.groups.filter((g) => g !== DEFAULT_GROUP)
      : [...definedGroups]
    const scopeSet = new Set(scoped)

    // Access-review context snapshot (decision aid) — best-effort: a review
    // outage must not block campaign activation.
    const context = new Map<string, RecertItemContext>()
    try {
      const review = await accessReviewService.getAccessReview()
      for (const ident of review.identities) {
        context.set(norm(ident.email), { tier: ident.tier, flags: ident.flags, lastActive: ident.lastActive })
      }
    } catch { /* snapshot unavailable — items carry an empty context */ }

    const directory = await kratosService.getAllIdentitiesWithGroups()
    const items: RecertItem[] = []
    let rr = 0
    for (const [email, groups] of directory) {
      const subject = norm(email)
      for (const group of groups) {
        if (!scopeSet.has(group)) continue
        // Round-robin assignment + self-review guard (spec §2).
        let reviewer = campaign.reviewers[rr++ % campaign.reviewers.length]
        const flags: string[] = []
        if (reviewer === subject) {
          const fallback = campaign.reviewers.find((r) => r !== subject)
          if (fallback) reviewer = fallback
          else flags.push('self-review')
        }
        const ctx = context.get(subject)
        items.push({
          id: randomUUID(),
          campaignId: campaign.id,
          subject,
          entitlement: { kind: 'group-membership', group },
          reviewer,
          decision: 'pending',
          context: {
            tier: ctx?.tier ?? null,
            flags: [...(ctx?.flags ?? []), ...flags],
            lastActive: ctx?.lastActive ?? null,
          },
        })
      }
    }
    return items
  }

  // ── Decisions ──────────────────────────────────────────────────────────────

  /**
   * Record a reviewer decision. `revoke` requires a comment and is applied
   * IMMEDIATELY (group removed in Kratos). Caller authorization (assigned
   * reviewer or admin) is enforced by the route; the self-review guard is
   * enforced here unconditionally: nobody decides their own membership.
   */
  async decide(
    campaignId: string,
    itemId: string,
    decision: 'approved' | 'revoked',
    comment: string | undefined,
    actor: AuditActorInput,
  ): Promise<RecertItem> {
    const decidedBy = actor.email ? norm(actor.email) : null
    if (!decidedBy) throw new RecertError(401, 'Authenticated identity required')

    return withRedisLock(`recert:${campaignId}`, async () => {
      const campaign = await redisRecertRepository.getCampaign(campaignId)
      if (!campaign) throw new RecertError(404, `Campaign not found: ${campaignId}`)
      if (campaign.status !== 'active') throw new RecertError(409, `Campaign is not active (status: ${campaign.status}).`)
      const item = await redisRecertRepository.getItem(campaignId, itemId)
      if (!item) throw new RecertError(404, `Item not found: ${itemId}`)
      if (item.decision !== 'pending') throw new RecertError(409, `Item already decided (${item.decision} by ${item.decidedBy}).`)
      if (norm(item.subject) === decidedBy) {
        throw new RecertError(403, 'Self-review is blocked: you cannot decide an item you are the subject of.')
      }
      if (decision === 'revoked' && !comment?.trim()) {
        throw new RecertError(400, 'A comment is required when revoking.')
      }

      item.decision = decision
      item.decidedBy = decidedBy
      item.decidedAt = new Date().toISOString()
      if (comment?.trim()) item.comment = comment.trim()

      // Apply a validated revoke immediately — it must not wait for the deadline.
      if (decision === 'revoked') {
        await this.removeGroupMembership(item.subject, item.entitlement.group)
        item.outcome = 'revoke-applied'
      }

      await redisRecertRepository.setItem(item)
      await redisRecertRepository.removeFromInbox(item.reviewer, campaignId, itemId)

      auditEventService.emit({
        category: 'access', kind: 'change',
        verb: decision === 'revoked' ? 'revoke' : 'approve',
        target: `recert:${campaignId}:${itemId}`,
        result: 'applied',
        severity: decision === 'revoked' ? 'warn' : 'info',
        actor: { email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId },
        requestId: actor.requestId,
        details: {
          campaign: campaign.name, subject: item.subject,
          group: item.entitlement.group, decision, comment: item.comment ?? null,
        },
      }).catch(() => {})

      // Last pending decision completes the campaign (and freezes the report).
      const remaining = (await redisRecertRepository.getItems(campaignId)).filter((i) => i.decision === 'pending')
      if (remaining.length === 0) await this.finalize(campaign, 'all-decided')

      return item
    })
  }

  // ── Close / expiry ─────────────────────────────────────────────────────────

  /**
   * Close a campaign: pending items get the onExpiry consequence
   * (revoke → group removed in Kratos, outcome 'auto-revoked';
   *  flag → outcome 'flagged'), then the completion report is frozen.
   * `actor` null = the system scheduler (deadline job).
   */
  async closeCampaign(id: string, actor: AuditActorInput | null, reason: 'manual' | 'deadline' | 'all-decided' = 'manual'): Promise<RecertCampaign> {
    return withRedisLock(`recert:${id}`, async () => {
      const campaign = await redisRecertRepository.getCampaign(id)
      if (!campaign) throw new RecertError(404, `Campaign not found: ${id}`)
      if (campaign.status !== 'active') throw new RecertError(409, `Campaign is not active (status: ${campaign.status}).`)

      campaign.status = 'closing'
      await redisRecertRepository.setCampaign(campaign)

      const actorEmail = actor?.email ?? 'system'
      const items = await redisRecertRepository.getItems(id)
      for (const item of items) {
        if (item.decision !== 'pending') continue
        if (campaign.onExpiry === 'revoke') {
          await this.removeGroupMembership(item.subject, item.entitlement.group)
          item.outcome = 'auto-revoked'
        } else {
          item.outcome = 'flagged'
        }
        await redisRecertRepository.setItem(item)
        await redisRecertRepository.removeFromInbox(item.reviewer, id, item.id)
        auditEventService.emit({
          category: 'access', kind: 'change',
          verb: campaign.onExpiry === 'revoke' ? 'expire' : 'flag',
          target: `recert:${id}:${item.id}`,
          result: 'applied',
          severity: campaign.onExpiry === 'revoke' ? 'warn' : 'info',
          actor: { email: actorEmail },
          requestId: actor?.requestId ?? null,
          details: { campaign: campaign.name, subject: item.subject, group: item.entitlement.group, onExpiry: campaign.onExpiry, reason },
        }).catch(() => {})
      }

      await this.finalize(campaign, reason, actor)
      return campaign
    })
  }

  /** Mark approved items 'kept', freeze the completion report, complete the campaign. */
  private async finalize(campaign: RecertCampaign, reason: string, actor?: AuditActorInput | null): Promise<void> {
    const items = await redisRecertRepository.getItems(campaign.id)
    for (const item of items) {
      if (item.decision === 'approved' && !item.outcome) {
        item.outcome = 'kept'
        await redisRecertRepository.setItem(item)
      }
    }

    campaign.status = 'completed'
    campaign.closedAt = new Date().toISOString()
    await redisRecertRepository.setCampaign(campaign)
    await redisRecertRepository.setReport(this.buildReport(campaign, await redisRecertRepository.getItems(campaign.id)))

    auditEventService.emit({
      category: 'access', kind: 'change', verb: 'close', target: `recert:${campaign.id}`,
      result: 'applied',
      actor: { email: actor?.email ?? 'system' },
      requestId: actor?.requestId ?? null,
      details: { campaign: campaign.name, reason, items: items.length },
    }).catch(() => {})
  }

  private buildReport(campaign: RecertCampaign, items: RecertItem[]): RecertReport {
    const completionByReviewer: Record<string, { decided: number; total: number }> = {}
    for (const item of items) {
      const row = (completionByReviewer[item.reviewer] ??= { decided: 0, total: 0 })
      row.total++
      if (item.decision !== 'pending') row.decided++
    }
    return {
      campaignId: campaign.id,
      campaignName: campaign.name,
      generatedAt: new Date().toISOString(),
      deadline: campaign.deadline,
      onExpiry: campaign.onExpiry,
      compliance: {
        iso27001: 'A.9.2.5 — Review of user access rights',
        soc2: ['CC6.2 — access authorization', 'CC6.3 — access modification & removal'],
      },
      counts: {
        total: items.length,
        approved: items.filter((i) => i.decision === 'approved').length,
        revoked: items.filter((i) => i.outcome === 'revoke-applied').length,
        autoRevoked: items.filter((i) => i.outcome === 'auto-revoked').length,
        flagged: items.filter((i) => i.outcome === 'flagged').length,
        kept: items.filter((i) => i.outcome === 'kept').length,
      },
      completionByReviewer,
      items,
    }
  }

  async getReport(campaignId: string): Promise<RecertReport> {
    const report = await redisRecertRepository.getReport(campaignId)
    if (!report) throw new RecertError(404, 'No report — the campaign has not completed yet.')
    return report
  }

  // ── Reviewer inbox ─────────────────────────────────────────────────────────

  async getInbox(reviewerEmail: string): Promise<Array<RecertItem & { campaignName: string; deadline: string }>> {
    const refs = await redisRecertRepository.getInboxRefs(norm(reviewerEmail))
    const campaigns = new Map<string, RecertCampaign | null>()
    const out: Array<RecertItem & { campaignName: string; deadline: string }> = []
    for (const { campaignId, itemId } of refs) {
      if (!campaigns.has(campaignId)) campaigns.set(campaignId, await redisRecertRepository.getCampaign(campaignId))
      const campaign = campaigns.get(campaignId)
      if (!campaign || campaign.status !== 'active') continue
      const item = await redisRecertRepository.getItem(campaignId, itemId)
      if (!item || item.decision !== 'pending') continue
      out.push({ ...item, campaignName: campaign.name, deadline: campaign.deadline })
    }
    return out
  }

  // ── Group-membership revoke (the ONE write path to Kratos) ─────────────────

  /**
   * Remove `group` from the subject's metadata_admin.groups via the existing
   * kratosService.updateUserGroups path. Never leaves the user groupless —
   * falls back to the default 'users' group (mirrors admin.routes behaviour).
   * Idempotent: a subject no longer holding the group is a no-op.
   */
  private async removeGroupMembership(subject: string, group: string): Promise<void> {
    const current = await kratosService.getUserGroups(subject)
    if (!current.includes(group)) return
    const next = current.filter((g) => g !== group)
    await kratosService.updateUserGroups(subject, next.length > 0 ? next : [DEFAULT_GROUP])
  }
}

export const recertService = new RecertService()
