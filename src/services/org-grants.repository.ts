import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Org grants — the groups an org admin handed out IN THEIR ORG (feeds data.org_grants).
 *
 *   rbac:org_grants → Hash: { organizationId: JSON({ email: [group, …] }) }
 *
 * Next to rbac:org_service_map and rbac:org_admins: one field per org, so a write reads and rewrites
 * only that org's map, under that org's lock. The policy (opal-policies org.rego) counts a grant only
 * on the routes of the org that holds it, and only a group's service roles — never its global ones.
 *
 * Emails are stored lowercased: the policy compares them verbatim with the bindings' keys.
 */

export type OrgGrants = Record<string, Record<string, string[]>> // { org: { email: groups[] } }

const KEY = 'rbac:org_grants'

function normalizeMembers(raw: string): Record<string, string[]> {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return {}
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
  const out: Record<string, string[]> = {}
  for (const [email, groups] of Object.entries(parsed as Record<string, unknown>)) {
    if (!Array.isArray(groups)) continue
    const valid = groups.filter((g): g is string => typeof g === 'string' && g.length > 0)
    if (valid.length > 0) out[email] = valid
  }
  return out
}

class OrgGrantsRepository {
  private get redis() { return getRedisClient() }

  /** The whole map. Throws when Redis cannot be read — callers must never publish a partial map. */
  async getAll(): Promise<OrgGrants> {
    const raw = await this.redis.hgetall(KEY)
    const out: OrgGrants = {}
    for (const [org, value] of Object.entries(raw)) {
      const members = normalizeMembers(value)
      if (Object.keys(members).length > 0) out[org] = members
    }
    return out
  }

  async getForOrg(organizationId: string): Promise<Record<string, string[]>> {
    const raw = await this.redis.hget(KEY, organizationId)
    return raw === null ? {} : normalizeMembers(raw)
  }

  async getForMember(organizationId: string, email: string): Promise<string[]> {
    return (await this.getForOrg(organizationId))[email.toLowerCase()] ?? []
  }

  /**
   * Replace one member's grants in one org with exactly `groups` (deduped, sorted); an empty list
   * drops the member, and an org left with nobody drops its field. Returns what was there before.
   */
  async setForMember(organizationId: string, email: string, groups: string[]): Promise<string[]> {
    const member = email.toLowerCase()
    return withRedisLock(`org_grants:${organizationId}`, async () => {
      const members = await this.getForOrg(organizationId)
      const before = members[member] ?? []
      const next = [...new Set(groups.filter((g) => typeof g === 'string' && g.length > 0))].sort()
      if (next.length > 0) members[member] = next
      else delete members[member]

      if (Object.keys(members).length > 0) await this.redis.hset(KEY, organizationId, JSON.stringify(members))
      else await this.redis.hdel(KEY, organizationId)
      return before
    })
  }
}

export const orgGrantsRepository = new OrgGrantsRepository()
