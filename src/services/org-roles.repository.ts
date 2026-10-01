import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Org role assignments — who holds which org role in which organisation (authz-v2-design §2.2; the
 * storage comparison is in that document, §8):
 *
 *   rbac:org_assignments → Hash: { organizationId: JSON({ subjectId: ["svc:role", …] }) }
 *
 * In jinbe's own store, next to the groups, so "who holds role X in org Y" is one field read, every
 * write is audited by jinbe and lands in the RBAC bundle (backup, restore), and the OPAL bindings
 * feed publishes it in the same document as group memberships (data.bindings.org_assignments, by
 * address). Keyed by the identity id: an address can change, the subject cannot.
 *
 * One field per org, so a write reads and rewrites only that org, under that org's lock. An
 * assignment counts only while its holder is a member of the org: the feed and the policy both check.
 */

export type OrgAssignments = Record<string, Record<string, string[]>> // { org: { subjectId: roles[] } }

const KEY = 'rbac:org_assignments'

/** `svc:role`, both parts lowercase names. */
export const QUALIFIED_ROLE = /^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$/

function parseMembers(raw: string): Record<string, string[]> {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return {}
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
  const out: Record<string, string[]> = {}
  for (const [subject, roles] of Object.entries(parsed as Record<string, unknown>)) {
    if (!Array.isArray(roles)) continue
    const valid = roles.filter((r): r is string => typeof r === 'string' && QUALIFIED_ROLE.test(r))
    if (valid.length > 0) out[subject] = [...new Set(valid)].sort()
  }
  return out
}

class OrgRolesRepository {
  private get redis() { return getRedisClient() }

  /** Everything. Throws when Redis cannot be read — callers must never publish a partial map. */
  async getAll(): Promise<OrgAssignments> {
    const raw = await this.redis.hgetall(KEY)
    const out: OrgAssignments = {}
    for (const [org, value] of Object.entries(raw)) {
      const members = parseMembers(value)
      if (Object.keys(members).length > 0) out[org] = members
    }
    return out
  }

  async getForOrg(organizationId: string): Promise<Record<string, string[]>> {
    const raw = await this.redis.hget(KEY, organizationId)
    return raw === null ? {} : parseMembers(raw)
  }

  async getForMember(organizationId: string, subjectId: string): Promise<string[]> {
    return (await this.getForOrg(organizationId))[subjectId] ?? []
  }

  /** The holders of one role in one org: "who holds role X in org Y". */
  async holdersOf(organizationId: string, role: string): Promise<string[]> {
    return Object.entries(await this.getForOrg(organizationId)).filter(([, rs]) => rs.includes(role)).map(([s]) => s).sort()
  }

  /**
   * Exactly `roles` for one member of one org (deduped, sorted); an empty list drops the member, and
   * an org left with nobody drops its field. Returns what was there before.
   */
  async setForMember(organizationId: string, subjectId: string, roles: readonly string[]): Promise<string[]> {
    return withRedisLock(`org_assignments:${organizationId}`, async () => {
      const members = await this.getForOrg(organizationId)
      const before = members[subjectId] ?? []
      const next = [...new Set(roles.filter((r) => QUALIFIED_ROLE.test(r)))].sort()
      if (next.length > 0) members[subjectId] = next
      else delete members[subjectId]
      if (Object.keys(members).length > 0) await this.redis.hset(KEY, organizationId, JSON.stringify(members))
      else await this.redis.hdel(KEY, organizationId)
      return before
    })
  }

  /** A member left the org: their roles there go with them. */
  async forgetMember(organizationId: string, subjectId: string): Promise<void> {
    await this.setForMember(organizationId, subjectId, [])
  }

  /** The org was deleted. */
  async forgetOrg(organizationId: string): Promise<void> {
    await this.redis.hdel(KEY, organizationId)
  }
}

export const orgRolesRepository = new OrgRolesRepository()
