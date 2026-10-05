import { getRedisClient } from '../../services/redis-client.service.js'
import { withRedisLock } from '../../services/redis-lock.js'

/**
 * What public sign-up keeps in Redis, outside the site intent:
 *
 *   jinbe:signup:pending:<email>  JSON [{site, at}]   a sign-up that waits for its address to be
 *                                                     verified (the registration guard runs before
 *                                                     the identity exists, so it is keyed by address)
 *   rbac:signup:org_sites         Hash org → [sites]   orgs entitled to a site because they were made
 *                                                     by its sign-up: unioned into the site's orgs on
 *                                                     every publish, so a republish never cuts them off
 *   rbac:org_domains              Hash domain → claim  an org's claim on an email domain, proven by a
 *                                                     DNS TXT record (sign-up `orgs: domain`)
 *
 * None of these is in the bootstrap wipe: they are not generated from the intents.
 */

export const PENDING_TTL_SEC = 30 * 24 * 3600
const pendingKey = (email: string) => `jinbe:signup:pending:${email.trim().toLowerCase()}`
const ORG_SITES = 'rbac:signup:org_sites'
const DOMAINS = 'rbac:org_domains'

export interface PendingJoin { site: string; at: string }

export interface DomainClaim {
  domain: string
  org: string
  /** The value the TXT record must carry. */
  token: string
  verified: boolean
  claimedAt: string
  verifiedAt?: string
}

const redis = () => getRedisClient()

function parseList<T>(raw: string | null | undefined, ok: (v: unknown) => v is T): T[] {
  if (!raw) return []
  try {
    const v: unknown = JSON.parse(raw)
    return Array.isArray(v) ? v.filter(ok) : []
  } catch {
    return []
  }
}
const isPending = (v: unknown): v is PendingJoin =>
  !!v && typeof (v as PendingJoin).site === 'string' && typeof (v as PendingJoin).at === 'string'
const isString = (v: unknown): v is string => typeof v === 'string' && v.length > 0

export const signUpStore = {
  /** Remembers that this address signed up through this site; one entry per site, refreshed. */
  async addPending(email: string, site: string, now = new Date()): Promise<void> {
    const key = pendingKey(email)
    await withRedisLock(`signup-pending:${email.trim().toLowerCase()}`, async () => {
      const list = parseList(await redis().get(key), isPending).filter((p) => p.site !== site)
      list.push({ site, at: now.toISOString() })
      await redis().set(key, JSON.stringify(list), 'EX', PENDING_TTL_SEC)
    })
  },

  async pending(email: string): Promise<PendingJoin[]> {
    return parseList(await redis().get(pendingKey(email)), isPending)
  },

  async clearPending(email: string, site: string): Promise<void> {
    const key = pendingKey(email)
    await withRedisLock(`signup-pending:${email.trim().toLowerCase()}`, async () => {
      const list = parseList(await redis().get(key), isPending).filter((p) => p.site !== site)
      if (list.length === 0) await redis().del(key)
      else await redis().set(key, JSON.stringify(list), 'KEEPTTL')
    })
  },

  /** org → sites it is entitled to through sign-up. */
  async orgSites(): Promise<Record<string, string[]>> {
    const raw = await redis().hgetall(ORG_SITES)
    return Object.fromEntries(Object.entries(raw).map(([org, v]) => [org, parseList(v, isString)]))
  },

  /** The orgs a site's sign-up made (or brought in by domain). */
  async orgsOf(site: string): Promise<string[]> {
    return Object.entries(await this.orgSites()).filter(([, sites]) => sites.includes(site)).map(([org]) => org).sort()
  },

  async addOrgSite(org: string, site: string): Promise<void> {
    await withRedisLock('signup-org-sites', async () => {
      const sites = parseList(await redis().hget(ORG_SITES, org), isString)
      if (!sites.includes(site)) await redis().hset(ORG_SITES, org, JSON.stringify([...sites, site].sort()))
    })
  },

  /** A site deleted (or an org): its sign-up entitlements go. */
  async forgetSite(site: string): Promise<void> {
    await withRedisLock('signup-org-sites', async () => {
      for (const [org, sites] of Object.entries(await this.orgSites())) {
        if (!sites.includes(site)) continue
        const rest = sites.filter((s) => s !== site)
        if (rest.length) await redis().hset(ORG_SITES, org, JSON.stringify(rest))
        else await redis().hdel(ORG_SITES, org)
      }
    })
  },

  async forgetOrg(org: string): Promise<void> {
    await redis().hdel(ORG_SITES, org)
    for (const claim of await this.domainsOf(org)) await redis().hdel(DOMAINS, claim.domain)
  },

  // ── Domain claims ──

  async domain(domain: string): Promise<DomainClaim | null> {
    const raw = await redis().hget(DOMAINS, domain.toLowerCase())
    if (!raw) return null
    try {
      return JSON.parse(raw) as DomainClaim
    } catch {
      return null
    }
  },

  async domainsOf(org: string): Promise<DomainClaim[]> {
    const raw = await redis().hgetall(DOMAINS)
    const out: DomainClaim[] = []
    for (const v of Object.values(raw)) {
      try {
        const c = JSON.parse(v) as DomainClaim
        if (c.org === org) out.push(c)
      } catch { /* an unreadable claim proves nothing */ }
    }
    return out.sort((a, b) => a.domain.localeCompare(b.domain))
  },

  async putDomain(claim: DomainClaim): Promise<void> {
    await redis().hset(DOMAINS, claim.domain, JSON.stringify(claim))
  },

  async removeDomain(domain: string): Promise<void> {
    await redis().hdel(DOMAINS, domain.toLowerCase())
  },
}
