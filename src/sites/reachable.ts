import { SwrCache } from '../cache/swr.js'
import { queryOpa } from '../services/opa-client.js'
import { SYSTEM_SITES, type Site } from './schemas.js'
import { sitesRepository } from './repository.js'
import { liveSite } from './login.js'
import { landingOf } from './mine.js'
import { kindOf } from './hosts.js'
import { PROBE_EMAIL } from './verify-access.js'

/**
 * `GET /api/admin/users/:id/reachable-sites` — the sites one person can open in a browser, for the
 * console's "open as this person" links (impersonation) and its warning when there are none.
 *
 * A site is listed when the gateway would let that person GET its entry page — the landing page
 * login-ui also sends them to (mine.ts `landingOf`) — and impersonating them changes what is shown
 * there. Like mine.ts, "would let" is the gateway's own answer, never a replay of it: OPA
 * `rbac/decision` for a GET of the entry path in the site's app, with the person's address, at aal2
 * (an impersonated session carries the administrator's aal2), which is the site layer, the org layer
 * and per-site 2FA in one verdict. Two more questions, the same for every person, say HOW it opens:
 *
 *   - asked with no address at all, as the gateway asks for an anonymous visitor: allowed means the
 *     page is public — left out, impersonation changes nothing there;
 *   - asked for a signed-in account that holds nothing (verify-access.ts PROBE_EMAIL, named by no
 *     binding): allowed means any signed-in person may open it → `signed-in`; refused, the person
 *     opens it on something they hold → `role`.
 *
 * Only applied, unpaused, non-system sites whose pages are for a browser (hosts.ts `kindOf`: not
 * every gate answering refusals as JSON) are asked about.
 *
 * COST: one OPA decision per candidate site for the person, kept 30 s per address, plus two per site
 * that are shared by every person and kept 30 s; at most DECISIONS_AT_ONCE in flight. A policy that
 * cannot be asked fails the whole answer — a shorter list would read as "no access".
 */

export interface ReachableSite {
  name: string
  /** The label people know the site by: its login branding name, else its display name, else its name. */
  title: string
  /** The entry page as a person opens it: the landing page, else https://<host><pathPrefix>/. */
  url: string
  /** `role`: opened on something the person holds. `signed-in`: open to any signed-in person. */
  access: 'role' | 'signed-in'
}

const TTL_MS = 30_000
const DECISIONS_AT_ONCE = 8

const forPerson = new SwrCache<ReachableSite[]>({ namespace: 'sites.reachable', freshMs: TTL_MS, staleMs: TTL_MS, local: true, l1Max: 2_000 })
const forAnyone = new SwrCache<{ anonymous: boolean; anySignedIn: boolean }>({ namespace: 'sites.reachable.open', freshMs: TTL_MS, staleMs: TTL_MS, local: true, l1Max: 2_000 })

/** Test seam. */
export function resetReachableSites(): void {
  forPerson.resetLocal()
  forAnyone.resetLocal()
}

/** The gateway's verdict on a GET of `path` in the site's app. `email` '' is an anonymous visitor. */
async function allowed(site: string, path: string, email: string): Promise<boolean> {
  const decision = await queryOpa<{ allow?: unknown }>('rbac/decision', {
    email,
    object: path,
    action: 'GET',
    app: site,
    // An anonymous visitor has no session, so no level; everybody else is asked at the level an
    // impersonated session carries.
    aal: email ? 'aal2' : '',
    client: false,
  })
  return decision?.allow === true
}

/** `fn` over `items`, at most `limit` at a time, results in order. The first failure fails the whole. */
async function pooled<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i])
    }
  }))
  return out
}

async function candidates(): Promise<Site[]> {
  const names = (await sitesRepository.list())
    .filter((r) => r.applied && !(SYSTEM_SITES as readonly string[]).includes(r.site.name))
    .map((r) => r.site.name)
  const live = (await Promise.all(names.map(liveSite))).filter((s): s is Site => !!s && s.state !== 'paused')
  return live.filter((s) => kindOf(s) === 'page')
}

async function reachable(site: Site, email: string): Promise<ReachableSite | null> {
  const url = landingOf(site)
  if (!(await allowed(site.name, url.pathname, email))) return null
  const open = await forAnyone.get(`${site.name}\u0000${url.pathname}`, async () => {
    const anonymous = await allowed(site.name, url.pathname, '')
    return { anonymous, anySignedIn: anonymous || (await allowed(site.name, url.pathname, PROBE_EMAIL)) }
  })
  if (open.anonymous) return null
  return {
    name: site.name,
    title: site.login?.branding?.name || site.displayName || site.name,
    url: url.toString(),
    access: open.anySignedIn ? 'signed-in' : 'role',
  }
}

/**
 * The sites this address can open, `role` first, then `signed-in`, each by title. No address: none
 * (the policy decides on addresses). Throws when the policy cannot be asked.
 */
export async function reachableSites(email: string): Promise<ReachableSite[]> {
  if (!email) return []
  return forPerson.get(email, async () => {
    const found = await pooled(await candidates(), DECISIONS_AT_ONCE, (site) => reachable(site, email))
    return found
      .filter((s): s is ReachableSite => !!s)
      .sort((a, b) => (a.access === b.access ? a.title.localeCompare(b.title) || a.name.localeCompare(b.name) : a.access === 'role' ? -1 : 1))
  })
}
