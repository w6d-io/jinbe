import { createHash } from 'node:crypto'
import { KratosSessionService, kratosSessionService } from '../services/kratos-session.service.js'
import { queryOpa } from '../services/opa-client.js'
import { SYSTEM_SITES, type Site } from './schemas.js'
import { sitesRepository } from './repository.js'
import { siteLoginStore } from './login-store.js'
import { liveSite } from './login.js'
import { siteError } from './checks.js'

/**
 * `GET /api/public/sites/mine` — the sites the signed-in visitor can open, for login-ui's landing
 * choice after sign-in (instead of Kratos' single default return URL).
 *
 * "Can open" is the gateway's own answer: OPA `rbac/decision` allows GET on the site's landing path
 * for the visitor's email and assurance level. Anything but an explicit allow leaves the site out,
 * and when OPA cannot answer the whole reply is 503 — a partial list would read as "you have no
 * access". Only applied, active, non-system sites are considered. Answers are kept 30 s per visitor
 * (identity + aal: stepping up to 2FA may open more).
 */

export interface MySite {
  name: string
  displayName: string
  /** The site's landing page: login.defaultReturnUrl, else https://<host><pathPrefix>/. */
  url: string
  logoUrl: string | null
  accent: string | null
}

const TTL_MS = 30_000
const MAX_ENTRIES = 5_000
const cache = new Map<string, { at: number; sites: MySite[] }>()

/** Test seam. */
export function resetMySitesCache(): void {
  cache.clear()
}

export function landingOf(site: Site): URL {
  return new URL(site.login?.defaultReturnUrl ?? `https://${site.address.host}${site.address.pathPrefix ?? ''}/`)
}

async function reachable(site: Site, email: string, aal: string): Promise<MySite | null> {
  const url = landingOf(site)
  const decision = await queryOpa<{ allow?: unknown }>('rbac/decision', {
    email,
    object: url.pathname,
    action: 'GET',
    app: site.name,
    aal,
    client: false,
  })
  if (decision?.allow !== true) return null
  const logo = await siteLoginStore.getLogo(site.name)
  return {
    name: site.name,
    displayName: site.login?.branding?.name ?? site.displayName,
    url: url.toString(),
    logoUrl: logo ? `/api/public/sites/${site.name}/logo` : null,
    accent: site.login?.branding?.accent ?? null,
  }
}

export async function mySites(cookieHeader: string | undefined): Promise<MySite[]> {
  const cookie = KratosSessionService.extractSessionCookie(cookieHeader)
  if (!cookie) throw siteError(401, 'unauthenticated', 'Sign in first')
  const { session } = await kratosSessionService.validateSession(cookie)
  if (!session) throw siteError(401, 'unauthenticated', 'Sign in first')

  const key = createHash('sha256').update(`${session.identityId}\0${session.email}\0${session.aal}`).digest('hex')
  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < TTL_MS) return hit.sites

  const names = (await sitesRepository.list())
    .filter((r) => r.applied && !(SYSTEM_SITES as readonly string[]).includes(r.site.name))
    .map((r) => r.site.name)
  const live = (await Promise.all(names.map(liveSite))).filter((s): s is Site => !!s && s.state !== 'paused')
  let found: Array<MySite | null>
  try {
    found = await Promise.all(live.map((s) => reachable(s, session.email, session.aal)))
  } catch {
    throw siteError(503, 'policy_unavailable', 'Access cannot be checked right now; try again shortly')
  }
  const sites = found.filter((s): s is MySite => !!s).sort((a, b) => a.displayName.localeCompare(b.displayName))

  if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value!)
  cache.set(key, { at: Date.now(), sites })
  return sites
}
