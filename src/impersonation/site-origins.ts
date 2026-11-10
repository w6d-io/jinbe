import { env } from '../config/env.js'
import { SwrCache } from '../cache/swr.js'
import { liveAddresses } from '../sites/address.js'
import { sitesConfig } from '../sites/config.js'
import { sitesRepository } from '../sites/repository.js'
import { SYSTEM_SITES } from '../sites/schemas.js'

/**
 * Which browser origins are SITES: the only pages that may be told an impersonated identity.
 *
 * A site origin is `https://<host>` where the host is the one an applied, unpaused site serves now
 * (its applied version's address — sites/address.ts liveAddresses), and is not a platform host. The
 * platform hosts are everything this service knows the platform itself answers on: the auth, console
 * and API domains, the login and console URLs, the MCP hosts, and SITES_RESERVED_HOSTS. They are
 * refused even if a site record names one, so the console and the login UI always see the
 * administrator. No origin, `null`, plain http (outside development) or an unknown host: not a site.
 */

const SITE_HOSTS_TTL_MS = 5_000

const siteHostsCache = new SwrCache<string[]>({ namespace: 'impersonation.site-hosts', freshMs: SITE_HOSTS_TTL_MS, staleMs: SITE_HOSTS_TTL_MS, local: true, l1Max: 1 })

const hostOf = (url: string | undefined): string | null => {
  if (!url) return null
  try {
    return new URL(url).hostname.toLowerCase() || null
  } catch {
    return null
  }
}

/** Every host the platform itself serves, lowercased. */
export function platformHosts(): Set<string> {
  const hosts = [
    env.AUTH_DOMAIN, env.APP_DOMAIN, env.API_DOMAIN,
    hostOf(env.LOGIN_UI_URL), hostOf(env.ADMIN_UI_URL), hostOf(env.MCP_PUBLIC_URL), hostOf(env.MCP_OAUTH_ISSUER),
    ...sitesConfig().SITES_RESERVED_HOSTS,
  ]
  return new Set(hosts.filter((h): h is string => typeof h === 'string' && h !== '').map((h) => h.toLowerCase()))
}

/** The hosts applied, unpaused sites serve now. Kept a few seconds: fronts poll whoami. */
function siteHosts(): Promise<string[]> {
  return siteHostsCache.get('all', async () => {
    const records = (await sitesRepository.list()).filter((r) => r.applied && r.site.state !== 'paused' && !(SYSTEM_SITES as readonly string[]).includes(r.site.name))
    const live = await liveAddresses(records)
    return [...new Set([...live.values()].map((a) => a.host.toLowerCase()))].sort()
  })
}

/**
 * The host of an Origin header when it is a site's, else null. A failure to read the sites answers
 * null: when in doubt the caller is told about the administrator, never about the user.
 */
export async function siteOriginHost(origin: string | string[] | undefined): Promise<string | null> {
  if (typeof origin !== 'string' || !origin) return null
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && env.NODE_ENV === 'development')) return null
  const host = url.hostname.toLowerCase()
  if (!host || platformHosts().has(host)) return null
  try {
    return (await siteHosts()).includes(host) ? host : null
  } catch {
    return null
  }
}

/** Test seam. */
export function resetSiteOrigins(): void {
  siteHostsCache.resetLocal()
}
