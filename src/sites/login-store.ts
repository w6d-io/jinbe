import { getRedisClient } from '../services/redis-client.service.js'

/**
 * Per-site login data in Redis.
 *
 *   rbac:sites:login          → Hash: { site: JSON(SiteLogin) }   data.site_login, applied sites only
 *   rbac:sites:logo:<site>    → String: JSON(StoredLogo)          the login-page logo
 *
 * `rbac:sites:login` is written in the "permissions published" step of an apply, so the policy
 * learns a site's 2FA bar before the gateway serves the site's new rules.
 */

/** Exactly what opal-policies rbac.rego reads as data.site_login[<site>]. */
export interface SiteLogin {
  min_aal: 'aal2'
  scope: 'none' | 'writes' | 'all' | 'routes'
  routes: string[]
  clients: 'exempt' | 'refused'
}

export interface StoredLogo {
  type: 'image/png' | 'image/webp'
  data: string
  etag: string
  at: string
  by: string
}

const LOGIN = 'rbac:sites:login'
const logoKey = (site: string) => `rbac:sites:logo:${site}`

export const siteLoginStore = {
  async getAll(): Promise<Record<string, SiteLogin>> {
    const all = await getRedisClient().hgetall(LOGIN)
    return Object.fromEntries(Object.entries(all).map(([site, raw]) => [site, JSON.parse(raw) as SiteLogin]))
  },

  async set(site: string, login: SiteLogin | null): Promise<void> {
    if (login) await getRedisClient().hset(LOGIN, site, JSON.stringify(login))
    else await getRedisClient().hdel(LOGIN, site)
  },

  async getLogo(site: string): Promise<StoredLogo | null> {
    const raw = await getRedisClient().get(logoKey(site))
    return raw ? (JSON.parse(raw) as StoredLogo) : null
  },

  async setLogo(site: string, logo: StoredLogo): Promise<void> {
    await getRedisClient().set(logoKey(site), JSON.stringify(logo))
  },

  async deleteLogo(site: string): Promise<void> {
    await getRedisClient().del(logoKey(site))
  },
}
