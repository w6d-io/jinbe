/**
 * The shapes of an authorization answer, and the scope rules a token is held to. NO IMPORTS, so a
 * snapshot or a comparison can load it on its own. Permissions match exactly, never by ancestry.
 */

/** What somebody holds, resolved the way the policy resolves it. */
export interface HeldRights {
  groups: string[]
  roles: string[]
  permissions: string[]
}

/**
 * What a request carries about its caller: the resolution, plus the address for a log or a trail.
 *
 * Lives here rather than beside a client for some engine, because it is the shape of an answer about
 * the model and not the shape of one engine's reply — which is what it used to be.
 */
export type UserRbacInfo = HeldRights & { email: string }

/**
 * Whether a string can be a scope at all: a plain `resource:verb` permission. `*`, and any
 * permission with a wildcard in it, never is — a scope names what it allows, one permission at a time.
 */
export function isGrantableScope(scope: string): boolean {
  return /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/.test(scope)
}

/** What the policy knows about an OAuth2 client (data.api_clients[client_id], published by jinbe). */
export interface ApiClientRecord {
  org: string
  /** The permissions its scopes stand for (permissions, site roles and groups expanded: api-key-scopes.ts). */
  scopes: string[]
  /**
   * What each of its scopes stands for, by scope: a token that asks for some of them is narrowed to
   * those (rbac.rego client_permissions). The union of the values is `scopes`.
   */
  by_scope?: Record<string, string[]>
  /** RFC 3339; absent = no expiry. */
  expires_at?: string
}

/** The platform's own apps: an org API key is never valid there (rbac.rego `system_apps`). */
export const KEYLESS_APPS: readonly string[] = ['jinbe', 'kuma', 'global']

/**
 * Whether an org API key may use a route — the twin of rbac.rego's org-key clause (§8b).
 *
 * ALL of: the client is registered (data.api_clients) and not past its expiry; the app is a site,
 * not one of the platform's own; the site serves the key's organization; the route carries a
 * permission that is in the key's expanded scopes, exactly; and on an org row the route's org is the
 * key's.
 */
export function clientGranted(
  client: ApiClientRecord | undefined,
  route: { permission?: string; org?: string | null; app: string },
  sitesOfOrg: (org: string) => readonly string[],
  now: number = Date.now(),
): boolean {
  if (!client || !route.permission || KEYLESS_APPS.includes(route.app)) return false
  if (client.expires_at && !(Date.parse(client.expires_at) > now)) return false
  if (!sitesOfOrg(client.org).includes(route.app)) return false
  if (!isGrantableScope(route.permission) || !client.scopes.includes(route.permission)) return false
  return route.org === undefined || route.org === null || route.org === client.org
}
