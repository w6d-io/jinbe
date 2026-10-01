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
  scopes: string[]
  /** RFC 3339; absent = no expiry. */
  expires_at?: string
}

/**
 * Whether a machine client may use a route — the twin of the proposed `client_granted` clause.
 *
 * ALL of: the route carries a permission; a scope the token carries AND the client was registered
 * with IS that permission; the client is not past its expiry; and the route is the client's
 * organization's — named by the route's org param when it has one, otherwise a site that
 * organization runs.
 *
 * Exact: no person stands behind a machine client to be asked what they hold, and its
 * scopes were picked as exact route permissions its creator held (services/api-key-scopes.ts).
 */
export function clientGranted(
  client: ApiClientRecord | undefined,
  tokenScopes: readonly string[],
  route: { permission?: string; org?: string | null; app: string },
  sitesOfOrg: (org: string) => readonly string[],
  now: number = Date.now(),
): boolean {
  if (!client || !route.permission) return false
  if (client.expires_at && !(Date.parse(client.expires_at) > now)) return false
  const registered = new Set(client.scopes)
  const required = route.permission
  if (!tokenScopes.some((s) => isGrantableScope(s) && registered.has(s) && s === required)) return false
  if (route.org !== undefined && route.org !== null) return route.org === client.org
  return sitesOfOrg(client.org).includes(route.app)
}
