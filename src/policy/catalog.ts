/**
 * The permission catalogue: every permission a jinbe route may require, declared ONCE.
 *
 * Each route names one of these in its options (`config.permission`, policy/route-access.ts); the
 * guard, the step-up, the delegation gate, the published route table and `GET /api/catalog` (what
 * kuma and auth-mcp paint and scope themselves from) are all read off this table. A route naming a
 * permission that is not here fails the boot.
 *
 * LEAVES ONLY, matched EXACTLY. `org:write` does not imply `org.admins:write`, whatever the dots say:
 * the gateway's policy matches permission names exactly, so an ancestor that passed here and failed
 * there would be two answers to one question (staff-rbac-proposal §0 F3).
 *
 * NO IMPORTS, like authorization-resolution.ts: the kuma snapshot and the resolver comparison load
 * this file on its own.
 */

/** How much harm one misuse does: read about the platform < read about people < change < take over. */
export type Sensitivity = 'low' | 'medium' | 'high' | 'critical'

/**
 * What a delegated token (MCP, a personal key) may do with the permission. Owner decision
 * (2026-09-29): anything the user can do EXCEPT deletions, second-factor resets, key and client
 * creation, approvals and changes to the access model itself — those are `never`, for every holder,
 * super_admin included. Tightened by the lead the same day (safer defaults the owner may relax):
 * sign-in and MCP settings, zone and gateway writes, the RBAC bundle export and audit export. A `stepUp` permission still needs a second factor proven in a browser, which a
 * token never carries, so `direct` + `stepUp` reaches a human anyway.
 */
export type Delegable = 'direct' | 'never'

export interface PermissionSpec {
  /** The console section it belongs to. */
  area: 'users' | 'access' | 'organizations' | 'sites' | 'gateway' | 'settings' | 'audit' | 'platform'
  label: string
  sensitivity: Sensitivity
  /** A second factor proven within 15 minutes (requireRecentMfa), attached by the route hook. */
  stepUp: boolean
  /** Needs a second person in prod (change request). Declared now, enforced from wave W3. */
  fourEyes: 'prod' | false
  delegable: Delegable
}

const p = (
  area: PermissionSpec['area'],
  label: string,
  sensitivity: Sensitivity,
  opts: { stepUp?: boolean; fourEyes?: 'prod'; delegable?: Delegable } = {},
): PermissionSpec => ({
  area,
  label,
  sensitivity,
  stepUp: opts.stepUp ?? false,
  fourEyes: opts.fourEyes ?? false,
  delegable: opts.delegable ?? 'direct',
})

export const CATALOG = {
  // ── People ─────────────────────────────────────────────────────────────────────────────────────
  'users:read': p('users', 'Find and view users, their groups and second factors', 'medium'),
  'users:create': p('users', 'Create or invite a user', 'medium'),
  'users:update': p('users', "Edit a user's name and traits (not the address)", 'medium'),
  'users:update_email': p('users', "Change a user's sign-in address", 'high', { stepUp: true }),
  'users.metadata:write': p('users', "Change a user's schema and public or admin metadata", 'high'),
  'users:disable': p('users', 'Deactivate or reactivate a user', 'high'),
  'users:delete': p('users', 'Delete a user', 'critical', { stepUp: true, delegable: 'never' }),
  'users:recovery': p('users', 'Send a user a recovery email', 'high'),
  'users:verify': p('users', 'Resend the verification email for an unverified address', 'low'),
  'users:send_login_link': p('users', 'Email a user a one-click sign-in link', 'high'),
  'users:reset_second_factor': p('users', "Remove a user's second factors", 'critical', { stepUp: true, delegable: 'never' }),
  'sessions:read': p('users', "See a user's sessions", 'medium'),
  'sessions:revoke': p('users', "End a user's sessions", 'medium'),

  // ── Access model ───────────────────────────────────────────────────────────────────────────────
  'access:read': p('access', 'See who can reach what: one user\'s access, the access review', 'medium'),
  'access:check': p('access', 'Ask whether somebody may reach a route', 'medium'),
  'groups:read': p('access', 'View groups, roles and the permission catalogue', 'low'),
  // Direct through a key (owner decision 2026-09-30: managing groups and their permissions is normal
  // work); deleting a group is still refused to keys (no DELETE), and the escalation guard applies.
  'groups:write': p('access', 'Create, edit or delete groups and what they bind (the access model)', 'critical', { stepUp: true, fourEyes: 'prod' }),
  'groups.members:write': p('access', 'Add people to platform groups', 'critical', { stepUp: true, fourEyes: 'prod' }),
  'groups.members:revoke': p('access', 'Remove people from platform groups', 'high', { delegable: 'never' }),

  // ── Organisations ──────────────────────────────────────────────────────────────────────────────
  'org:read': p('organizations', 'List organisations and their admins', 'low'),
  'org:write': p('organizations', 'Create or edit an organisation', 'high'),
  'org:delete': p('organizations', 'Delete an organisation', 'critical', { stepUp: true, delegable: 'never' }),
  'org.members:read': p('organizations', "See an organisation's members and grants", 'medium'),
  'org.members:write': p('organizations', "Invite, remove and grant an organisation's members", 'high'),
  'org.admins:write': p('organizations', 'Change who administers an organisation', 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),
  'org.keys:read': p('organizations', "See an organisation's API keys and key policy", 'medium'),
  'org.keys:write': p('organizations', 'Create API keys, change the key policy', 'critical', { stepUp: true, delegable: 'never' }),
  'org.keys:revoke': p('organizations', 'Revoke an API key', 'high'),

  // ── Sites and the edge ─────────────────────────────────────────────────────────────────────────
  'sites:read': p('sites', 'View sites, versions, status, drift, requests; test a URL', 'low'),
  'sites:write': p('sites', 'Draft, import, save and request the publication of a site', 'medium'),
  'sites:apply': p('sites', 'Publish, roll back, pause, resume or restore a site', 'high', { stepUp: true, fourEyes: 'prod' }),
  'sites:delete': p('sites', 'Delete a site', 'critical', { stepUp: true, delegable: 'never' }),
  'sites.requests:approve': p('sites', 'Approve or reject a publication request', 'high', { stepUp: true, delegable: 'never' }),
  'zones:read': p('sites', 'View zones', 'low'),
  'zones:write': p('sites', 'Create or change a zone', 'high', { stepUp: true, delegable: 'never' }),
  'zones:delete': p('sites', 'Delete a zone', 'critical', { stepUp: true, delegable: 'never' }),
  'gateway:read': p('gateway', 'View the gateway handlers and rollouts', 'low'),
  'gateway:apply': p('gateway', 'Change or roll back the gateway configuration', 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),

  // ── Settings and the policy ────────────────────────────────────────────────────────────────────
  'settings:read': p('settings', 'View sign-in, second-factor and AI assistant settings', 'low'),
  'settings.signin:write': p('settings', 'Change how people sign in (methods, second factor, bot check)', 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),
  'settings.mcp:write': p('settings', 'Switch AI assistants (MCP) on or off', 'high', { stepUp: true, delegable: 'never' }),
  'policy.bundle:read': p('settings', 'Export the RBAC bundle, list its history and backups', 'high', { delegable: 'never' }),
  'policy.bundle:write': p('settings', 'Import, roll back or restore the RBAC bundle', 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),

  // ── Audit and review ───────────────────────────────────────────────────────────────────────────
  'audit:read': p('audit', 'Read the audit trail; keep saved views', 'medium'),
  'audit:export': p('audit', 'Export audit evidence', 'high', { stepUp: true, delegable: 'never' }),
  'recert:read': p('audit', 'View recertification campaigns and reports', 'medium'),
  'recert:manage': p('audit', 'Create, activate and close recertification campaigns (a close applies its revokes)', 'high', { delegable: 'never' }),
  'recert:delete': p('audit', 'Delete a recertification campaign', 'high', { delegable: 'never' }),
  'stats:read': p('platform', 'Directory counters and the live change stream', 'low'),
} as const satisfies Record<string, PermissionSpec>

export type Permission = keyof typeof CATALOG

/** The wildcard: only a global role carrying `*` (super_admin) holds it, and no scope ever covers it. */
export const EVERYTHING = '*'

export function isCatalogPermission(name: string): name is Permission {
  return Object.prototype.hasOwnProperty.call(CATALOG, name)
}

export function specOf(name: string): PermissionSpec | undefined {
  return isCatalogPermission(name) ? CATALOG[name] : undefined
}

/**
 * The catalogue entry for a permission name (`stepUp`, `delegable`, …), or undefined outside the
 * catalogue — the lookup the delegated step-up decision (middleware/delegated-step-up.ts) reads.
 */
export const catalogPermission = specOf

export const PERMISSIONS = Object.keys(CATALOG) as Permission[]

const reads = PERMISSIONS.filter((n) => n.endsWith(':read'))

/**
 * Names the model held before the catalogue, still honoured FOR ONE RELEASE (remove in wave W5): a
 * role in Redis, an OPAL org grant, a token scope or a kuma check may carry them. Each covers exactly
 * the catalogue permissions its old gate used to open, so nobody gains or loses a route in the
 * release that introduces the catalogue — the staff roles replace them in W3.
 *
 * Not aliased on purpose: `sites:apply` is a live name with a narrower meaning now (zones, the gateway,
 * approvals and deletion are their own permissions; only `*` held all of them before).
 */
export const ALIASES: Readonly<Record<string, readonly Permission[]>> = {
  // The plugin-wide gate on /api/admin/*. `audit:export` rode on it through the audit scope guard.
  'admin:read': [
    ...reads.filter((n) => !['org.keys:read', 'policy.bundle:read'].includes(n)),
    'audit:export',
  ],
  // requireSuperAdmin, and the fine user-management names USER_PERMISSIONS refined it into.
  'admin:write': [
    'users:create', 'users:update', 'users:update_email', 'users.metadata:write', 'users:disable', 'users:delete', 'users:recovery',
    'users:verify', 'users:send_login_link', 'users:reset_second_factor', 'sessions:revoke',
    'access:check', 'groups:write', 'groups.members:write', 'groups.members:revoke',
    'org:write', 'org:delete', 'org.members:write', 'org.admins:write',
    'sites:write', 'settings.signin:write', 'settings.mcp:write',
    'policy.bundle:read', 'policy.bundle:write', 'recert:manage', 'recert:delete',
  ],
  'admin.organisation:read': ['org:read'],
  'admin.organisation:write': ['org:write', 'org:delete'],
  'admin.membership:write': ['groups.members:write', 'groups.members:revoke'],
  'users:assign_group': ['groups.members:write', 'groups.members:revoke'],
  // Renamed (OPAL org_grants and ORG_ADMIN_PERMISSIONS still carry the old names).
  'org:manage_users': ['org.members:read', 'org.members:write'],
  'org:manage_api_keys': ['org.keys:read', 'org.keys:write', 'org.keys:revoke'],
}

/**
 * Whether held permissions grant a required one: `*`, the permission itself, or a legacy alias of
 * it. A required name outside the catalogue (a site's own permission) keeps the dotted-ancestor rule
 * of the model it belongs to.
 */
export function grants(held: readonly string[], required: string): boolean {
  if (held.includes(EVERYTHING)) return true
  if (required === EVERYTHING) return false
  if (held.includes(required)) return true
  if (isCatalogPermission(required)) {
    return held.some((h) => ALIASES[h]?.includes(required) ?? false)
  }
  return held.some((h) => coversByAncestry(h, required))
}

/**
 * Whether a token's scopes cover a required permission: `grants` without the wildcard. A scope that
 * is not a plain `resource:verb` covers nothing, so a forged `*` opens no route.
 */
export function scopeGrants(scopes: readonly string[], required: string): boolean {
  return grants(scopes.filter((s) => /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/.test(s)), required)
}

/** The catalogue permissions these held names amount to (`*` is every one of them). */
export function effectivePermissions(held: readonly string[]): Permission[] {
  return PERMISSIONS.filter((name) => grants(held, name))
}

// authorization-resolution `covers`, repeated so this file needs no import.
function coversByAncestry(held: string, required: string): boolean {
  const [heldResource, heldVerb] = held.split(':')
  const [requiredResource, requiredVerb] = required.split(':')
  return heldVerb === requiredVerb && requiredResource.startsWith(`${heldResource}.`)
}
