/**
 * The permission catalogue: every permission a jinbe route may require, declared ONCE.
 *
 * Each route names one of these in its options (`config.permission`, policy/route-access.ts); the
 * guard, the step-up, the delegation gate, the published route table and `GET /api/catalog` (what
 * kuma and auth-mcp paint and scope themselves from) are all read off this table. A route naming a
 * permission that is not here fails the boot.
 *
 * LEAVES ONLY, matched EXACTLY. `orgs:write` does not imply `orgs.owners:write`, whatever the dots
 * say, and there is no wildcard and no alias: the gateway's policy matches names exactly, so anything
 * looser here would be two answers to one question.
 *
 * TWO SCOPES (authz-v2-design §2.1). A `platform` permission is decided on routes without an org
 * parameter and held through platform roles (groups). An `org` permission is decided ONLY on routes
 * naming an org parameter, held through org roles assigned in that org (or the explicit every-org
 * map, roles.ts); it means nothing elsewhere. The boot refuses a route whose permission does not
 * match its shape.
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

/** Where a permission is decided (see the file comment). */
export type Scope = 'platform' | 'org'

export interface PermissionSpec {
  scope: Scope
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
  opts: { stepUp?: boolean; fourEyes?: 'prod'; delegable?: Delegable; scope?: Scope } = {},
): PermissionSpec => ({
  scope: opts.scope ?? 'platform',
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
  'users:recovery': p('users', 'Send a user a recovery email', 'high', { stepUp: true }),
  'users:verify': p('users', 'Resend the verification email for an unverified address', 'low'),
  'users:send_login_link': p('users', 'Email a user a one-click sign-in link', 'high', { stepUp: true }),
  'users:reset_second_factor': p('users', "Remove a user's second factors", 'critical', { stepUp: true, delegable: 'never' }),
  'sessions:read': p('users', "See a user's sessions", 'medium'),
  'sessions:revoke': p('users', "End a user's sessions", 'medium', { stepUp: true }),

  // ── Access model ───────────────────────────────────────────────────────────────────────────────
  'access:read': p('access', 'See who can reach what: one user\'s access, the access review', 'medium'),
  'access:check': p('access', 'Ask whether somebody may reach a route', 'medium'),
  'groups:read': p('access', 'View groups, roles and the permission catalogue', 'low'),
  // Direct through a key (owner decision 2026-09-30: managing groups and their permissions is normal
  // work); deleting a group is still refused to keys (no DELETE), and the escalation guard applies.
  'groups:write': p('access', 'Create, edit or delete groups and what they bind (the access model)', 'critical', { stepUp: true, fourEyes: 'prod' }),
  'groups.members:write': p('access', 'Add people to platform groups', 'critical', { stepUp: true, fourEyes: 'prod' }),
  'groups.members:revoke': p('access', 'Remove people from platform groups', 'high', { delegable: 'never' }),
  // Held by super_admin alone (no staff role carries it; owner decision 2026-09-30): who must sign in
  // with a second factor, and who may join without one.
  'groups.mfa:write': p('access', "Switch a group's \"Members must use 2FA\"", 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),
  // Per-person direct grants (a role or a permission held without a group). Reading them is review work
  // (security, auditors); writing is the holding rule's, like handing out a group.
  'users.grants:read': p('access', 'See the roles and permissions people hold directly, not through a group', 'medium'),
  'users.grants:write': p('access', 'Give a person a role or a permission directly, or take it away', 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),

  // ── Organisations, from the platform (no org parameter) ────────────────────────────────────────
  'orgs:read': p('organizations', 'List organisations and their owners', 'low'),
  'orgs:write': p('organizations', 'Create an organisation for an owner, or edit one', 'high'),
  'orgs:delete': p('organizations', 'Delete an organisation', 'critical', { stepUp: true, delegable: 'never' }),
  'orgs.members:write': p('organizations', 'Move a person into or out of an organisation from the platform console', 'high'),
  // Onboarding and break-glass of one organisation: who owns it (jinbe:owner there).
  'orgs.owners:write': p('organizations', "Name an organisation's owners", 'critical', { stepUp: true, fourEyes: 'prod', delegable: 'never' }),
  // An org API key is a machine acting in that organisation on every site serving it: made by staff
  // only for now (owner decision 2026-10-06); the org's own people list and revoke them (org.keys:*).
  'orgs.keys:write': p('organizations', "Create an organisation's API keys", 'critical', { stepUp: true, delegable: 'never' }),

  // ── Inside one organisation (org scope: routes under /api/organizations/:organizationId) ─────────
  'org.members:read': p('organizations', "See this organisation's members and their roles", 'medium', { scope: 'org' }),
  'org.members:write': p('organizations', "Invite and remove this organisation's members, assign their roles", 'high', { scope: 'org' }),
  'org.keys:read': p('organizations', "See this organisation's API keys and key policy", 'medium', { scope: 'org' }),
  'org.keys:write': p('organizations', 'Change the key policy (keys are created by the platform: orgs.keys:write)', 'critical', { stepUp: true, delegable: 'never', scope: 'org' }),
  'org.keys:revoke': p('organizations', 'Revoke an API key', 'high', { scope: 'org' }),
  'org.audit:read': p('organizations', "Read this organisation's audit events", 'medium', { scope: 'org' }),

  // ── Sites and the edge ─────────────────────────────────────────────────────────────────────────
  'sites:read': p('sites', 'View sites, versions, status, drift, requests; test a URL', 'low'),
  'sites:write': p('sites', 'Draft, import and save a site (ephemeral included, and extend its TTL); request its publication or deletion', 'medium'),
  'sites:apply': p('sites', 'Publish, roll back, pause, resume or restore a site', 'high', { stepUp: true, fourEyes: 'prod' }),
  // Approving a deletion request is a deletion: never through a key, never the requester (deletion-requests.ts).
  'sites:delete': p('sites', 'Delete a site; approve or reject a request to delete one', 'critical', { stepUp: true, delegable: 'never' }),
  'sites.requests:approve': p('sites', 'Approve or reject a publication request', 'high', { stepUp: true, delegable: 'never' }),
  // Public sign-up through a site (sites/signup): drafting it is sites:write; publishing a version
  // that opens or widens it also needs this, so who exposes a site to the internet is a named holder.
  'sites.signup:write': p('sites', 'Open or widen public sign-up through a site', 'high', { stepUp: true, delegable: 'never' }),
  'sites.signup:revoke': p('sites', "Remove people from a site's sign-up group", 'high', { delegable: 'never' }),
  // People in a site's own groups (<site>-…, which bind only that site's roles): the site's builders
  // manage who uses it. Never jinbe's or another site's groups (sites/members.ts).
  'sites.members:write': p('sites', "Add or remove people in a site's own groups", 'high'),
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

export const PLATFORM_PERMISSIONS = PERMISSIONS.filter((n) => CATALOG[n].scope === 'platform')
export const ORG_PERMISSIONS = PERMISSIONS.filter((n) => CATALOG[n].scope === 'org')

export function scopeOf(name: string): Scope | undefined {
  return specOf(name)?.scope
}

/** Whether held permissions grant a required one: the permission itself, nothing else. */
export function grants(held: readonly string[], required: string): boolean {
  return held.includes(required)
}

/**
 * Whether a token's scopes cover a required permission: the same exact match, over scopes that are
 * a plain `resource:verb` (anything else covers nothing).
 */
export function scopeGrants(scopes: readonly string[], required: string): boolean {
  return grants(scopes.filter((s) => /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/.test(s)), required)
}

/** The catalogue permissions among these held names. */
export function effectivePermissions(held: readonly string[]): Permission[] {
  return PERMISSIONS.filter((name) => held.includes(name))
}
