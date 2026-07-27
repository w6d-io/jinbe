import type { AuditChanges, AuditFlag } from './audit-event.service.js'
import type { GroupDefinition, FlatRolesMap, RouteMap, OathkeeperRule } from './redis-rbac.repository.js'

/**
 * Before→after diff builders (A3). Every builder returns a STRUCTURAL,
 * secret-free {@link AuditChanges} envelope: identifiers only (service:role,
 * method:path, handler names, hostnames without userinfo) — never handler
 * `config` objects or metadata values. Posture `flags` are computed here so
 * severity/risk is server-authoritative.
 */

const arrDiff = (before: string[], after: string[]) => {
  const b = new Set(before)
  const a = new Set(after)
  return {
    added:   [...a].filter((x) => !b.has(x)),
    removed: [...b].filter((x) => !a.has(x)),
  }
}

/** Flatten a group def ({service: roles[]}) to "service:role" identifiers. */
function flattenGroup(def: GroupDefinition): string[] {
  const out: string[] = []
  for (const [svc, roles] of Object.entries(def || {})) {
    for (const r of roles) out.push(`${svc}:${r}`)
  }
  return out
}

/** Group definition diff — grants_super_admin when a global:super_admin binding is added. */
export function diffGroupDefinition(
  name: string,
  before: GroupDefinition | null | undefined,
  after: GroupDefinition,
): AuditChanges {
  const { added, removed } = arrDiff(flattenGroup(before ?? {}), flattenGroup(after))
  const flags: AuditFlag[] = []
  if (added.includes('global:super_admin')) flags.push('grants_super_admin')
  return {
    resource: 'group',
    id: name,
    added,
    removed,
    flags: flags.length ? flags : undefined,
    summary: summarize(`group '${name}'`, added, removed),
  }
}

/** Roles map diff (service scoped) — wildcard_permission when a role gains '*'. */
export function diffRoles(
  service: string,
  before: FlatRolesMap | null | undefined,
  after: FlatRolesMap,
): AuditChanges {
  const flat = (m: FlatRolesMap) => {
    const out: string[] = []
    for (const [role, perms] of Object.entries(m || {})) {
      for (const p of perms) out.push(`${role}:${p}`)
    }
    return out
  }
  const { added, removed } = arrDiff(flat(before ?? {}), flat(after))
  const flags: AuditFlag[] = []
  const gainedWildcard =
    Object.values(after).some((p) => p.includes('*')) &&
    added.some((x) => x.endsWith(':*'))
  if (gainedWildcard) flags.push('wildcard_permission')
  return {
    resource: 'roles',
    id: service,
    added,
    removed,
    flags: flags.length ? flags : undefined,
    summary: summarize(`roles for '${service}'`, added, removed),
  }
}

/** Route-map diff (service scoped) — opened_to_public when a route drops its permission. */
export function diffRouteMap(
  service: string,
  before: RouteMap | null | undefined,
  after: RouteMap,
): AuditChanges {
  const key = (m: string, p: string) => `${m.toUpperCase()} ${p}`
  const beforeMap = new Map((before?.rules ?? []).map((r) => [key(r.method, r.path), r.permission ?? '']))
  const afterMap = new Map((after.rules ?? []).map((r) => [key(r.method, r.path), r.permission ?? '']))

  const added: string[] = []
  const removed: string[] = []
  const flags: AuditFlag[] = []

  for (const [k, perm] of afterMap) {
    const prev = beforeMap.get(k)
    if (prev === undefined) {
      added.push(perm ? `${k} → ${perm}` : `${k} → (public)`)
      if (!perm) flags.push('opened_to_public')
    } else if (prev !== perm) {
      added.push(`${k} → ${perm || '(public)'}`)
      // A route that required a permission and now requires none is opened up.
      if (prev && !perm) flags.push('opened_to_public')
    }
  }
  for (const [k, perm] of beforeMap) {
    if (!afterMap.has(k)) removed.push(perm ? `${k} → ${perm}` : `${k} → (public)`)
  }

  return {
    resource: 'route_map',
    id: service,
    added,
    removed,
    flags: flags.length ? [...new Set(flags)] : undefined,
    summary: summarize(`routes for '${service}'`, added, removed),
  }
}

/** Strip any `user:pass@` userinfo from a URL so credentials never enter the log. */
function stripUserinfo(url: string | undefined): string {
  if (!url) return ''
  try {
    const u = new URL(url)
    u.username = ''
    u.password = ''
    return u.toString()
  } catch {
    // Not a full URL — drop anything before an '@' defensively.
    return url.includes('@') ? url.slice(url.lastIndexOf('@') + 1) : url
  }
}

const handlerNames = (arr: Array<{ handler: string }> | undefined) => (arr ?? []).map((h) => h.handler)

/**
 * Oathkeeper access-rule / service-config diff — STRUCTURAL fields ONLY (handler
 * names, match url + methods, upstream host without userinfo). The handler
 * `config` objects (which can carry secrets) are NEVER serialized.
 * Flags: auth_disabled when auth is weakened (noop/anonymous authenticator or
 * an `allow` authorizer); opened_to_public tracks an `allow` authorizer.
 */
export function diffOathkeeperRule(
  id: string,
  before: OathkeeperRule | null | undefined,
  after: OathkeeperRule,
): AuditChanges {
  const struct = (r: OathkeeperRule) => ({
    matchUrl: r.match?.url ?? '',
    methods: (r.match?.methods ?? []).join(','),
    upstream: stripUserinfo(r.upstream?.url),
    authenticators: handlerNames(r.authenticators).join(','),
    authorizer: r.authorizer?.handler ?? '',
    mutators: handlerNames(r.mutators).join(','),
  })

  const b = before ? struct(before) : null
  const a = struct(after)
  const changedKeys: string[] = []
  const added: string[] = []
  const removed: string[] = []
  for (const k of Object.keys(a) as Array<keyof typeof a>) {
    if (!b || b[k] !== a[k]) {
      changedKeys.push(k)
      if (a[k]) added.push(`${k}: ${a[k]}`)
      if (b && b[k]) removed.push(`${k}: ${b[k]}`)
    }
  }

  const flags: AuditFlag[] = []
  const weakAuthN = ['noop', 'anonymous', 'unauthorized']
  const afterAuthN = handlerNames(after.authenticators)
  const beforeAuthN = handlerNames(before?.authenticators)
  if (afterAuthN.some((h) => weakAuthN.includes(h)) && !beforeAuthN.some((h) => weakAuthN.includes(h))) {
    flags.push('auth_disabled')
  }
  if (after.authorizer?.handler === 'allow' && before?.authorizer?.handler !== 'allow') {
    flags.push('opened_to_public')
    if (!flags.includes('auth_disabled')) flags.push('auth_disabled')
  }

  return {
    resource: 'access_rule',
    id,
    added,
    removed,
    changedKeys,
    flags: flags.length ? flags : undefined,
    summary: `access rule '${id}' changed: ${changedKeys.join(', ') || 'no structural change'}`,
  }
}

/** User group membership diff. grants_super_admin when an admin/super group is added. */
export function diffUserGroups(
  targetId: string,
  oldGroups: string[],
  newGroups: string[],
): AuditChanges {
  const { added, removed } = arrDiff(oldGroups, newGroups)
  const flags: AuditFlag[] = []
  const privileged = /super_admin|admins?$|org_admins/i
  if (added.some((g) => /super_admin/i.test(g))) flags.push('grants_super_admin')
  if (added.some((g) => privileged.test(g))) {
    if (!flags.includes('grants_super_admin')) flags.push('wildcard_permission')
  }
  return {
    resource: 'user_groups',
    id: targetId,
    added,
    removed,
    flags: flags.length ? flags : undefined,
    summary: summarize('group membership', added, removed),
  }
}

function summarize(subject: string, added: string[], removed: string[]): string {
  const parts: string[] = []
  if (added.length) parts.push(`+${added.length} added`)
  if (removed.length) parts.push(`-${removed.length} removed`)
  return `${subject} ${parts.length ? parts.join(', ') : 'unchanged'}`
}
