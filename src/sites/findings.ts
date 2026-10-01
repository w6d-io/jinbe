import type { GroupDefinition } from '../services/redis-rbac.repository.js'
import type { Access, Site } from './schemas.js'
import type { Check, Rendered } from './render.js'
import type { ProtectionStatus } from './protection.js'
import { WHO, WHO_LABEL, isBareBearer, whoOf, type WhoPreset } from './presets.js'
import { siteError } from './checks.js'

/**
 * Security findings on a site: what it lets in, and who can reach what — beside the checks render
 * and the platform make, which say whether it CAN be published. A finding says whether it SHOULD:
 *
 *   error    publishing is refused until it is fixed;
 *   confirm  publishing is refused until a person acknowledges it (`acknowledge: [code]` on apply or
 *            on the apply request) — a deliberate choice that must not happen by accident: a public
 *            route, a hand-built gate, a role granting everything;
 *   warn     said, never blocking;
 *   info     worth knowing about a deliberate setting, never blocking.
 *
 * Acknowledging a code covers every finding with that code. Pure: the groups and the WAF state are
 * handed in (sites.service `findingsFor` reads them).
 */

export type FindingLevel = 'error' | 'warn' | 'confirm' | 'info'

export interface Finding {
  code: string
  level: FindingLevel
  message: string
  /** How to fix it (or what acknowledging it means). */
  fix: string
  /** Where in the intent, e.g. `routes.items.2` or `gates.0.authenticators`. */
  path?: string
}

export interface FindingContext {
  /** Every group on the platform now (redis `getGroups`): groups other than the site's may hold its roles. */
  groups: Record<string, GroupDefinition>
  /** Whether the site's host is behind the WAF; null when the cluster cannot say. */
  protection: ProtectionStatus | null
}

const WRITES = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const presetList = (Object.keys(WHO) as WhoPreset[]).map((k) => `${k} (${WHO[k].map((h) => h.handler).join(' → ')})`).join('; ')

/** The permissions of a role that grant everything on the site, or everything on one resource. */
const wildcards = (perms: readonly string[]) => perms.filter((p) => p === '*' || p.endsWith(':*'))

/** Whether one permission held satisfies a required one (exact, `*`, or `resource:*`). */
const grants = (held: string, needed: string) => held === needed || held === '*' || (held.endsWith(':*') && needed.startsWith(held.slice(0, -1)))

export function securityFindings(site: Site, rendered: Pick<Rendered, 'roles'>, ctx: FindingContext): Finding[] {
  const out: Finding[] = []
  const add = (level: FindingLevel, code: string, message: string, fix: string, path?: string) => out.push({ code, level, message, fix, ...(path ? { path } : {}) })

  // ── gates ───────────────────────────────────────────────────
  site.gates.forEach((gate, i) => {
    const at = `gates.${i}.authenticators`
    const names = gate.authenticators.map((h) => h.handler)
    if (names.length === 0) {
      add('error', 'gate_without_authenticator', `gate '${gate.id}' has no authenticator: nobody can come in`, `Pick who may come in: ${presetList}`, at)
      return
    }
    if (whoOf(gate) === 'custom') {
      add('confirm', 'gate_not_preset', `gate '${gate.id}' lets in [${names.join(', ')}], which is none of the presets`,
        `Use a preset unless this chain is deliberate: ${presetList}. Acknowledge gate_not_preset to publish it as it is`, at)
    }
    const bare = gate.authenticators.findIndex(isBareBearer)
    const oauth2 = names.indexOf('oauth2_introspection')
    if (bare >= 0 && oauth2 > bare) {
      add('error', 'bearer_before_oauth2', `gate '${gate.id}': bearer_token reads Authorization before oauth2_introspection, so every OAuth2 (API) token is refused`,
        `Read session tokens from their own header — ${WHO_LABEL['signed-in-or-tokens']}: cookie_session, bearer_token with token_from.header X-Session-Token, oauth2_introspection`, at)
    } else if (bare >= 0 && oauth2 < 0) {
      add('confirm', 'bare_bearer_token', `gate '${gate.id}': bearer_token reads Authorization and there is no oauth2_introspection: API (OAuth2) tokens are refused, only Kratos session tokens pass`,
        `For API tokens use ${WHO_LABEL['signed-in-or-tokens']} or ${WHO_LABEL.tokens}. Acknowledge bare_bearer_token if only session tokens should pass`, at)
    }
    const noop = names.indexOf('noop')
    if (noop >= 0 && gate.authorizer === 'policy') {
      if (noop === 0) {
        add('error', 'noop_with_policy', `gate '${gate.id}' identifies nobody (noop) yet asks the policy: the policy has no one to check and refuses every request`,
          'For a public gate let everyone pass (authorizer allow); to check permissions, pick a sign-in preset', `gates.${i}`)
      } else {
        add('warn', 'noop_before_policy', `gate '${gate.id}': callers no authenticator before noop recognises reach the policy anonymously and are refused; the authenticators after noop never run`,
          'Put noop out of a policy gate; use anonymous (Optional sign-in) if anonymous callers must pass', `gates.${i}`)
      }
    }
  })

  // ── routes ──────────────────────────────────────────────────
  const roles = rendered.roles
  const held = heldRoles(site, ctx.groups)
  const heldPerms = [...held].flatMap((r) => roles[r] ?? [])
  const reachable = (permission: string) => heldPerms.some((p) => grants(p, permission))
  const route = (access: Access, what: string, writes: boolean, at: string, catchAll: boolean) => {
    if (access.kind === 'public') {
      if (catchAll) add('confirm', 'public_catch_all', `${what} is open to anyone, without signing in`, 'Make the catch-all deny or a permission and list the public paths one by one; acknowledge public_catch_all if the whole site is public', at)
      else if (writes) add('confirm', 'public_write_route', `${what} accepts writes from anyone, without signing in`, 'Give it a permission, or acknowledge public_write_route if anonymous writes are the point (a sign-up, a webhook with its own secret)', at)
      else add('confirm', 'public_route', `${what} is open to anyone, without signing in`, 'Keep it public only for health checks, assets or a landing page; otherwise give it a permission. Acknowledge public_route to publish it', at)
    } else if (access.kind === 'signed-in') {
      if (catchAll) add('confirm', 'signed_in_catch_all', `${what} is open to every signed-in account, granted anything on this site or not`, 'Give the catch-all a permission, or deny it and list the routes; acknowledge signed_in_catch_all to publish it', at)
      else add('confirm', 'signed_in_route', `${what} is open to every signed-in account, granted anything on this site or not`, 'Give it a permission (resource:verb) held through a role; acknowledge signed_in_route to publish it', at)
    } else if (access.kind === 'permission' && !reachable(access.permission)) {
      add('warn', 'permission_unreachable', `${what} needs ${access.permission}, which no role held by a group grants: nobody but super admins can call it`, 'Add the permission to a role and give that role to a group', at)
    }
  }
  site.routes.items.forEach((r, i) => route(r.access, `${r.methods.join(',')} ${r.path}`, r.methods.some((m) => WRITES.has(m)), `routes.items.${i}`, false))
  route(site.routes.catchAll.access, `every path not listed (${site.address.pathPrefix ?? ''}/*)`, true, 'routes.catchAll', true)

  // ── roles ───────────────────────────────────────────────────
  for (const [role, perms] of Object.entries(roles)) {
    if (!held.has(role)) {
      add('warn', 'role_unheld', `role '${role}' is held by no group: nobody but super admins gets it`, `Give it to a group (groups.platform or groups.orgGrantable), or remove it`, 'roles')
      continue
    }
    const wild = wildcards(perms)
    if (wild.length > 0) {
      add('confirm', 'wildcard_role', `role '${role}' grants ${wild.map((w) => (w === '*' ? 'everything on the site (*)' : w)).join(', ')}, and a group holds it`,
        'List the permissions the role needs; acknowledge wildcard_role if this is the site administrators\' role', 'roles')
    }
  }

  // ── upstream ────────────────────────────────────────────────
  if (site.upstream.preserveHost !== true) {
    const { service, namespace } = site.upstream
    add('info', 'preserve_host_off', `the service sees the internal host name (${service}.${namespace}.svc.cluster.local), not ${site.address.host}`,
      'Turn on Preserve host so redirects, absolute links and cookies use the public host; keep it off only for a service that answers on its Service name', 'upstream.preserveHost')
  }

  // ── edge ────────────────────────────────────────────────────
  const p = ctx.protection
  if (!p) add('warn', 'waf_unknown', `whether ${site.address.host} is behind the WAF could not be read here`, 'Check the zone and its Gateway (GET /api/admin/sites/zones, /gateways)', 'address.host')
  else if (p.state !== 'waf') add('warn', 'waf_off', `${site.address.host} is not behind the WAF: ${p.message}`, 'Attach the zone to a WAF-protected Gateway and drop its Ingress (zone ingress none)', 'address.host')
  return out
}

/** Roles some group holds on this site: the site's own groups, and any other group covering it now. */
function heldRoles(site: Site, groups: Record<string, GroupDefinition>): Set<string> {
  const held = new Set<string>()
  for (const r of Object.values(site.groups.platform).flat()) held.add(r)
  for (const def of Object.values(site.groups.orgGrantable)) def.roles.forEach((r) => held.add(r))
  for (const def of Object.values(groups)) (def[site.name] ?? []).forEach((r) => held.add(r))
  return held
}

/** How to fix the platform checks apply refuses on; anything else gets the generic hint. */
const CHECK_FIX: Record<string, string> = {
  unknown_group: 'Create the group first (Access → Groups), or map the roles to an existing platform group',
  group_taken: 'Name an org-grantable group for this site only (<site>-…); that group already covers other services',
  service_exists: 'This name is a service not managed as a site: adopt it through the migration, or pick another name',
  route_tie: 'Another service declares the same route on a shared host: change the path, or give the site its own host',
  host_reserved: 'Pick another host: this one is the platform\'s',
  host_taken: 'Pick another host or path prefix: another site serves it',
  rule_overlap: 'Change the route or gate so no request matches two gateway rules (POST /sites/match shows which)',
  pattern_invalid: 'Fix the route path or the expert match URL so the gateway can compile it',
  handler_disabled: 'Use a handler the gateway runs, or enable it in the gateway configuration first',
  host_outside_zones: 'Use a host under a zone, or create the zone first (POST /sites/zones/suggest)',
  host_too_deep: 'Use a host exactly one label under a zone',
  unknown_role: 'Map the group to a role the site defines',
  unknown_gate: 'Point the route at a gate the site declares',
  public_needs_anonymous_gate: 'Serve the public route through a gate that lets anonymous callers in (Anyone, or Optional sign-in)',
}

/**
 * The error checks apply refuses on before writing anything — render (422 invalid_site), the platform
 * context, gatekit and an address swap (409 checks_failed) — as error findings, so the check endpoint
 * says `blocked` whenever apply would refuse. Apply keeps running them itself.
 */
export function blockingFindings(checks: readonly Check[]): Finding[] {
  const seen = new Set<string>()
  return checks.filter((c) => c.level === 'error').flatMap((c) => {
    const key = `${c.code} ${c.message} ${c.path ?? ''}`
    if (seen.has(key)) return []
    seen.add(key)
    const fix = CHECK_FIX[c.code] ?? 'Fix it in the draft: publishing refuses (409 checks_failed / 422 invalid_site) until this check passes'
    return [{ code: c.code, level: 'error' as const, message: c.message, fix, ...(c.path ? { path: c.path } : {}) }]
  })
}

/** What still stops a publish: every error, and every confirm whose code was not acknowledged. */
export function unresolved(findings: readonly Finding[], acknowledge: readonly string[] = []): Finding[] {
  const ack = new Set(acknowledge)
  return findings.filter((f) => f.level === 'error' || (f.level === 'confirm' && !ack.has(f.code)))
}

/** The summary the check endpoint returns beside the findings. */
export function publishState(findings: readonly Finding[]) {
  return {
    blocked: findings.some((f) => f.level === 'error'),
    acknowledge: [...new Set(findings.filter((f) => f.level === 'confirm').map((f) => f.code))],
  }
}

/** 422 `unconfirmed_findings` listing what still stops the publish; nothing when nothing does. */
export function assertPublishable(findings: readonly Finding[], acknowledge: readonly string[] = []): void {
  const left = unresolved(findings, acknowledge)
  if (left.length === 0) return
  const errors = left.filter((f) => f.level === 'error').length
  const codes = [...new Set(left.filter((f) => f.level === 'confirm').map((f) => f.code))]
  const parts = [
    ...(errors > 0 ? [`${errors} security error(s) to fix`] : []),
    ...(codes.length > 0 ? [`findings to acknowledge (acknowledge: [${codes.map((c) => `"${c}"`).join(', ')}])`] : []),
  ]
  throw Object.assign(siteError(422, 'unconfirmed_findings', `Not published: ${parts.join(' and ')}`), { findings: left })
}
