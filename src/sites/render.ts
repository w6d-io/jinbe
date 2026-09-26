import { createHash } from 'node:crypto'
import type { FlatRolesMap, GroupDefinition, OathkeeperRule, RouteRule } from '../services/redis-rbac.repository.js'
import { orgParamProblem } from '../policy/route-org-param.js'
import { defaultServiceRoles } from '../services/rbac-defaults.js'
import { HTTP_METHODS, SYSTEM_SITES, type Access, type Gate, type Handler, type Route, type Site } from './schemas.js'
import { catchAllMatchUrl, enumeratedMatchUrl, pathsOverlap } from './patterns.js'
import { placeHost, type Zone } from './host.js'

/**
 * render(site, platform): every artefact a Site stands for, from its intent alone.
 *
 * Pure — no I/O, same input same output — so preview, diff, apply and rollback cannot disagree about
 * what a version means. What needs the outside world (ties against other services, gatekit compile
 * and overlap, the Kubernetes API) happens in the service around it.
 *
 * Problems are returned as checks rather than thrown: the editor needs every one of them at once,
 * and an `error` check blocks save and apply.
 */

export interface Platform {
  namespace: string
  enabled: { authenticators: string[]; authorizers: string[]; mutators: string[]; errors: string[] }
  zones?: Zone[]
  cookieDomain?: string
  /** Namespaces no upstream may point into (kratos-admin, OPA, the gateway itself…). */
  platformNamespaces?: string[]
  /** Exact `namespace/service` exceptions to platformNamespaces (e.g. a sandbox echo in the gateway namespace). */
  upstreamAllow?: string[]
  /** login-ui's /access page: where a 2FA site's browser gates send `forbidden` (SITES_ACCESS_URL). */
  accessUrl?: string
}

export interface Check {
  level: 'error' | 'warn'
  code: string
  message: string
  path?: string
}

/** One gate of the Site CR; the operator names its Rule `<site>-<name>-<hash>`. */
export interface SiteCrGate {
  name: string
  match: { methods: string[]; url: string }
  authenticators: Handler[]
  authorizer: Handler
  mutators: Handler[]
  errors?: Handler[]
  /** Per-gate upstream (the CRD allows it; only migrated legacy rules use it). */
  upstream?: SiteCr['spec']['upstream']
}

export interface SiteCr {
  apiVersion: 'auth.w6d.io/v1alpha1'
  kind: 'Site'
  metadata: { name: string; namespace: string; labels: Record<string, string>; annotations: Record<string, string> }
  spec: {
    hosts: string[]
    /** The operator renders `<scheme>://<service>.<namespace>.svc.cluster.local:<port>`. */
    upstream: { service: string; namespace: string; port: number; scheme: 'http' | 'https'; preserveHost: boolean; stripPath?: string }
    gates: SiteCrGate[]
    /** zone: the zone's wildcard Ingress serves the host. vanity: a per-site Ingress. */
    exposure: { mode: 'zone' } | { mode: 'vanity'; tls: 'wildcard' | 'per-site' }
    paused: boolean
    /** A platform-owned site (migrated built-ins); read-only in kuma. */
    system?: boolean
  }
}

export interface Rendered {
  routeMap: RouteRule[]
  roles: FlatRolesMap
  groups: { platform: Record<string, GroupDefinition>; orgGrantable: Record<string, GroupDefinition> }
  orgServiceMap: Record<string, string[]>
  siteCr: SiteCr
  /** The same gates as full Oathkeeper rules — what gatekit compiles and probes. */
  rules: OathkeeperRule[]
  checks: Check[]
}

const DEFAULT_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']
const DENY_GATE = 'deny'
const CATCH_ALL_ID = 'catch-all'
// Static paths under /api/admin/sites and the migrated system sites: a site by that name would be shadowed.
const RESERVED_NAMES = ['migration', 'requests', 'preview', 'zones', 'check-host', 'match', 'render', 'platform', 'sign-in']
// The services the operator and admission refuse as upstreams in any namespace (site-operator):
// the identity admin API, the policy engine and its feeder, the data stores.
const FORBIDDEN_SERVICE = /^(kratos-admin|opa|opal(-.*)?|redis(-.*)?|postgres(ql)?(-.*)?)$/

/**
 * The platform authorizer payload (charts auth values, remote_json) plus the pinned site. A site
 * that asks for 2FA also sends the session's sign-in strength, which the policy compares with
 * data.site_login[site].min_aal (only then: adding it renames every rule of the site).
 */
export function platformPayload(site: string, withAal = false): string {
  return [
    '{',
    '  "input": {',
    '    "sub": "{{ print .Subject }}",',
    '    "email": "{{ if .Extra.identity }}{{ index .Extra.identity.traits "email" }}{{ end }}",',
    '    "object": "{{ .MatchContext.URL.Path }}",',
    '    "action": "{{ .MatchContext.Method }}",',
    ...(withAal ? ['    "aal": "{{ if .Extra }}{{ print .Extra.authenticator_assurance_level }}{{ end }}",'] : []),
    `    "app": "${site}"`,
    '  }',
    '}',
  ].join('\n')
}

/** Whether the site asks for a second factor anywhere (scope, or routes picked one by one). */
export function twoFactorOn(site: Pick<Site, 'login'>): boolean {
  const tf = site.login?.twoFactor
  return !!tf && (tf.scope !== 'none' || (tf.routes?.length ?? 0) > 0)
}

/**
 * Browser-gate error handlers of a 2FA site: a refused HTML request goes to login-ui /access
 * (step-up, enrol, or a branded no-access page — it asks jinbe which), before the platform's
 * redirect-to-login and JSON handlers. Oathkeeper's remote_json cannot pass the policy's reason
 * through, so the redirect is per rule, on `forbidden` only.
 */
function accessRedirect(site: string, accessUrl: string): Handler {
  const to = new URL(accessUrl)
  to.searchParams.set('site', site)
  return {
    handler: 'redirect',
    config: {
      to: to.toString(),
      return_to_query_param: 'return_to',
      when: [{ error: ['forbidden'], request: { header: { accept: ['text/html'] } } }],
    },
  }
}

/** The URL the operator renders for an upstream — jinbe builds the same one only for gatekit. */
export function upstreamUrl(u: Site['upstream']): string {
  return `${u.scheme ?? 'http'}://${u.service}.${u.namespace}.svc.cluster.local:${u.port}`
}

export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined)
    return `{${entries.sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export const sha256 = (value: unknown) => createHash('sha256').update(stableStringify(value)).digest('hex')

export function expandRoles(site: Pick<Site, 'name' | 'roles'>): FlatRolesMap {
  const d = defaultServiceRoles(site.name)
  if (site.roles === 'standard') return { admin: d.admin, editor: d.editor, viewer: d.viewer }
  if (site.roles === 'readonly') return { viewer: d.viewer }
  if (site.roles === 'operator') return d
  return site.roles
}

/**
 * Why a group could not be handed out by an org admin (opal-policies `can_grant`): it must span only
 * this site, carry at least one permission and never `*`. Null when it can.
 */
export function orgGrantableProblem(site: string, group: string, roles: readonly string[], rolesMap: FlatRolesMap): string | null {
  if (!group.startsWith(`${site}-`)) return `org-grantable group '${group}' must be named ${site}-…`
  const unknown = roles.filter((r) => !rolesMap[r])
  if (unknown.length > 0) return `org-grantable group '${group}' maps to unknown role(s) ${unknown.join(', ')}`
  const perms = roles.flatMap((r) => rolesMap[r])
  if (perms.includes('*')) return `org-grantable group '${group}' carries an "everything" role, which org admins may not hand out`
  if (perms.length === 0) return `org-grantable group '${group}' grants no permission`
  return null
}

const methodOrder = (methods: Iterable<string>) => HTTP_METHODS.filter((m) => new Set(methods).has(m))
const allowsAnonymous = (gate: Gate) => gate.authenticators.some((a) => a.handler === 'anonymous' || a.handler === 'noop')

function errorHandlers(errors: Gate['errors']): Handler[] | undefined {
  if (errors === 'platform') return undefined
  if (errors === 'website') return [{ handler: 'redirect' }, { handler: 'json' }]
  if (errors === 'api') return [{ handler: 'json' }]
  return errors
}

// Every row carries its route's id: data.site_login[site].routes names rows by it (S-4a).
function rowsFor(route: Pick<Route, 'id' | 'methods' | 'path' | 'orgParam'>, access: Access): RouteRule[] {
  return methodOrder(route.methods).map((method) => ({
    id: route.id,
    method,
    path: route.path,
    ...(access.kind === 'permission' ? { permission: access.permission } : {}),
    ...(route.orgParam ? { org_param: route.orgParam } : {}),
  }))
}

export function render(site: Site, platform: Platform): Rendered {
  const checks: Check[] = []
  const fail = (code: string, message: string, path?: string) => checks.push({ level: 'error', code, message, path })
  const warn = (code: string, message: string, path?: string) => checks.push({ level: 'warn', code, message, path })
  const name = site.name
  const host = site.address.host.toLowerCase()
  const prefix = site.address.pathPrefix

  if ((SYSTEM_SITES as readonly string[]).includes(name)) fail('system_site', `'${name}' is a system service and cannot be managed as a site`, 'name')
  if (RESERVED_NAMES.includes(name)) fail('reserved_name', `'${name}' is reserved (an API path or a system site)`, 'name')

  const gates = new Map<string, Gate>()
  for (const [i, gate] of site.gates.entries()) {
    if (gates.has(gate.id)) fail('duplicate_gate', `gate '${gate.id}' is declared twice`, `gates.${i}`)
    if (gate.id === DENY_GATE || gate.id.endsWith('-preflight')) fail('reserved_gate_id', `gate id '${gate.id}' is reserved`, `gates.${i}`)
    gates.set(gate.id, gate)
  }
  const catchAllGate = gates.get(site.routes.catchAll.gate)
  if (!catchAllGate) fail('unknown_gate', `catch-all uses unknown gate '${site.routes.catchAll.gate}'`, 'routes.catchAll.gate')

  // ── routes → route map ──────────────────────────────────────
  const routeMap: RouteRule[] = []
  const seenRoutes = new Set<string>()
  const seenIds = new Set<string>()
  const byGate = new Map<string, Route[]>()
  for (const [i, route] of site.routes.items.entries()) {
    const at = `routes.items.${i}`
    if (seenIds.has(route.id)) fail('duplicate_route_id', `route id '${route.id}' is used twice`, at)
    seenIds.add(route.id)
    if (prefix && route.path !== prefix && !route.path.startsWith(`${prefix}/`)) {
      fail('outside_prefix', `${route.path} is outside the site prefix ${prefix}`, at)
    }
    const gateId = route.access.kind === 'deny' ? DENY_GATE : route.gate
    const gate = gates.get(route.gate)
    if (route.access.kind !== 'deny') {
      if (!gate) fail('unknown_gate', `route ${route.path} uses unknown gate '${route.gate}'`, at)
      else if (route.access.kind === 'public' && !allowsAnonymous(gate)) {
        fail('public_needs_anonymous_gate', `${route.path} is public but gate '${gate.id}' only lets signed-in callers in`, at)
      }
      if (gate?.methods && route.methods.some((m) => !gate.methods!.includes(m))) {
        fail('method_not_in_gate', `${route.path} uses a method gate '${gate.id}' does not handle`, at)
      }
    }
    for (const row of rowsFor(route, route.access)) {
      const key = `${row.method} ${row.path}`
      if (seenRoutes.has(key)) fail('duplicate_route', `${key} is declared twice`, at)
      seenRoutes.add(key)
      const problem = orgParamProblem(row)
      if (problem) fail('org_param', problem, at)
      if (route.access.kind !== 'deny') routeMap.push(row)
    }
    byGate.set(gateId, [...(byGate.get(gateId) ?? []), route])
  }

  const catchAllPath = `${prefix ?? ''}/:any*`
  const catchAllMethods = methodOrder(catchAllGate?.methods ?? DEFAULT_METHODS).filter((m) => m !== 'OPTIONS')
  const catchAllAccess = site.routes.catchAll.access
  if (catchAllAccess.kind === 'public' && catchAllGate && !allowsAnonymous(catchAllGate)) {
    fail('public_needs_anonymous_gate', `the catch-all is public but gate '${catchAllGate.id}' only lets signed-in callers in`, 'routes.catchAll')
  }
  if (catchAllAccess.kind === 'public') warn('public_catch_all', 'every path not listed is open to anyone', 'routes.catchAll')
  // A deny catch-all publishes no row: the policy then owns no route there and refuses.
  if (catchAllAccess.kind !== 'deny') routeMap.push(...rowsFor({ id: CATCH_ALL_ID, methods: catchAllMethods, path: catchAllPath }, catchAllAccess))

  // ── per-site 2FA ────────────────────────────────────────────
  const with2fa = twoFactorOn(site)
  for (const id of site.login?.twoFactor.routes ?? []) {
    if (!seenIds.has(id) && id !== CATCH_ALL_ID) fail('unknown_2fa_route', `2FA is asked on route '${id}', which the site does not have`, 'login.twoFactor.routes')
  }
  const landing = site.login?.defaultReturnUrl
  if (landing && new URL(landing).hostname.toLowerCase() !== host) {
    fail('return_url_host', `the landing page must be on the site's host ${host}`, 'login.defaultReturnUrl')
  }
  if (with2fa && !platform.accessUrl && site.gates.some((g) => g.errors === 'website')) {
    fail('access_url_missing', 'per-site 2FA needs the sign-in step-up page (SITES_ACCESS_URL) configured on the platform', 'login.twoFactor')
  }

  // ── roles and groups ────────────────────────────────────────
  const roles = expandRoles(site)
  const platformGroups: Record<string, GroupDefinition> = {}
  for (const [group, groupRoles] of Object.entries(site.groups.platform)) {
    const unknown = groupRoles.filter((r) => !roles[r])
    if (unknown.length > 0) fail('unknown_role', `group '${group}' maps to unknown role(s) ${unknown.join(', ')}`, `groups.platform.${group}`)
    platformGroups[group] = { [name]: groupRoles }
  }
  const orgGrantable: Record<string, GroupDefinition> = {}
  for (const [group, def] of Object.entries(site.groups.orgGrantable)) {
    const problem = orgGrantableProblem(name, group, def.roles, roles)
    if (problem) fail(problem.includes('unknown role') ? 'unknown_role' : 'org_grantable', problem, `groups.orgGrantable.${group}`)
    if (site.groups.platform[group]) fail('org_grantable', `'${group}' cannot be both a platform and an org-grantable group`, `groups.orgGrantable.${group}`)
    orgGrantable[group] = { [name]: def.roles }
  }
  const orgServiceMap = Object.fromEntries(site.orgs.map((org) => [org, [name]]))

  // ── gates → rules ───────────────────────────────────────────
  const handlerOk = (kind: keyof Platform['enabled'], h: Handler, at: string) => {
    if (!platform.enabled[kind].includes(h.handler)) {
      fail('handler_disabled', `${h.handler} is not enabled on the gateway (${kind}); enable it in the Oathkeeper config first`, at)
    }
  }
  const allowListed = platform.upstreamAllow?.includes(`${site.upstream.namespace}/${site.upstream.service}`) ?? false
  if (!allowListed && platform.platformNamespaces?.includes(site.upstream.namespace)) {
    fail('upstream_platform_namespace', `upstream namespace '${site.upstream.namespace}' is a platform namespace`, 'upstream.namespace')
  }
  if (FORBIDDEN_SERVICE.test(site.upstream.service)) {
    fail('upstream_forbidden_service', `'${site.upstream.service}' is a platform data service and cannot be exposed`, 'upstream.service')
  }
  const upstream = {
    url: upstreamUrl(site.upstream),
    ...(site.upstream.preserveHost ? { preserve_host: true } : {}),
    ...(site.upstream.stripPath ? { strip_path: site.upstream.stripPath } : {}),
  }
  const enumerated = [...byGate.entries()].filter(([id]) => id !== catchAllGate?.id)
  const rules: OathkeeperRule[] = []
  const crGates: SiteCrGate[] = []
  // jinbe's own id for the rule (what gatekit is asked about) is content-hashed like the operator's
  // Rule name, so a template edit is a new rule on both sides.
  const emit = (gateName: string, gate: Omit<SiteCrGate, 'name'>) => {
    crGates.push({ name: gateName, ...gate })
    rules.push({ id: `site-${name}-${gateName}-${sha256({ ...gate, upstream }).slice(0, 10)}`, ...gate, upstream })
  }

  const gateRule = (gate: Gate, url: string, methods: string[]) => {
    const at = `gates.${site.gates.indexOf(gate)}`
    gate.authenticators.forEach((h) => handlerOk('authenticators', h, at))
    gate.mutators.forEach((h) => handlerOk('mutators', h, at))
    const authorizer: Handler = gate.authorizer === 'policy'
      ? { handler: 'remote_json', config: { payload: platformPayload(name, with2fa) } }
      : gate.authorizer
    handlerOk('authorizers', authorizer, at)
    const preset = errorHandlers(gate.errors)
    const errors = with2fa && gate.errors === 'website' && platform.accessUrl && preset ? [accessRedirect(name, platform.accessUrl), ...preset] : preset
    errors?.forEach((h) => handlerOk('errors', h, at))
    const matchUrl = gate.expert?.matchUrl ?? url
    if (gate.expert?.matchUrl) warn('expert_match_url', `gate '${gate.id}' uses a raw match URL; only gatekit checks it`, at)
    emit(gate.id, {
      match: { methods: methods.filter((m) => !gate.preflight || m !== 'OPTIONS'), url: matchUrl },
      authenticators: gate.authenticators,
      authorizer,
      mutators: gate.mutators,
      ...(errors ? { errors } : {}),
    })
    if (gate.preflight) {
      handlerOk('authenticators', { handler: 'noop' }, at)
      handlerOk('authorizers', { handler: 'allow' }, at)
      handlerOk('mutators', { handler: 'noop' }, at)
      emit(`${gate.id}-preflight`, {
        match: { methods: ['OPTIONS'], url: matchUrl },
        authenticators: [{ handler: 'noop' }],
        authorizer: { handler: 'allow' },
        mutators: [{ handler: 'noop' }],
      })
    }
  }

  for (const [gateId, routes] of enumerated) {
    const url = enumeratedMatchUrl(host, routes.map((r) => r.path))
    const methods = methodOrder(routes.flatMap((r) => r.methods))
    if (gateId === DENY_GATE) {
      handlerOk('authenticators', { handler: 'noop' }, 'routes')
      handlerOk('authorizers', { handler: 'deny' }, 'routes')
      handlerOk('mutators', { handler: 'noop' }, 'routes')
      emit(DENY_GATE, { match: { methods, url }, authenticators: [{ handler: 'noop' }], authorizer: { handler: 'deny' }, mutators: [{ handler: 'noop' }] })
    } else if (gates.has(gateId)) {
      gateRule(gates.get(gateId)!, url, methods)
    }
  }
  if (catchAllGate) {
    const excluded = enumerated.flatMap(([, routes]) => routes.map((r) => r.path))
    gateRule(catchAllGate, catchAllMatchUrl(host, prefix, excluded), catchAllMethods)
    // A path carved out for another gate is carved out for every method: the ones that gate does not
    // handle reach no rule and are refused (404) at the gateway. Fail-closed, but worth saying.
    for (const [gateId, routes] of enumerated) {
      const handled = new Set(routes.flatMap((r) => r.methods))
      const lost = catchAllMethods.filter((m) => !handled.has(m))
      if (lost.length > 0) warn('unrouted_methods', `${lost.join(', ')} on the paths of gate '${gateId}' reach no rule`, 'routes')
    }
  }
  for (const gate of site.gates) {
    if (!byGate.has(gate.id) && gate.id !== catchAllGate?.id) warn('unused_gate', `gate '${gate.id}' serves no route`, 'gates')
  }

  // Two rules sharing a method and a URL is a 500 at the gateway (no precedence). The catch-all is
  // disjoint by construction; the enumerated gates must be checked pairwise.
  for (let i = 0; i < enumerated.length; i++) {
    for (let j = i + 1; j < enumerated.length; j++) {
      const [ga, ra] = enumerated[i]
      const [gb, rb] = enumerated[j]
      const ma = new Set(ra.flatMap((r) => r.methods))
      if (!rb.some((r) => r.methods.some((m) => ma.has(m)))) continue
      const hit = ra.flatMap((a) => rb.filter((b) => pathsOverlap(a.path, b.path)).map((b) => `${a.path} / ${b.path}`))
      if (hit.length > 0) fail('gate_overlap', `gates '${ga}' and '${gb}' both match ${hit[0]} on a shared method`, 'routes')
    }
  }

  // ── Site CR ─────────────────────────────────────────────────
  if (crGates.length > 32) fail('too_many_gates', `${crGates.length} gateway rules; a Site holds at most 32 (pre-flight rules count)`, 'gates')
  const placement = placeHost(host, platform.zones ?? [], platform.cookieDomain)
  if (placement.tooDeep) fail('host_too_deep', `${host} must be exactly one label under a zone`, 'address.host')
  else if (!placement.zone) fail('host_outside_zones', `${host} is under no zone; the platform maps hosts under its wildcard zones only`, 'address.host')
  else if (!placement.sso) warn('no_sso', `the login cookie does not reach ${placement.zone}; browser sign-in will not work on ${host}`, 'address.host')
  const u = site.upstream
  const spec: SiteCr['spec'] = {
    hosts: [host],
    upstream: { service: u.service, namespace: u.namespace, port: u.port, scheme: u.scheme ?? 'http', preserveHost: u.preserveHost ?? false, ...(u.stripPath ? { stripPath: u.stripPath } : {}) },
    gates: crGates,
    exposure: site.exposure.mode === 'vanity' ? { mode: 'vanity', tls: placement.tls === 'per-site' ? 'per-site' : 'wildcard' } : { mode: 'zone' },
    paused: site.state === 'paused',
  }
  const siteCr: SiteCr = {
    apiVersion: 'auth.w6d.io/v1alpha1',
    kind: 'Site',
    metadata: {
      name,
      namespace: platform.namespace,
      labels: { 'auth.w6d.io/site': name, 'app.kubernetes.io/managed-by': 'jinbe' },
      annotations: { 'auth.w6d.io/spec-hash': sha256(spec) },
    },
    spec,
  }

  return { routeMap, roles, groups: { platform: platformGroups, orgGrantable }, orgServiceMap, siteCr, rules, checks }
}
