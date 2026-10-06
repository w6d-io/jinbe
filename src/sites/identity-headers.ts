import type { GatewaySpec } from '../gateway/kube-gateway.js'
import type { Gate, Handler, Site } from './schemas.js'

/**
 * Identity headers: what an upstream trusts because the gateway set it.
 *
 * Oathkeeper forwards every client header it does not overwrite, and it cannot delete one. The
 * header mutator overwrites (session.SetHeader → http.Header.Set, then proxy.CopyHeaders →
 * Header.Set on the outgoing request), an empty template included: the upstream gets the header,
 * empty. So a gate that sets no identity header of its own still renders a header mutator setting
 * every one of them to "" — otherwise `X-User-Email: spoof@evil.io` from the client reaches the
 * upstream as if the gateway had said it.
 *
 * The rule's header map is deep-merged into the global one (koanf maps.Merge): the global
 * templates still run, and a rule key only wins over the global key spelled the same way. So the
 * blanked names keep the gateway config's own spelling (x-User-Email and x-user-email are two keys
 * there, one header on the wire).
 */

/**
 * The platform header mutator's names (charts auth values, dev-aws-1 and prod-aws-1), and the role and
 * permission headers a policy decision may carry for the requested site's app (ROLE_HEADERS): every
 * one is blanked on a gate that does not set it, so a client can never send it to the upstream.
 */
export const PLATFORM_IDENTITY_HEADERS = [
  'x-user-id', 'x-user-email', 'x-user-groups', 'x-email', 'x-id', 'x-tenant-id', 'x-type',
  'x-person-uuid', 'x-applicant-uuid', 'x-client-id', 'x-token-scope', 'x-user-roles', 'x-user-permissions',
  // Organization context: only the platform may say which organization a caller acts in. A copy the
  // client sends never reaches the upstream (opa-authz-proxy emits X-User-Organizations).
  'x-user-organizations', 'x-org-id', 'x-org-roles',
]

/**
 * What a policy gate forwards from the decision when it opts in (gate `passRoles`) and the platform
 * turns role headers on (SITES_ROLE_HEADERS): the caller's groups, and their roles and permissions in
 * THIS site's app only (the payload names the app; rbac.decision answers for it). Every other gate
 * — the default — forwards none of them and blanks all three, header-mutator gates included.
 */
export const ROLE_HEADERS = ['X-User-Groups', 'X-User-Roles', 'X-User-Permissions']

/**
 * What a policy gate of a site with organizations on forwards from the decision: on an org row the
 * route's organization and the caller's org roles of this site there; for an org API key its client
 * id and its organization, on every row. Empty where the decision says nothing.
 */
export const ORG_HEADERS = ['X-Org-Id', 'X-Org-Roles', 'X-Client-Id']

/**
 * The headers only a decision (or a global header template) may fill: blanked on every gate that
 * does not set them, header-mutator gates included — a client's copy would otherwise pass through.
 */
const DECIDED_NAMES = new Set([...ROLE_HEADERS, ...ORG_HEADERS, 'X-User-Organizations'].map((h) => h.toLowerCase()))

/**
 * The sign-in strength, for apps that run their own step-up: X-User-AAL (aal1 | aal2) and
 * X-User-2FA-At (when the session last proved a second factor, RFC 3339; empty if never), read from
 * the Kratos session the authenticator put in .Extra. jinbe sets them on every gate that passes
 * identity (it has a header mutator) and blanks them on the others, like every identity header.
 */
export const SESSION_HEADERS: Record<string, string> = {
  'x-user-aal': '{{ if .Extra }}{{ if .Extra.authenticator_assurance_level }}{{ print .Extra.authenticator_assurance_level }}{{ end }}{{ end }}',
  'x-user-2fa-at': '{{ $at := "" }}{{ if .Extra }}{{ range .Extra.authentication_methods }}{{ if .aal }}{{ if eq (print .aal) "aal2" }}{{ $at = print .completed_at }}{{ end }}{{ end }}{{ end }}{{ end }}{{ $at }}',
}

/** The platform session cookie: ory_kratos_session, and every variant (ory_kratos_session_sandbox…). */
export const SESSION_COOKIE_PREFIX = 'ory_kratos_session'

const BT = '`'
/**
 * The Cookie header a site app receives: the client's, minus the platform session cookie.
 *
 * Oathkeeper proxies the whole Cookie header to the upstream, and the session cookie's domain covers
 * every site: without this every app got a session it could replay on the console and on jinbe. The
 * header mutator sets it (Header.Set replaces the client's value) from the incoming request
 * (.MatchContext.Header), removing each cookie whose NAME starts with SESSION_COOKIE_PREFIX — the
 * match is anchored at a cookie start, so `my_ory_kratos_session=1` stays — and keeping the others in
 * order. sprig (regexReplaceAll, trimPrefix, trim) is in Oathkeeper's template functions. Set on
 * every gate of every site, whatever its own mutators say.
 */
export const STRIPPED_COOKIE_HEADER: Record<string, string> = {
  Cookie: `{{ $c := .MatchContext.Header.Get "Cookie" }}{{ $c = regexReplaceAll ${BT}(^|;)\\s*${SESSION_COOKIE_PREFIX}[A-Za-z0-9_-]*=[^;]*${BT} $c "" }}{{ trimPrefix ";" $c | trim }}`,
}

const withoutCookie = (headers: Record<string, unknown>) => Object.fromEntries(Object.entries(headers).filter(([k]) => k.toLowerCase() !== 'cookie'))

/** What the gateway config makes upstreams trust, read from the Gateway spec. */
export interface GatewayIdentity {
  /** Global header-mutator headers whose value is a template (session data), as spelled there. */
  headers: string[]
  /** Headers each remote authorizer copies from its decision response (it overwrites them too). */
  forwarded: Record<string, string[]>
  /** The global remote_json `remote` (the policy endpoint every policy gate asks), when set. */
  policyRemote?: string
}

/**
 * The decision endpoint for a policy gate forwarding role headers: the configured URL, else the
 * gateway's remote_json remote with its rule `/allow` replaced by `/decision` (the boolean /allow
 * answer carries no identity headers; /decision carries them all). Null when neither says.
 */
export function decisionUrlOf(configured: string | undefined, policyRemote: string | undefined): string | null {
  if (configured) return configured
  if (policyRemote && /\/allow$/.test(policyRemote)) return policyRemote.replace(/\/allow$/, '/decision')
  return policyRemote && /\/decision$/.test(policyRemote) ? policyRemote : null
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

export function gatewayIdentity(spec: GatewaySpec): GatewayIdentity {
  const headers = spec.mutators.header?.config?.headers
  const forwarded: Record<string, string[]> = {}
  for (const [name, h] of Object.entries(spec.authorizers)) {
    const list = strings(h.config?.forward_response_headers_to_upstream)
    if (list.length > 0) forwarded[name] = list
  }
  const remote = spec.authorizers.remote_json?.config?.remote
  return {
    headers: isObject(headers) ? Object.entries(headers).filter(([, v]) => typeof v === 'string' && v.includes('{{')).map(([k]) => k) : [],
    forwarded,
    ...(typeof remote === 'string' ? { policyRemote: remote } : {}),
  }
}

const headerMap = (h: Handler): Record<string, unknown> => (isObject(h.config?.headers) ? h.config.headers : {})

/**
 * Every identity header name for a site: the platform's, the gateway config's, and what the site's
 * own header mutators set. Exact spellings are kept (see above); duplicates by exact name dropped.
 */
export function identityHeaderNames(site: Pick<Site, 'gates'>, platformNames: readonly string[]): string[] {
  const own = site.gates.flatMap((g) => g.mutators.filter((m) => m.handler === 'header').flatMap((m) => Object.keys(headerMap(m))))
  return [...new Set([...platformNames, ...[...ROLE_HEADERS, ...ORG_HEADERS].map((h) => h.toLowerCase()), ...Object.keys(SESSION_HEADERS), ...own])]
}

/** Headers the gate's authorizer sets from its decision: its own list, else the gateway's for that handler. */
function authorizerHeaders(authorizer: Handler, forwarded: Record<string, string[]>): string[] {
  const own = authorizer.config?.forward_response_headers_to_upstream
  return own !== undefined ? strings(own) : forwarded[authorizer.handler] ?? []
}

/**
 * A header mutator that also sets the SESSION_HEADERS it does not name itself, blanks the role and
 * organization headers in `blankRoles` (neither the gate's authorizer nor a global header template sets them), and
 * sets the stripped Cookie.
 */
function withSessionHeaders(m: Handler, blankRoles: readonly string[]): Handler {
  const own = withoutCookie(headerMap(m))
  const named = new Set(Object.keys(own).map((k) => k.toLowerCase()))
  const add = Object.entries(SESSION_HEADERS).filter(([k]) => !named.has(k))
  const blanks = blankRoles.filter((n) => !named.has(n.toLowerCase())).map((n) => [n, ''])
  return { ...m, config: { ...(m.config ?? {}), headers: { ...own, ...Object.fromEntries(add), ...Object.fromEntries(blanks), ...STRIPPED_COOKIE_HEADER } } }
}

/** A later header mutator of the gate: it may not set Cookie (the last Header.Set would win). */
function withoutOwnCookie(m: Handler): Handler {
  const own = headerMap(m)
  return Object.keys(own).some((k) => k.toLowerCase() === 'cookie') ? { ...m, config: { ...(m.config ?? {}), headers: withoutCookie(own) } } : m
}

/**
 * The gate's mutators with identity headers owned by the gateway. A gate that has a header mutator
 * keeps its own (every header it names is overwritten, never merged with the client's), plus the
 * SESSION_HEADERS and the blanked role headers on the first one. One that has none gets a header
 * mutator blanking every identity header its authorizer does not set, in place of noop. Every gate
 * sets the stripped Cookie.
 *
 * `templated`: the headers the gateway's global header mutator fills from a template (the session,
 * a trusted source). On a header-mutator gate that template still runs, so such a role header — the
 * global x-user-groups some gateways set — is left to it rather than blanked.
 */
export function guardedMutators(gate: Pick<Gate, 'mutators'>, authorizer: Handler, names: readonly string[], forwarded: Record<string, string[]>, templated: readonly string[] = []): Handler[] {
  const fromDecision = new Set(authorizerHeaders(authorizer, forwarded).map((h) => h.toLowerCase()))
  const first = gate.mutators.findIndex((m) => m.handler === 'header')
  if (first >= 0) {
    // A role or organization header nothing sets here — no decision forwarding it, no global
    // template — would carry the client's value: blank it. One a global template fills keeps the template's value.
    const fromTemplate = new Set(templated.map((h) => h.toLowerCase()))
    const blankRoles = names.filter((n) => DECIDED_NAMES.has(n.toLowerCase()) && !fromDecision.has(n.toLowerCase()) && !fromTemplate.has(n.toLowerCase()))
    return gate.mutators.map((m, i) => (i === first ? withSessionHeaders(m, blankRoles) : m.handler === 'header' ? withoutOwnCookie(m) : m))
  }
  const blank = names.filter((n) => !fromDecision.has(n.toLowerCase()) && n.toLowerCase() !== 'cookie')
  const rest = gate.mutators.filter((m) => m.handler !== 'noop')
  return [{ handler: 'header', config: { headers: { ...Object.fromEntries(blank.map((n) => [n, ''])), ...STRIPPED_COOKIE_HEADER } } }, ...rest]
}
