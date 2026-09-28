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

/** The platform header mutator's names (charts auth values, dev-aws-1 and prod-aws-1). */
export const PLATFORM_IDENTITY_HEADERS = [
  'x-user-id', 'x-user-email', 'x-user-groups', 'x-email', 'x-id', 'x-tenant-id', 'x-type',
  'x-person-uuid', 'x-applicant-uuid', 'x-client-id', 'x-token-scope',
]

/** What the gateway config makes upstreams trust, read from the Gateway spec. */
export interface GatewayIdentity {
  /** Global header-mutator headers whose value is a template (session data), as spelled there. */
  headers: string[]
  /** Headers each remote authorizer copies from its decision response (it overwrites them too). */
  forwarded: Record<string, string[]>
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
  return {
    headers: isObject(headers) ? Object.entries(headers).filter(([, v]) => typeof v === 'string' && v.includes('{{')).map(([k]) => k) : [],
    forwarded,
  }
}

const headerMap = (h: Handler): Record<string, unknown> => (isObject(h.config?.headers) ? h.config.headers : {})

/**
 * Every identity header name for a site: the platform's, the gateway config's, and what the site's
 * own header mutators set. Exact spellings are kept (see above); duplicates by exact name dropped.
 */
export function identityHeaderNames(site: Pick<Site, 'gates'>, platformNames: readonly string[]): string[] {
  const own = site.gates.flatMap((g) => g.mutators.filter((m) => m.handler === 'header').flatMap((m) => Object.keys(headerMap(m))))
  return [...new Set([...platformNames, ...own])]
}

/** Headers the gate's authorizer sets from its decision: its own list, else the gateway's for that handler. */
function authorizerHeaders(authorizer: Handler, forwarded: Record<string, string[]>): string[] {
  const own = authorizer.config?.forward_response_headers_to_upstream
  return own !== undefined ? strings(own) : forwarded[authorizer.handler] ?? []
}

/**
 * The gate's mutators with identity headers owned by the gateway. A gate that has a header mutator
 * keeps its own (every header it names is overwritten, never merged with the client's). One that
 * has none gets a header mutator blanking every identity header its authorizer does not set, in
 * place of noop.
 */
export function guardedMutators(gate: Pick<Gate, 'mutators'>, authorizer: Handler, names: readonly string[], forwarded: Record<string, string[]>): Handler[] {
  if (gate.mutators.some((m) => m.handler === 'header')) return gate.mutators
  const fromDecision = new Set(authorizerHeaders(authorizer, forwarded).map((h) => h.toLowerCase()))
  const blank = names.filter((n) => !fromDecision.has(n.toLowerCase()))
  const rest = gate.mutators.filter((m) => m.handler !== 'noop')
  if (blank.length === 0) return rest.length > 0 ? rest : [{ handler: 'noop' }]
  return [{ handler: 'header', config: { headers: Object.fromEntries(blank.map((n) => [n, ''])) } }, ...rest]
}
