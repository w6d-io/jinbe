/**
 * Every Oathkeeper v25.4.0 pipeline handler and every global config field, described for a form
 * (docs/research/oathkeeper-spec.md §4–§7).
 *
 * A field `key` is a dot path into the handler's `config` (`pre_authorization.client_secret`).
 * `required` means required by Oathkeeper's schema once the handler is enabled — a global config
 * missing it makes the gateway refuse its whole config. `secret` fields are set by the platform
 * (chart env from a Secret) and never through the console (secrets.ts).
 * `restart` marks templates Oathkeeper caches by rule id and header name (spec §0.8): only a pod
 * restart picks up an edit, which the operator's rolling restart provides.
 */

export type HandlerKind = 'authenticator' | 'authorizer' | 'mutator' | 'error'
export const HANDLER_KINDS: readonly HandlerKind[] = ['authenticator', 'authorizer', 'mutator', 'error']

export type FieldType = 'string' | 'url' | 'bool' | 'int' | 'duration' | 'enum' | 'list' | 'kv' | 'json' | 'template'

export interface FieldMeta {
  key: string
  label: string
  type: FieldType
  required?: boolean
  default?: unknown
  options?: readonly (string | number)[]
  pattern?: string
  secret?: boolean
  restart?: boolean
  help?: string
}

export interface HandlerMeta {
  kind: HandlerKind
  name: string
  label: string
  description: string
  fields: FieldMeta[]
  /** Why the console cannot enable it on its own (needs a chart change, or is unusable). */
  locked?: string
}

const DURATION = '^[0-9]+(ns|us|µs|ms|s|m|h)$'
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const
const SCOPE_STRATEGIES = ['hierarchic', 'exact', 'wildcard', 'none'] as const

const retry = (prefix = 'retry'): FieldMeta[] => [
  { key: `${prefix}.give_up_after`, label: 'Give up after', type: 'duration', pattern: DURATION, default: '1s' },
  { key: `${prefix}.max_delay`, label: 'Maximum delay between retries', type: 'duration', pattern: DURATION, default: '100ms' },
]

const tokenFrom: FieldMeta = {
  key: 'token_from', label: 'Where to read the token', type: 'json',
  help: 'Exactly one of {"header": "..."}, {"query_parameter": "..."}, {"cookie": "..."}. Default: Authorization: Bearer.',
}

const sessionCheck = (subjectDefault: string): FieldMeta[] => [
  { key: 'check_session_url', label: 'Session check address', type: 'url', required: true, help: 'Kratos …/sessions/whoami' },
  { key: 'preserve_path', label: 'Keep the check URL path', type: 'bool', default: false, help: 'Off: the request path replaces the check URL path. Kratos needs it on.' },
  { key: 'preserve_query', label: 'Keep the check URL query', type: 'bool', default: true },
  { key: 'preserve_host', label: 'Send X-Forwarded-Host', type: 'bool', default: false },
  { key: 'force_method', label: 'Force method', type: 'enum', options: METHODS },
  { key: 'forward_http_headers', label: 'Headers forwarded to the check', type: 'list' },
  { key: 'additional_headers', label: 'Static headers on the check', type: 'kv', help: 'No credentials: the configuration is readable.' },
  { key: 'subject_from', label: 'Subject (GJSON path)', type: 'string', default: subjectDefault, help: 'Kratos: identity.id' },
  { key: 'extra_from', label: 'Extra (GJSON path)', type: 'string', default: 'extra', help: 'Kratos: @this' },
]

const when: FieldMeta = {
  key: 'when', label: 'When this handler answers', type: 'json',
  help: 'Array of {error: [unauthorized|forbidden|internal_server_error|not_found], request: {header: {accept, content_type}}}. IP conditions do not work in v25.4.0 and are refused.',
}

export const CATALOG: readonly HandlerMeta[] = [
  // Authenticators — who is calling
  { kind: 'authenticator', name: 'noop', label: 'No sign-in', description: 'Always succeeds with an empty subject; the authorizer and mutators still run.', fields: [] },
  { kind: 'authenticator', name: 'anonymous', label: 'Anonymous', description: 'Sets a fixed subject when no Authorization header is present — the tail of an optional-login chain.', fields: [
    { key: 'subject', label: 'Subject', type: 'string', default: 'anonymous' },
  ] },
  { kind: 'authenticator', name: 'unauthorized', label: 'Always refuse', description: 'Always 401. Terminates a chain, or closes a path.', fields: [] },
  { kind: 'authenticator', name: 'cookie_session', label: 'Session cookie', description: 'Checks the request cookies against Kratos.', fields: [
    { key: 'only', label: 'Only these cookies', type: 'list', help: 'Empty: any cookie makes it responsible, so a stray cookie answers 401. Use [ory_kratos_session].' },
    ...sessionCheck('subject'),
  ] },
  { kind: 'authenticator', name: 'bearer_token', label: 'Session token', description: 'Checks a Kratos session token from a header, query parameter or cookie.', fields: [
    tokenFrom,
    { key: 'prefix', label: 'Token prefix', type: 'string', help: 'Responsible only for tokens starting with it, e.g. ory_st_' },
    ...sessionCheck('sub'),
  ] },
  { kind: 'authenticator', name: 'oauth2_introspection', label: 'OAuth2 introspection', description: 'Validates an OAuth2 access token against Hydra.', fields: [
    { key: 'introspection_url', label: 'Introspection address', type: 'url', required: true },
    { key: 'scope_strategy', label: 'Scope strategy', type: 'enum', options: SCOPE_STRATEGIES, default: 'none' },
    { key: 'required_scope', label: 'Required scopes', type: 'list' },
    { key: 'target_audience', label: 'Required audiences', type: 'list' },
    { key: 'trusted_issuers', label: 'Trusted issuers', type: 'list' },
    { key: 'prefix', label: 'Token prefix', type: 'string' },
    { key: 'preserve_host', label: 'Send X-Forwarded-Host', type: 'bool', default: false },
    { key: 'introspection_request_headers', label: 'Headers on the introspection call', type: 'kv', help: 'No credentials: the configuration is readable.' },
    tokenFrom,
    { key: 'pre_authorization.enabled', label: 'Authenticate to the introspection endpoint', type: 'bool', default: false },
    { key: 'pre_authorization.client_id', label: 'Client id', type: 'string' },
    { key: 'pre_authorization.client_secret', label: 'Client secret', type: 'string', secret: true, help: 'Set by the platform (chart env from a Secret); the console cannot enable what needs it.' },
    { key: 'pre_authorization.token_url', label: 'Token URL', type: 'url' },
    { key: 'pre_authorization.audience', label: 'Audience', type: 'string' },
    { key: 'pre_authorization.scope', label: 'Scopes', type: 'list' },
    ...retry(),
    { key: 'cache.enabled', label: 'Cache results', type: 'bool', default: false },
    { key: 'cache.ttl', label: 'Cache TTL', type: 'duration', pattern: DURATION, help: 'One process-wide cache: the TTL applies to every rule.' },
    { key: 'cache.max_cost', label: 'Cache maximum cost', type: 'int', default: 100000000 },
  ] },
  { kind: 'authenticator', name: 'jwt', label: 'JWT', description: 'Verifies a signed JWT against a JWKS.', fields: [
    { key: 'jwks_urls', label: 'JWKS URLs', type: 'list', required: true },
    { key: 'jwks_max_wait', label: 'JWKS fetch wait', type: 'duration', pattern: DURATION, default: '1s' },
    { key: 'jwks_ttl', label: 'JWKS cache TTL', type: 'duration', pattern: DURATION, default: '30s' },
    { key: 'allowed_algorithms', label: 'Allowed algorithms', type: 'list', default: ['RS256'] },
    { key: 'trusted_issuers', label: 'Trusted issuers', type: 'list' },
    { key: 'target_audience', label: 'Required audiences', type: 'list' },
    { key: 'required_scope', label: 'Required scopes', type: 'list' },
    { key: 'scope_strategy', label: 'Scope strategy', type: 'enum', options: SCOPE_STRATEGIES, default: 'none', help: 'Required scopes with "none" answer 500.' },
    tokenFrom,
  ] },
  { kind: 'authenticator', name: 'oauth2_client_credentials', label: 'Client credentials (Basic)', description: 'Exchanges HTTP Basic client_id:secret for a token on every request.', fields: [
    { key: 'token_url', label: 'Token URL', type: 'url', required: true },
    { key: 'required_scope', label: 'Required scopes', type: 'list' },
    ...retry(),
    { key: 'cache.enabled', label: 'Cache tokens', type: 'bool', default: false },
    { key: 'cache.ttl', label: 'Cache TTL', type: 'duration', pattern: DURATION },
    { key: 'cache.max_tokens', label: 'Cache size', type: 'int', default: 1000 },
  ] },

  // Authorizers — is it allowed
  { kind: 'authorizer', name: 'allow', label: 'Allow', description: 'Permits every request that got this far.', fields: [] },
  { kind: 'authorizer', name: 'deny', label: 'Deny', description: 'Refuses every request with 403.', fields: [] },
  { kind: 'authorizer', name: 'remote_json', label: 'Policy decision (JSON)', description: 'POSTs a JSON payload to the policy engine; 200 allows, 403 refuses.', fields: [
    { key: 'remote', label: 'Decision endpoint', type: 'url', required: true },
    { key: 'payload', label: 'Payload template', type: 'template', required: true, help: 'Go template producing JSON.' },
    { key: 'headers', label: 'Request headers', type: 'kv', restart: true, help: 'Templates; no credentials: the configuration is readable.' },
    { key: 'forward_response_headers_to_upstream', label: 'Decision headers passed upstream', type: 'list' },
    ...retry(),
  ] },
  { kind: 'authorizer', name: 'remote', label: 'Policy decision (body)', description: 'POSTs the original request body to a policy endpoint.', fields: [
    { key: 'remote', label: 'Decision endpoint', type: 'url', required: true },
    { key: 'headers', label: 'Request headers', type: 'kv', restart: true, help: 'Templates; no credentials: the configuration is readable.' },
    { key: 'forward_response_headers_to_upstream', label: 'Decision headers passed upstream', type: 'list' },
    ...retry(),
  ] },
  { kind: 'authorizer', name: 'keto_engine_acp_ory', label: 'Keto ACP (legacy)', description: 'Keto ≤0.5 ACP engine.',
    locked: 'Modern Keto has no ACP API; the handler cannot answer', fields: [
      { key: 'base_url', label: 'Keto URL', type: 'url', required: true },
      { key: 'required_action', label: 'Action template', type: 'template', required: true },
      { key: 'required_resource', label: 'Resource template', type: 'template', required: true },
      { key: 'subject', label: 'Subject template', type: 'template' },
      { key: 'flavor', label: 'Flavor', type: 'enum', options: ['regex', 'exact', 'glob'], default: 'regex' },
    ] },

  // Mutators — what the upstream receives
  { kind: 'mutator', name: 'noop', label: 'Pass through', description: 'Adds nothing; client headers reach the upstream untouched.', fields: [] },
  { kind: 'mutator', name: 'header', label: 'Identity headers', description: 'Sets templated headers, overwriting any the client sent.', fields: [
    { key: 'headers', label: 'Headers', type: 'kv', required: true, restart: true },
  ] },
  { kind: 'mutator', name: 'cookie', label: 'Cookies', description: 'Sets templated cookies on the upstream request.', fields: [
    { key: 'cookies', label: 'Cookies', type: 'kv', required: true, restart: true },
  ] },
  { kind: 'mutator', name: 'id_token', label: 'Signed ID token', description: 'Replaces Authorization with a JWT signed by the gateway.',
    locked: 'Needs a private signing key Secret mounted into the gateway pods (chart change)', fields: [
      { key: 'issuer_url', label: 'Issuer', type: 'string', required: true },
      { key: 'jwks_url', label: 'Private JWKS', type: 'url', required: true },
      { key: 'ttl', label: 'Token TTL', type: 'duration', pattern: DURATION, default: '15m' },
      { key: 'claims', label: 'Claims template', type: 'template' },
    ] },
  { kind: 'mutator', name: 'hydrator', label: 'Hydrator', description: 'Sends the session and every request header to an API that returns an enriched session.', fields: [
    { key: 'api.url', label: 'Hydrator URL', type: 'url', required: true },
    { key: 'api.auth.basic.username', label: 'Basic auth user', type: 'string' },
    { key: 'api.auth.basic.password', label: 'Basic auth password', type: 'string', secret: true, help: 'Set by the platform (chart env from a Secret); the console cannot enable what needs it.' },
    ...retry('api.retry'),
    { key: 'cache.enabled', label: 'Cache', type: 'bool', default: false },
    { key: 'cache.ttl', label: 'Cache TTL', type: 'duration', pattern: DURATION, default: '1m' },
  ] },

  // Error handlers — what a refused caller sees
  { kind: 'error', name: 'json', label: 'JSON error', description: 'Answers a JSON error with the original status.', fields: [
    { key: 'verbose', label: 'Include details', type: 'bool', default: false, help: 'Leaks internal reasons; keep off in production.' },
    when,
  ] },
  { kind: 'error', name: 'redirect', label: 'Redirect', description: 'Sends the browser to another page, typically the login.', fields: [
    { key: 'to', label: 'Redirect to', type: 'string', required: true },
    { key: 'code', label: 'Status', type: 'enum', options: [301, 302], default: 302 },
    { key: 'return_to_query_param', label: 'Return-to parameter', type: 'string', pattern: '^[A-Za-z0-9,._~-]*$' },
    when,
  ] },
  { kind: 'error', name: 'www_authenticate', label: 'Basic-auth prompt', description: 'Answers 401 with WWW-Authenticate: Basic.', fields: [
    { key: 'realm', label: 'Realm', type: 'string', default: 'Please authenticate.' },
    when,
  ] },
]

export function handlerMeta(kind: HandlerKind, name: string): HandlerMeta | undefined {
  return CATALOG.find((h) => h.kind === kind && h.name === name)
}

/**
 * Handlers the platform's own rules (login, console, jinbe) and every site's catch-all deny gate
 * use (sites/render.ts). Disabling one would make Oathkeeper reject those rules.
 */
export const PLATFORM_HANDLERS: Readonly<Record<HandlerKind, readonly string[]>> = {
  authenticator: ['noop', 'cookie_session'],
  authorizer: ['allow', 'deny', 'remote_json'],
  mutator: ['noop', 'header'],
  error: ['json', 'redirect'],
}
