import type { OathkeeperRule, BootstrapDomains, BootstrapUrls } from './types.js'

/**
 * Build the full set of built-in Oathkeeper access rules from environment-derived inputs.
 *
 * Each rule has a stable `id`. The `upstream-rules` upserter preserves
 * any custom rules (rules whose id is not in this list) while overwriting
 * built-in rules with the latest version from this builder.
 *
 * Rule IDs (in evaluation order):
 *   1. selfservice-ui    — login UI static + Kratos flow pages (no auth)
 *   2. kratos-public     — Kratos public API (no auth)
 *   3. kuma-api-preflight — CORS OPTIONS for kuma /api (no auth)
 *   4. kuma-api          — Jinbe API via kuma subdomain (cookie + OPA)
 *   5. kuma-settings     — Kratos settings flow on kuma subdomain (cookie)
 *   6. kuma-app          — Admin UI SPA on kuma subdomain (cookie + allow)
 *   7. jinbe-preflight   — CORS OPTIONS on jinbe subdomain (no auth)
 *   8. jinbe-public      — /api/health, /api/whoami, /docs (no auth)
 *   9. jinbe-api         — Authenticated API via jinbe subdomain (cookie + OPA)
 *
 * With the sign-in gate on (`signInGate`), kratos-public keeps every method but POST, and POSTs are
 * split between two more rules on the auth domain:
 *   - selfservice-gate        — POST /self-service/{login,registration,recovery,verification,settings}:
 *                               through jinbe's gate (sign-in-protection/gate.ts), which passes it on to Kratos
 *   - selfservice-kratos-post — the other POSTs Kratos serves (social callbacks, FedCM, sessions):
 *                               straight to Kratos. Any other POST matches no rule (404).
 */

/** Built-in ids that exist only with some inputs: dropped from Redis when the builder stops emitting them. */
export const OPTIONAL_BUILT_IN_RULE_IDS: readonly string[] = ['selfservice-gate', 'selfservice-kratos-post']

export function buildBuiltInRules(input: { domains: BootstrapDomains; urls: BootstrapUrls; signInGate?: boolean }): OathkeeperRule[] {
  const { domains, urls } = input
  const rules: OathkeeperRule[] = []

  if (domains.auth) {
    rules.push(buildSelfserviceRootRule(domains.auth, urls.loginUi))
    rules.push(buildSelfserviceUiRule(domains.auth, urls.loginUi))
    if (input.signInGate) {
      rules.push(buildKratosPublicRule(domains.auth, urls.kratosPublic, { post: false }))
      rules.push(buildSelfserviceGateRule(domains.auth, urls.jinbeInternal))
      rules.push(buildKratosPublicPostRule(domains.auth, urls.kratosPublic))
    } else {
      rules.push(buildKratosPublicRule(domains.auth, urls.kratosPublic))
    }
  }

  if (domains.app) {
    rules.push(buildKumaApiPreflightRule(domains.app, urls.jinbeInternal))
    rules.push(buildKumaApiRule(domains.app, urls.jinbeInternal))
    rules.push(buildKumaSettingsRule(domains.app, urls.loginUi))
    rules.push(buildKumaAppRule(domains.app, urls.adminUi))
  }

  // The jinbe-api rule is a catch-all (`/<.*>`) on the API domain. When the
  // deployer sets (or a chart default computes) API_DOMAIN equal to the APP
  // domain, that catch-all overlaps every kuma-* rule above and Oathkeeper
  // 500s the WHOLE host ("Expected exactly one rule but found multiple") —
  // this took the dev gateway down on 2026-08-24. The app-domain rules
  // already route /api to jinbe, so a same-domain jinbe rule set adds
  // nothing: skip it, fail-safe by construction.
  if (domains.api && domains.api !== domains.app) {
    rules.push(buildJinbePreflightRule(domains.api, urls.jinbeInternal))
    rules.push(buildJinbeApiRule(domains.api, urls.jinbeInternal))
  }

  return rules
}

export function buildSelfserviceUiRule(authDomain: string, loginUiUrl: string): OathkeeperRule {
  return {
    id: 'selfservice-ui',
    upstream: { url: loginUiUrl, preserve_host: true },
    match: {
      url: `http<(s?)>://${authDomain}/<(app|error|register|settings|logout|_next|static|assets|logos|login|recovery|verify|verification|access|two-step|welcome|api|public|favicon\\.ico|robots\\.txt|logo\\.svg|manifest\\.json|index\\.html)(.*)>`,
      methods: ['GET', 'POST', 'OPTIONS'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildSelfserviceRootRule(authDomain: string, loginUiUrl: string): OathkeeperRule {
  return {
    id: 'selfservice-root',
    upstream: { url: loginUiUrl, preserve_host: true },
    match: {
      // Bare authDomain root — login UI's index page (typically redirects to /login).
      // Anchored to `/` only, so it doesn't overlap with kratos-public or selfservice-ui.
      url: `http<(s?)>://${authDomain}/`,
      methods: ['GET'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildKratosPublicRule(authDomain: string, kratosPublicUrl: string, opts: { post?: boolean } = {}): OathkeeperRule {
  return {
    id: 'kratos-public',
    upstream: { url: kratosPublicUrl, preserve_host: true },
    match: {
      url: `http<(s?)>://${authDomain}/<(\\.well-known|self-service|sessions|schemas)(.*)>`,
      methods: opts.post === false ? ['GET', 'PUT', 'DELETE', 'OPTIONS'] : ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

/**
 * The submits that can make Kratos look an address up or send an email, through jinbe's gate. Oathkeeper appends the
 * original path to the upstream's, so jinbe receives /api/public/sign-in-protection/gate/self-service/<flow>.
 * Oathkeeper matches the path without the query, so `?flow=` never changes which rule applies.
 */
export function buildSelfserviceGateRule(authDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'selfservice-gate',
    upstream: { url: `${jinbeInternalUrl.replace(/\/+$/, '')}/api/public/sign-in-protection/gate`, preserve_host: true },
    match: {
      url: `http<(s?)>://${authDomain}/<self-service/(login|registration|recovery|verification|settings)(.*)>`,
      methods: ['POST'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

/** Every other POST Kratos public serves, straight to it. */
export function buildKratosPublicPostRule(authDomain: string, kratosPublicUrl: string): OathkeeperRule {
  return {
    id: 'selfservice-kratos-post',
    upstream: { url: kratosPublicUrl, preserve_host: true },
    match: {
      url: `http<(s?)>://${authDomain}/<(\\.well-known|sessions|schemas|self-service/(methods|fed-cm))(.*)>`,
      methods: ['POST'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildKumaApiPreflightRule(kumaDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'kuma-api-preflight',
    upstream: { url: jinbeInternalUrl },
    match: {
      url: `http<(s?)>://${kumaDomain}/api/<.*>`,
      methods: ['OPTIONS'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildKumaApiRule(kumaDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'kuma-api',
    upstream: { url: jinbeInternalUrl },
    match: {
      url: `http<(s?)>://${kumaDomain}/api/<.*>`,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    },
    authenticators: [{ handler: 'cookie_session' }],
    authorizer: { handler: 'remote_json' },
    mutators: [{ handler: 'header' }],
  }
}

export function buildKumaSettingsRule(kumaDomain: string, loginUiUrl: string): OathkeeperRule {
  return {
    id: 'kuma-settings',
    upstream: { url: loginUiUrl },
    match: {
      url: `http<(s?)>://${kumaDomain}/<(settings)(.*)>`,
      methods: ['GET', 'POST', 'OPTIONS'],
    },
    authenticators: [{ handler: 'cookie_session' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'header' }],
  }
}

export function buildKumaAppRule(kumaDomain: string, adminUiUrl: string): OathkeeperRule {
  // Explicit non-`/api` enumeration. Oathkeeper requires a unique rule
  // match, and a generic `/<.*>` overlaps `kuma-api` (`/api/<.*>`) →
  // "multiple rules" 500. Kuma is a HashRouter SPA, so all client-side
  // routes live after `#` and the server only ever sees these top-level
  // paths. RE2 (Go regexp) doesn't support negative lookahead, so we
  // enumerate. Nested `<...>` is not supported inside the oathkeeper
  // url syntax; use raw regex like `assets/.*` without inner brackets.
  const allowed = [
    'index\\.html',
    'assets/.*',
    'logos/.*',
    'favicon\\.ico',
    'manifest\\.json',
    'robots\\.txt',
    // Branded static assets at the web root, prefixed with letters/digits/underscore
    // (e.g. `acme_logo.svg`). Branding files belong under `logos/` for new projects;
    // this entry exists for compatibility with apps that ship loose root-level images.
    '[a-z0-9_-]+\\.(svg|png|ico)',
  ].join('|')
  return {
    id: 'kuma-app',
    upstream: { url: adminUiUrl },
    match: {
      // Optional group `?` matches the bare `/` (index.html serving) too.
      url: `http<(s?)>://${kumaDomain}/<(${allowed})?>`,
      methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'],
    },
    authenticators: [{ handler: 'cookie_session' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildJinbePreflightRule(jinbeDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'jinbe-preflight',
    upstream: { url: jinbeInternalUrl },
    match: {
      url: `http<(s?)>://${jinbeDomain}/<.*>`,
      methods: ['OPTIONS'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildJinbePublicRule(jinbeDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'jinbe-public',
    upstream: { url: jinbeInternalUrl },
    match: {
      url: `http<(s?)>://${jinbeDomain}/<(api/health|api/whoami|docs)(.*)>`,
      methods: ['GET'],
    },
    authenticators: [{ handler: 'noop' }],
    authorizer: { handler: 'allow' },
    mutators: [{ handler: 'noop' }],
  }
}

export function buildJinbeApiRule(jinbeDomain: string, jinbeInternalUrl: string): OathkeeperRule {
  return {
    id: 'jinbe-api',
    upstream: { url: jinbeInternalUrl },
    match: {
      url: `http<(s?)>://${jinbeDomain}/<.*>`,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    },
    // cookie_session validates the session if present; noop is a fallback so
    // requests without a session still flow to the OPA authorizer with an
    // anonymous subject. OPA's policy (rbac.rego) allows route_map entries
    // that have no `permission` field for any caller — that's how /api/health,
    // /api/whoami, /docs stay public.
    authenticators: [{ handler: 'cookie_session' }, { handler: 'noop' }],
    authorizer: { handler: 'remote_json' },
    mutators: [{ handler: 'header' }],
  }
}
