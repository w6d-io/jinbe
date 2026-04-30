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
 */
export function buildBuiltInRules(input: { domains: BootstrapDomains; urls: BootstrapUrls }): OathkeeperRule[] {
  const { domains, urls } = input
  const rules: OathkeeperRule[] = []

  if (domains.auth) {
    rules.push(buildSelfserviceRootRule(domains.auth, urls.loginUi))
    rules.push(buildSelfserviceUiRule(domains.auth, urls.loginUi))
    rules.push(buildKratosPublicRule(domains.auth, urls.kratosPublic))
  }

  if (domains.app) {
    rules.push(buildKumaApiPreflightRule(domains.app, urls.jinbeInternal))
    rules.push(buildKumaApiRule(domains.app, urls.jinbeInternal))
    rules.push(buildKumaSettingsRule(domains.app, urls.loginUi))
    rules.push(buildKumaAppRule(domains.app, urls.adminUi))
  }

  if (domains.api) {
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
      url: `http<(s?)>://${authDomain}/<(app|error|register|settings|logout|_next|static|assets|logos|login|recovery|verify|verification|public|favicon\\.ico|robots\\.txt|logo\\.svg|manifest\\.json|index\\.html)(.*)>`,
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

export function buildKratosPublicRule(authDomain: string, kratosPublicUrl: string): OathkeeperRule {
  return {
    id: 'kratos-public',
    upstream: { url: kratosPublicUrl, preserve_host: true },
    match: {
      url: `http<(s?)>://${authDomain}/<(\\.well-known|self-service|sessions|schemas)(.*)>`,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
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
  return {
    id: 'kuma-app',
    upstream: { url: adminUiUrl },
    match: {
      url: `http<(s?)>://${kumaDomain}/<.*>`,
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
