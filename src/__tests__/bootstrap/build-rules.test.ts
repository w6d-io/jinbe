import { createHash } from 'node:crypto'
import { describe, it, expect } from 'vitest'
import { oathkeeperRegex } from '../sites/fixtures.js'
import {
  buildBuiltInRules,
  buildSelfserviceUiRule,
  buildKratosPublicRule,
  buildKumaApiPreflightRule,
  buildKumaApiRule,
  buildKumaSettingsRule,
  buildKumaAppRule,
  buildJinbePreflightRule,
  buildJinbePublicRule,
  buildJinbeApiRule,
  buildMcpRule,
  buildMcpOAuthAsRule,
  buildKratosSessionRule,
  OPTIONAL_BUILT_IN_RULE_IDS,
  BUILT_IN_RULE_IDS,
} from '../../bootstrap/build-rules.js'

const URLS = {
  kratosPublic: 'http://kratos-public:80',
  kratosAdmin: 'http://kratos-admin:80',
  loginUi: 'http://kratos-login-ui:80',
  adminUi: 'http://admin-ui:80',
  jinbeInternal: 'http://jinbe:8080',
}

describe('bootstrap/build-rules', () => {
  describe('individual rule builders', () => {
    it('selfservice-ui matches login UI on auth domain with noop+allow', () => {
      const r = buildSelfserviceUiRule('auth.example.com', URLS.loginUi)
      expect(r.id).toBe('selfservice-ui')
      expect(r.upstream.url).toBe(URLS.loginUi)
      expect(r.upstream.preserve_host).toBe(true)
      expect(r.match.url).toContain('auth.example.com')
      expect(r.authenticators[0].handler).toBe('noop')
      expect(r.authorizer.handler).toBe('allow')
      expect(r.match.methods).toContain('OPTIONS')
    })

    it('selfservice-ui covers every page and API route the login UI serves', () => {
      // Oathkeeper's regexp strategy: text outside <…> is literal, inside is a regex.
      const toRegex = (u: string) =>
        new RegExp(`^${u.split(/(<[^>]*>)/).map((part) => (part.startsWith('<') ? part.slice(1, -1) : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`)
      const re = toRegex(buildSelfserviceUiRule('auth.example.com', URLS.loginUi).match.url)
      // kratos-login-ui src/app: every page and route handler (a missing one is a gateway 404).
      for (const path of ['/login', '/register', '/settings', '/logout', '/recovery', '/verification', '/error', '/access', '/two-step', '/welcome', '/oauth2/login', '/oauth2/consent', '/oauth2/refused',
        '/account', '/invitation',
        '/api/access-reason', '/api/branding', '/api/branding/logo', '/api/config', '/api/health', '/api/landing', '/api/ready', '/api/second-factor', '/api/sites/mine',
        '/api/sign-up/continue', '/api/account/me/organizations']) {
        expect(re.test(`https://auth.example.com${path}`), path).toBe(true)
      }
    })

    it('kratos-public targets kratos public service', () => {
      const r = buildKratosPublicRule('auth.example.com', URLS.kratosPublic)
      expect(r.id).toBe('kratos-public')
      expect(r.upstream.url).toBe(URLS.kratosPublic)
      expect(r.match.url).toContain('self-service')
    })

    it('kuma-api-preflight only matches OPTIONS', () => {
      const r = buildKumaApiPreflightRule('app.example.com', URLS.jinbeInternal)
      expect(r.id).toBe('kuma-api-preflight')
      expect(r.match.methods).toEqual(['OPTIONS'])
      expect(r.upstream.url).toBe(URLS.jinbeInternal)
    })

    it('kuma-api uses cookie_session + remote_json (OPA enforced)', () => {
      const r = buildKumaApiRule('app.example.com', URLS.jinbeInternal)
      expect(r.id).toBe('kuma-api')
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authorizer.handler).toBe('remote_json')
      expect(r.mutators[0].handler).toBe('header')
    })

    it('kuma-settings proxies settings to login UI', () => {
      const r = buildKumaSettingsRule('app.example.com', URLS.loginUi)
      expect(r.id).toBe('kuma-settings')
      expect(r.upstream.url).toBe(URLS.loginUi)
      expect(r.match.url).toContain('settings')
    })

    it('kuma-app routes admin UI SPA on app domain', () => {
      const r = buildKumaAppRule('app.example.com', URLS.adminUi)
      expect(r.id).toBe('kuma-app')
      expect(r.upstream.url).toBe(URLS.adminUi)
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authorizer.handler).toBe('allow')
    })

    it('kuma-app does NOT match /api/* (would overlap kuma-api)', () => {
      const r = buildKumaAppRule('app.example.com', URLS.adminUi)
      // Must NOT contain a generic catch-all `/<.*>` — that overlaps kuma-api
      expect(r.match.url).not.toMatch(/\/<\.\*>$/)
      // Must explicitly enumerate non-/api paths
      expect(r.match.url).toContain('assets')
      expect(r.match.url).toContain('index')
      // Sanity: regex shouldn't have 'api' in the allowed alternation
      const inside = r.match.url.match(/\/<\(([^)]+)\)>$/)?.[1] ?? ''
      expect(inside.split('|')).not.toContain('api/<.*>')
    })

    it('jinbe-preflight only OPTIONS, noop+allow', () => {
      const r = buildJinbePreflightRule('api.example.com', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-preflight')
      expect(r.match.methods).toEqual(['OPTIONS'])
      expect(r.authenticators[0].handler).toBe('noop')
    })

    it('jinbe-public matches /api/health, /api/whoami, /docs, no auth', () => {
      const r = buildJinbePublicRule('api.example.com', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-public')
      expect(r.match.url).toContain('api/health')
      expect(r.match.url).toContain('api/whoami')
      expect(r.match.url).toContain('docs')
      expect(r.authenticators[0].handler).toBe('noop')
    })

    it('jinbe-api enforces OPA via remote_json (no allow-all)', () => {
      const r = buildJinbeApiRule('api.example.com', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-api')
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authenticators[1].handler).toBe('noop')
      expect(r.authorizer.handler).toBe('remote_json')
      expect(r.match.methods).not.toContain('OPTIONS')
    })
  })

  describe('kratos-session (SITES_SESSION_ZONES)', () => {
    const DOMAINS = { auth: 'auth.dev.example.com', app: 'kuma.dev.example.com', api: 'kuma.dev.example.com' }
    const ruleOf = (zones: string[]) => buildBuiltInRules({ domains: DOMAINS, urls: URLS, sessionZones: zones }).find((r) => r.id === 'kratos-session')

    it('is not emitted without zones', () => {
      expect(ruleOf([])).toBeUndefined()
      expect(buildKratosSessionRule([], [], URLS.kratosPublic)).toBeNull()
    })

    it('GET of the two session paths on any site host one label under a zone, to Kratos, untouched', () => {
      const r = ruleOf(['dev.example.com', 'qualif.example.com'])!
      expect(r.upstream.url).toBe(URLS.kratosPublic)
      expect(r.match.methods).toEqual(['GET'])
      expect(r.authenticators).toEqual([{ handler: 'noop' }])
      expect(r.authorizer).toEqual({ handler: 'allow' })
      expect(r.mutators).toEqual([{ handler: 'noop' }])
      const re = oathkeeperRegex(r.match.url)
      for (const url of ['https://superadmin.dev.example.com/sessions/whoami', 'https://superadmin.qualif.example.com/self-service/logout/browser', 'http://a-1.dev.example.com/sessions/whoami']) {
        expect(re.test(url), url).toBe(true)
      }
      for (const url of [
        'https://superadmin.dev.example.com/sessions/whoami/x',
        'https://superadmin.dev.example.com/sessions',
        'https://superadmin.dev.example.com/self-service/login/browser',
        'https://superadmin.dev.example.com/self-service/logout',
        'https://a.b.dev.example.com/sessions/whoami',
        'https://superadmin.prod.example.com/sessions/whoami',
        'https://dev.example.com/sessions/whoami',
      ]) {
        expect(re.test(url), url).toBe(false)
      }
    })

    it('leaves the platform hosts to their own rules (two matching rules are a 500)', () => {
      const r = buildBuiltInRules({
        domains: DOMAINS,
        urls: URLS,
        mcp: { publicUrl: 'https://mcp.dev.example.com/mcp', upstream: 'http://auth-mcp:3100' },
        mcpOAuthIssuer: 'https://hydra.dev.example.com/',
        sessionZones: ['dev.example.com'],
      }).find((x) => x.id === 'kratos-session')!
      const re = oathkeeperRegex(r.match.url)
      for (const host of ['auth', 'kuma', 'mcp', 'hydra']) expect(re.test(`https://${host}.dev.example.com/sessions/whoami`), host).toBe(false)
      expect(re.test('https://authx.dev.example.com/sessions/whoami')).toBe(true)
    })

    it('is an optional built-in id, dropped when the zones are emptied', () => {
      expect(OPTIONAL_BUILT_IN_RULE_IDS).toContain('kratos-session')
      expect(BUILT_IN_RULE_IDS).toContain('kratos-session')
    })
  })

  describe('buildBuiltInRules orchestration', () => {
    it('emits all 9 rules when all domains set', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.example.com', app: 'app.example.com', api: 'api.example.com' },
        urls: URLS,
      })
      expect(rules).toHaveLength(9)
      const ids = rules.map((r) => r.id)
      expect(ids).toEqual([
        'selfservice-root',
        'selfservice-ui',
        'kratos-public',
        'kuma-api-preflight',
        'kuma-api',
        'kuma-settings',
        'kuma-app',
        'jinbe-preflight',
        'jinbe-api',
      ])
    })

    it('skips jinbe-api/preflight when API domain equals the app domain (gateway-outage regression)', () => {
      // API_DOMAIN == APP_DOMAIN made the jinbe-api catch-all overlap every
      // kuma-* rule on the same host — Oathkeeper 500'd the whole host
      // ("Expected exactly one rule but found multiple"). 2026-08-24 incident.
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.example.com', app: 'app.example.com', api: 'app.example.com' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('jinbe-api')
      expect(ids).not.toContain('jinbe-preflight')
      expect(ids).toContain('kuma-api') // app-domain routing still fully present
    })

    it('skips auth-domain rules when authDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: '', app: 'app.example.com', api: 'api.example.com' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('selfservice-ui')
      expect(ids).not.toContain('kratos-public')
    })

    it('skips kuma rules when appDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.example.com', app: '', api: 'api.example.com' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('kuma-api')
      expect(ids).not.toContain('kuma-app')
    })

    it('skips jinbe rules when apiDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.example.com', app: 'app.example.com', api: '' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('jinbe-api')
      expect(ids).not.toContain('jinbe-public')
    })

    it('builders are pure — same inputs produce identical outputs', () => {
      const inp = {
        domains: { auth: 'auth.example.com', app: 'app.example.com', api: 'api.example.com' },
        urls: URLS,
      }
      const a = buildBuiltInRules(inp)
      const b = buildBuiltInRules(inp)
      expect(JSON.stringify(a)).toBe(JSON.stringify(b))
    })
  })

  describe('impersonation-whoami (IMPERSONATION_ENABLED)', () => {
    const DOMAINS = { auth: 'auth.example.com', app: 'app.example.com', api: 'api.example.com' }
    const FULL = { domains: DOMAINS, urls: URLS, mcp: { publicUrl: 'https://mcp.example.com/mcp', upstream: 'http://auth-mcp:3100' }, mcpOAuthIssuer: 'https://hydra.example.com', sessionZones: ['dev.example.com'] }
    const sha = (v: unknown) => createHash('sha256').update(JSON.stringify(v)).digest('hex')
    /** The ids of the rules matching one request, as Oathkeeper decides it: method and URL without the query. */
    const matching = (rules: ReturnType<typeof buildBuiltInRules>, method: string, path: string) =>
      rules.filter((r) => r.match.methods.includes(method) && oathkeeperRegex(r.match.url).test(`https://auth.example.com${path}`)).map((r) => r.id)

    it('off: the built-in rules are byte for byte what they were before the rule existed', () => {
      // sha256 of JSON.stringify(buildBuiltInRules(FULL + signInGate)) computed on develop before this rule was written.
      expect(sha(buildBuiltInRules({ ...FULL, signInGate: false }))).toBe('753e9d4db986534ddfe219f438a9152fd1cdd8afafc3b599d15bcb4cbd534f5a')
      expect(sha(buildBuiltInRules({ ...FULL, signInGate: true }))).toBe('ef5cbc94752bac6a058de850038fe9a719ed5ac6f20094d93d12ef97fe7947ee')
      for (const signInGate of [false, true]) {
        expect(JSON.stringify(buildBuiltInRules({ ...FULL, signInGate, impersonation: false }))).toBe(JSON.stringify(buildBuiltInRules({ ...FULL, signInGate })))
        expect(buildBuiltInRules({ ...FULL, signInGate }).map((r) => r.id)).not.toContain('impersonation-whoami')
      }
      expect(buildKratosPublicRule('auth.example.com', URLS.kratosPublic).match.url).toBe('http<(s?)>://auth.example.com/<(\\.well-known|self-service|sessions|schemas)(.*)>')
    })

    it('on: GET /sessions/whoami, exactly, goes to jinbe, which receives /api/public/impersonation/whoami', () => {
      const rule = buildBuiltInRules({ domains: DOMAINS, urls: URLS, impersonation: true }).find((r) => r.id === 'impersonation-whoami')!
      expect(rule).toEqual({
        id: 'impersonation-whoami',
        upstream: { url: 'http://jinbe:8080/api/public/impersonation/whoami', preserve_host: true, strip_path: '/sessions/whoami' },
        match: { url: 'http<(s?)>://auth.example.com/sessions/whoami', methods: ['GET'] },
        authenticators: [{ handler: 'noop' }],
        authorizer: { handler: 'allow' },
        mutators: [{ handler: 'noop' }],
      })
      // Oathkeeper: the upstream's path in front of the request's, then the first strip_path removed.
      const forwarded = (new URL(rule.upstream.url).pathname + '/sessions/whoami').replace(rule.upstream.strip_path!, '')
      expect(forwarded).toBe('/api/public/impersonation/whoami')
      expect(OPTIONAL_BUILT_IN_RULE_IDS).toContain('impersonation-whoami')
      expect(BUILT_IN_RULE_IDS).toContain('impersonation-whoami')
    })

    it('on: kratos-public leaves out that one path and nothing else', () => {
      for (const post of [true, false]) {
        const r = buildKratosPublicRule('auth.example.com', URLS.kratosPublic, { post, whoami: false })
        expect(r.match.url).toBe('http<(s?)>://auth.example.com/<(?!sessions/whoami$)(\\.well-known|self-service|sessions|schemas)(.*)>')
        expect(r.match.methods).toEqual(buildKratosPublicRule('auth.example.com', URLS.kratosPublic, { post }).match.methods)
      }
    })

    it.each([false, true])('on (sign-in gate %s): every request matches exactly the rule it should, never two', (signInGate) => {
      const rules = buildBuiltInRules({ ...FULL, signInGate, impersonation: true })
      expect(matching(rules, 'GET', '/sessions/whoami')).toEqual(['impersonation-whoami'])
      for (const path of ['/sessions/whoami/', '/sessions/whoamix', '/sessions', '/sessions/abc', '/self-service/login/browser', '/.well-known/jwks.json', '/schemas/default', '/sessions/whoami/extra']) {
        expect(matching(rules, 'GET', path), `GET ${path}`).toEqual(['kratos-public'])
        for (const method of ['PUT', 'DELETE', 'OPTIONS']) expect(matching(rules, method, path), `${method} ${path}`).toEqual(['kratos-public'])
      }
      // The path is left out for every method of kratos-public: these reach no rule.
      for (const method of ['PUT', 'DELETE', 'OPTIONS']) expect(matching(rules, method, '/sessions/whoami'), method).toEqual([])
      // No request on the auth host matches two rules.
      for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']) {
        for (const path of ['/', '/login', '/sessions/whoami', '/sessions/whoami/', '/sessions', '/self-service/login', '/self-service/methods/oidc/callback/x', '/.well-known/jwks.json']) {
          expect(matching(rules, method, path).length, `${method} ${path}`).toBeLessThanOrEqual(1)
        }
      }
    })

    it('on: POST is what it was with the sign-in gate on; with it off, POST on exactly that path reaches no rule', () => {
      const on = buildBuiltInRules({ ...FULL, signInGate: true, impersonation: true })
      const before = buildBuiltInRules({ ...FULL, signInGate: true })
      for (const path of ['/sessions/whoami', '/sessions', '/self-service/login', '/self-service/registration', '/self-service/methods/oidc/callback/x', '/.well-known/jwks.json', '/other']) {
        expect(matching(on, 'POST', path), path).toEqual(matching(before, 'POST', path))
      }
      for (const id of ['selfservice-gate', 'selfservice-kratos-post']) expect(on.find((r) => r.id === id)).toEqual(before.find((r) => r.id === id))
      const gateOff = buildBuiltInRules({ ...FULL, impersonation: true })
      expect(matching(gateOff, 'POST', '/sessions/whoami')).toEqual([])
      expect(matching(gateOff, 'POST', '/sessions/abc')).toEqual(['kratos-public'])
    })

    it('on: only the auth domain gets the rule, and none without one', () => {
      expect(buildBuiltInRules({ domains: { ...DOMAINS, auth: '' }, urls: URLS, impersonation: true }).map((r) => r.id)).not.toContain('impersonation-whoami')
      const rules = buildBuiltInRules({ ...FULL, impersonation: true })
      // The site hosts' own session check (kratos-session) is untouched.
      expect(rules.find((r) => r.id === 'kratos-session')).toEqual(buildBuiltInRules(FULL).find((r) => r.id === 'kratos-session'))
    })
  })

  describe('mcp (auth-mcp behind Oathkeeper)', () => {
    const toRegex = (u: string) =>
      new RegExp(`^${u.split(/(<[^>]*>)/).map((part) => (part.startsWith('<') ? part.slice(1, -1) : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`)
    const MCP = { publicUrl: 'https://mcp.example.com/mcp', upstream: 'http://auth-mcp:3100/' }
    const DOMAINS = { auth: 'auth.example.com', app: 'kuma.example.com', api: 'api.example.com' }

    it('passes the endpoint and the protected-resource metadata through untouched, nothing else', () => {
      const r = buildMcpRule(MCP)!
      expect(r).toMatchObject({ id: 'mcp', upstream: { url: 'http://auth-mcp:3100' }, authenticators: [{ handler: 'noop' }], authorizer: { handler: 'allow' }, mutators: [{ handler: 'noop' }] })
      expect(r.match.methods).toEqual(['GET', 'POST', 'DELETE'])
      const re = toRegex(r.match.url)
      for (const path of ['/mcp', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
        expect(re.test(`https://mcp.example.com${path}`), path).toBe(true)
      }
      for (const path of ['/', '/healthz', '/mcpx', '/mcp/x', '/.well-known/oauth-protected-resourcex', '/.well-known/openid-configuration']) {
        expect(re.test(`https://mcp.example.com${path}`), path).toBe(false)
      }
      expect(re.test('https://mcpxexample.com/mcp')).toBe(false)
    })

    it('is emitted only with a usable address on a host of its own, and is optional (pruned when dropped)', () => {
      expect(OPTIONAL_BUILT_IN_RULE_IDS).toContain('mcp')
      const ids = (mcp: typeof MCP | null) => buildBuiltInRules({ domains: DOMAINS, urls: URLS, mcp }).map((r) => r.id)
      expect(ids(MCP)).toContain('mcp')
      expect(ids(null)).not.toContain('mcp')
      expect(ids({ ...MCP, publicUrl: 'https://kuma.example.com/mcp' })).not.toContain('mcp')
      expect(buildMcpRule({ ...MCP, publicUrl: 'http://mcp.example.com/mcp' })).toBeNull()
      expect(buildMcpRule({ ...MCP, publicUrl: 'https://mcp.example.com/' })).toBeNull()
      expect(buildMcpRule({ ...MCP, upstream: 'auth-mcp' })).toBeNull()
      // Without MCP the built-ins (and their hash) are what they were.
      expect(buildBuiltInRules({ domains: DOMAINS, urls: URLS })).toEqual(buildBuiltInRules({ domains: DOMAINS, urls: URLS, mcp: null }))
    })
  })

  describe('mcp-oauth-as (RFC 8414 + MCP client registration on the Hydra host)', () => {
    const toRegex = (u: string) =>
      new RegExp(`^${u.split(/(<[^>]*>)/).map((part) => (part.startsWith('<') ? part.slice(1, -1) : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`)
    const DOMAINS = { auth: 'auth.example.com', app: 'kuma.example.com', api: 'api.example.com' }
    const ISSUER = 'https://hydra.example.com/'

    it('sends the two paths to jinbe with the Host preserved, and nothing else of Hydra', () => {
      const r = buildMcpOAuthAsRule(ISSUER, 'http://jinbe:8080/')!
      expect(r).toMatchObject({ id: 'mcp-oauth-as', upstream: { url: 'http://jinbe:8080', preserve_host: true }, authenticators: [{ handler: 'noop' }], authorizer: { handler: 'allow' }, mutators: [{ handler: 'noop' }] })
      expect(r.match.methods).toEqual(['GET', 'POST'])
      const re = toRegex(r.match.url)
      for (const path of ['/.well-known/oauth-authorization-server', '/oauth2/register']) expect(re.test(`https://hydra.example.com${path}`), path).toBe(true)
      for (const path of ['/oauth2/auth', '/oauth2/token', '/.well-known/openid-configuration', '/oauth2/registerx', '/xoauth2/register', '/.well-known/oauth-authorization-serverx']) {
        expect(re.test(`https://hydra.example.com${path}`), path).toBe(false)
      }
    })

    it('is emitted only with an https issuer on a host of its own, and is optional', () => {
      expect(OPTIONAL_BUILT_IN_RULE_IDS).toContain('mcp-oauth-as')
      const ids = (mcpOAuthIssuer: string | null, mcp: { publicUrl: string; upstream: string } | null = null) =>
        buildBuiltInRules({ domains: DOMAINS, urls: URLS, mcp, mcpOAuthIssuer }).map((r) => r.id)
      expect(ids(ISSUER)).toContain('mcp-oauth-as')
      expect(ids(null)).not.toContain('mcp-oauth-as')
      expect(ids('https://auth.example.com/')).not.toContain('mcp-oauth-as')
      expect(ids('https://mcp.example.com/', { publicUrl: 'https://mcp.example.com/mcp', upstream: 'http://auth-mcp:3100' })).not.toContain('mcp-oauth-as')
      expect(buildMcpOAuthAsRule('http://hydra.example.com/', URLS.jinbeInternal)).toBeNull()
      expect(buildMcpOAuthAsRule('not a url', URLS.jinbeInternal)).toBeNull()
      expect(buildBuiltInRules({ domains: DOMAINS, urls: URLS })).toEqual(buildBuiltInRules({ domains: DOMAINS, urls: URLS, mcpOAuthIssuer: null }))
    })
  })

  it('BUILT_IN_RULE_IDS lists every id the builders produce (the migration counts them apart)', () => {
    const all = [
      ...buildBuiltInRules({ domains: { auth: 'auth.example.com', app: 'kuma.example.com', api: 'jinbe.example.com' }, urls: URLS, signInGate: true, mcp: { publicUrl: 'https://mcp.example.com/mcp', upstream: 'http://auth-mcp:3100' }, mcpOAuthIssuer: 'https://hydra.example.com', sessionZones: ['example.com'] }),
      ...buildBuiltInRules({ domains: { auth: 'auth.example.com', app: 'kuma.example.com', api: 'jinbe.example.com' }, urls: URLS, impersonation: true }),
      buildJinbePublicRule('jinbe.example.com', URLS.jinbeInternal),
    ]
    expect(new Set(all.map((r) => r.id))).toEqual(new Set(BUILT_IN_RULE_IDS))
  })
})
