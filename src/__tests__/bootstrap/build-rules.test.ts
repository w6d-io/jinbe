import { describe, it, expect } from 'vitest'
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
} from '../../bootstrap/build-rules.js'

const URLS = {
  kratosPublic: 'http://auth-w6d-kratos-public:80',
  kratosAdmin: 'http://auth-w6d-kratos-admin:80',
  loginUi: 'http://auth-w6d-kratos-login-ui:80',
  adminUi: 'http://auth-w6d-admin-ui:80',
  jinbeInternal: 'http://auth-w6d-jinbe:8080',
}

describe('bootstrap/build-rules', () => {
  describe('individual rule builders', () => {
    it('selfservice-ui matches login UI on auth domain with noop+allow', () => {
      const r = buildSelfserviceUiRule('auth.dev.w6d.io', URLS.loginUi)
      expect(r.id).toBe('selfservice-ui')
      expect(r.upstream.url).toBe(URLS.loginUi)
      expect(r.upstream.preserve_host).toBe(true)
      expect(r.match.url).toContain('auth.dev.w6d.io')
      expect(r.authenticators[0].handler).toBe('noop')
      expect(r.authorizer.handler).toBe('allow')
      expect(r.match.methods).toContain('OPTIONS')
    })

    it('kratos-public targets kratos public service', () => {
      const r = buildKratosPublicRule('auth.dev.w6d.io', URLS.kratosPublic)
      expect(r.id).toBe('kratos-public')
      expect(r.upstream.url).toBe(URLS.kratosPublic)
      expect(r.match.url).toContain('self-service')
    })

    it('kuma-api-preflight only matches OPTIONS', () => {
      const r = buildKumaApiPreflightRule('kuma.dev.w6d.io', URLS.jinbeInternal)
      expect(r.id).toBe('kuma-api-preflight')
      expect(r.match.methods).toEqual(['OPTIONS'])
      expect(r.upstream.url).toBe(URLS.jinbeInternal)
    })

    it('kuma-api uses cookie_session + remote_json (OPA enforced)', () => {
      const r = buildKumaApiRule('kuma.dev.w6d.io', URLS.jinbeInternal)
      expect(r.id).toBe('kuma-api')
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authorizer.handler).toBe('remote_json')
      expect(r.mutators[0].handler).toBe('header')
    })

    it('kuma-settings proxies settings to login UI', () => {
      const r = buildKumaSettingsRule('kuma.dev.w6d.io', URLS.loginUi)
      expect(r.id).toBe('kuma-settings')
      expect(r.upstream.url).toBe(URLS.loginUi)
      expect(r.match.url).toContain('settings')
    })

    it('kuma-app routes admin UI SPA on app domain', () => {
      const r = buildKumaAppRule('kuma.dev.w6d.io', URLS.adminUi)
      expect(r.id).toBe('kuma-app')
      expect(r.upstream.url).toBe(URLS.adminUi)
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authorizer.handler).toBe('allow')
    })

    it('jinbe-preflight only OPTIONS, noop+allow', () => {
      const r = buildJinbePreflightRule('jinbe.dev.w6d.io', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-preflight')
      expect(r.match.methods).toEqual(['OPTIONS'])
      expect(r.authenticators[0].handler).toBe('noop')
    })

    it('jinbe-public matches /api/health, /api/whoami, /docs, no auth', () => {
      const r = buildJinbePublicRule('jinbe.dev.w6d.io', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-public')
      expect(r.match.url).toContain('api/health')
      expect(r.match.url).toContain('api/whoami')
      expect(r.match.url).toContain('docs')
      expect(r.authenticators[0].handler).toBe('noop')
    })

    it('jinbe-api enforces OPA via remote_json (no allow-all)', () => {
      const r = buildJinbeApiRule('jinbe.dev.w6d.io', URLS.jinbeInternal)
      expect(r.id).toBe('jinbe-api')
      expect(r.authenticators[0].handler).toBe('cookie_session')
      expect(r.authenticators[1].handler).toBe('noop')
      expect(r.authorizer.handler).toBe('remote_json')
      expect(r.match.methods).not.toContain('OPTIONS')
    })
  })

  describe('buildBuiltInRules orchestration', () => {
    it('emits all 9 rules when all domains set', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.dev.w6d.io', app: 'kuma.dev.w6d.io', api: 'jinbe.dev.w6d.io' },
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

    it('skips auth-domain rules when authDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: '', app: 'kuma.dev.w6d.io', api: 'jinbe.dev.w6d.io' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('selfservice-ui')
      expect(ids).not.toContain('kratos-public')
    })

    it('skips kuma rules when appDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.dev.w6d.io', app: '', api: 'jinbe.dev.w6d.io' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('kuma-api')
      expect(ids).not.toContain('kuma-app')
    })

    it('skips jinbe rules when apiDomain is empty', () => {
      const rules = buildBuiltInRules({
        domains: { auth: 'auth.dev.w6d.io', app: 'kuma.dev.w6d.io', api: '' },
        urls: URLS,
      })
      const ids = rules.map((r) => r.id)
      expect(ids).not.toContain('jinbe-api')
      expect(ids).not.toContain('jinbe-public')
    })

    it('builders are pure — same inputs produce identical outputs', () => {
      const inp = {
        domains: { auth: 'auth.dev.w6d.io', app: 'kuma.dev.w6d.io', api: 'jinbe.dev.w6d.io' },
        urls: URLS,
      }
      const a = buildBuiltInRules(inp)
      const b = buildBuiltInRules(inp)
      expect(JSON.stringify(a)).toBe(JSON.stringify(b))
    })
  })
})
