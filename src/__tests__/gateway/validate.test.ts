import { describe, it, expect } from 'vitest'
import { validate, type InUse } from '../../gateway/validate.js'
import { maskConfig, resolveSecrets, MASK } from '../../gateway/secrets.js'
import type { GatewaySpec } from '../../gateway/kube-gateway.js'

// GW-2: what a proposed Gateway spec is checked against, and how secrets are kept out of it.

const base = (): GatewaySpec => ({
  authenticators: {
    noop: { enabled: true },
    cookie_session: { enabled: true, config: { check_session_url: 'http://kratos/sessions/whoami', only: ['ory_kratos_session'] } },
  },
  authorizers: { deny: { enabled: true }, remote_json: { enabled: true, config: { remote: 'http://opa/v1/data/rbac/allow', payload: '{}' } } },
  mutators: { noop: { enabled: true }, header: { enabled: true, config: { headers: { 'X-User': '{{ print .Subject }}' } } } },
  errors: { json: { enabled: true }, redirect: { enabled: true, config: { to: 'https://login/' } } },
  errorFallback: ['redirect', 'json'],
})
const noUse = (): InUse => ({ authenticator: {}, authorizer: {}, mutator: {}, error: {} })
const codes = (spec: GatewaySpec, cur: GatewaySpec | null = base(), inUse = noUse()) => validate(spec, cur, inUse).issues.map((i) => i.code)

describe('validate', () => {
  it('accepts the current configuration unchanged, with nothing to roll', () => {
    const v = validate(base(), base(), noUse())
    expect(v.ok).toBe(true)
    expect(v.changes).toEqual([])
    expect(v.issues).toEqual([])
  })

  it('refuses an enabled handler missing a field Oathkeeper requires', () => {
    const s = base()
    s.authenticators.oauth2_introspection = { enabled: true, config: {} }
    const v = validate(s, base(), noUse())
    expect(v.ok).toBe(false)
    expect(v.issues).toContainEqual(expect.objectContaining({ code: 'field_required', handler: 'oauth2_introspection', path: 'introspection_url' }))
  })

  it('refuses an unknown setting, an unknown handler and a mistyped value', () => {
    const s = base()
    s.authenticators.cookie_session.config!.colour = 'red'
    s.authorizers.opa_magic = { enabled: true }
    s.errors.redirect.config!.code = 307
    expect(codes(s)).toEqual(expect.arrayContaining(['unknown_field', 'unknown_handler', 'field_invalid']))
  })

  it('refuses disabling a handler a site uses, naming the sites', () => {
    const s = base()
    s.authorizers.remote_json.enabled = false
    const inUse = noUse()
    inUse.authorizer.remote_json = ['payroll', 'wiki']
    const v = validate(s, base(), inUse)
    expect(v.ok).toBe(false)
    expect(v.issues.find((i) => i.code === 'handler_in_use')?.message).toContain('payroll, wiki')
  })

  it('treats a handler left out of the spec as disabled', () => {
    const s = base()
    delete (s.mutators as Record<string, unknown>).header
    const inUse = noUse()
    inUse.mutator.header = ['(platform)']
    expect(codes(s, base(), inUse)).toContain('handler_in_use')
  })

  it('flags turning on anonymous access or allow-all as risks, without refusing', () => {
    const cur = base()
    delete (cur.authenticators as Record<string, unknown>).noop
    const s = base()
    s.authorizers.allow = { enabled: true }
    const v = validate(s, cur, noUse())
    expect(v.ok).toBe(true)
    expect(v.issues.filter((i) => i.severity === 'warn').map((i) => i.code).sort()).toEqual(['risk_allow_all', 'risk_anonymous'])
  })

  it('refuses enabling a locked handler', () => {
    const s = base()
    s.mutators.id_token = { enabled: true, config: { issuer_url: 'https://x', jwks_url: 'file:///k.json' } }
    expect(codes(s)).toContain('handler_locked')
  })

  it('refuses a fallback that is not an enabled error handler, and an empty one', () => {
    const s = base()
    s.errorFallback = ['www_authenticate']
    expect(codes(s)).toContain('fallback_disabled')
    s.errorFallback = []
    expect(codes(s)).toContain('fallback_empty')
  })

  it('refuses IP conditions, which Oathkeeper v25.4.0 ignores', () => {
    const s = base()
    s.errors.json.config = { when: [{ error: ['forbidden'], request: { cidr: ['10.0.0.0/8'] } }] }
    expect(codes(s)).toContain('field_invalid')
  })

  it('refuses pre-authorization and hydrator basic auth, which need a platform secret', () => {
    const s = base()
    s.authenticators.oauth2_introspection = { enabled: true, config: { introspection_url: 'http://h', pre_authorization: { enabled: true, client_id: 'c', token_url: 'http://t' } } }
    s.mutators.hydrator = { enabled: true, config: { api: { url: 'http://h', auth: { basic: { username: 'u' } } } } }
    expect(validate(s, base(), noUse()).issues.filter((i) => i.code === 'needs_platform_secret').map((i) => i.handler)).toEqual(['oauth2_introspection', 'hydrator'])
  })

  it('refuses jwt required scopes with scope strategy none (every request 500)', () => {
    const s = base()
    s.authenticators.jwt = { enabled: true, config: { jwks_urls: ['https://h/jwks.json'], required_scope: ['read'] } }
    expect(codes(s)).toContain('field_invalid')
    s.authenticators.jwt.config!.scope_strategy = 'exact'
    expect(codes(s)).not.toContain('field_invalid')
  })

  it('reports a header template edit as a sensitive config change, keys only, and a rolling restart', () => {
    const s = base()
    s.mutators.header.config = { headers: { 'X-User': '{{ .Subject }}', 'X-Email': 'e' } }
    const v = validate(s, base(), noUse())
    expect(v.changes).toEqual([{ kind: 'mutator', handler: 'header', change: 'config', changedKeys: ['headers'], sensitive: true }])
    expect(v.issues.map((i) => i.code)).toContain('rolling_restart')
  })
})

describe('secrets (set by the platform, never in the Gateway)', () => {
  const saved = { introspection_url: 'http://hydra', introspection_request_headers: { 'X-Tenant': 'acme', Authorization: 'Basic c2VjcmV0c2VjcmV0' }, pre_authorization: { client_id: 'jinbe', client_secret: 'clear!' } }

  it('masks secret keys and credential-looking values', () => {
    const out = maskConfig(saved)!
    expect(out.introspection_request_headers).toEqual({ 'X-Tenant': 'acme', Authorization: MASK })
    expect(out.pre_authorization).toEqual({ client_id: 'jinbe', client_secret: MASK })
    expect(out.introspection_url).toBe('http://hydra')
  })

  it('drops a secret key sent back as ***, and refuses one with a value', () => {
    const a = resolveSecrets({ pre_authorization: { client_id: 'jinbe', client_secret: MASK } }, saved)
    expect(a.issues).toEqual([])
    expect(a.config).toEqual({ pre_authorization: { client_id: 'jinbe' } })
    const b = resolveSecrets({ api: { auth: { basic: { password: 'vault:kv/x#y' } } } }, undefined)
    expect(b.issues.map((i) => i.code)).toEqual(['secret_set_by_platform'])
    const c = resolveSecrets({ headers: { Authorization: 'vault:kv/hydra#basic' } }, undefined)
    expect(c.issues.map((i) => `${i.code}:${i.path}`)).toEqual(['secret_set_by_platform:headers.Authorization'])
  })

  it('matches secret keys like the operator: exact name, any depth, any case (token_url is fine)', () => {
    expect(resolveSecrets({ token_url: 'http://t', headers: { Token: 'x' } }, undefined).issues.map((i) => i.path)).toEqual(['headers.Token'])
  })

  it('refuses a credential-looking value, and *** over a live credential', () => {
    expect(resolveSecrets({ headers: { Authorization: 'Bearer abcdefghij' } }, undefined).issues.map((i) => i.code)).toEqual(['secret_in_config'])
    expect(resolveSecrets({ introspection_request_headers: { Authorization: MASK } }, saved).issues.map((i) => i.code)).toEqual(['secret_in_config'])
    expect(resolveSecrets({ headers: { 'X-New': MASK } }, saved).issues.map((i) => i.code)).toEqual(['secret_nothing_to_keep'])
  })

  it('keeps a masked non-credential value from the saved config', () => {
    const { config, issues } = resolveSecrets({ introspection_request_headers: { 'X-Tenant': MASK } }, saved)
    expect(issues).toEqual([])
    expect(config).toEqual({ introspection_request_headers: { 'X-Tenant': 'acme' } })
  })
})
