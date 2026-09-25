import { describe, it, expect } from 'vitest'
import { render, orgGrantableProblem, platformPayload } from '../../sites/render.js'
import { siteSchema } from '../../sites/schemas.js'
import { routeSpecificity } from '../../policy/route-ties.js'
import { ACME, oathkeeperRegex, payrollSite, platform } from './fixtures.js'

// S-1: render(site, platform) is the ONE place every derived artefact comes from — route map,
// roles, groups, org map entries and the Site CR (one Oathkeeper rule per gate, disjoint patterns).

const errors = (r: ReturnType<typeof render>) => r.checks.filter((c) => c.level === 'error').map((c) => c.code)

describe('render — the fixture is a valid intent', () => {
  it('parses with the intent schema and renders with no error', () => {
    expect(siteSchema.safeParse(payrollSite()).success).toBe(true)
    expect(errors(render(payrollSite(), platform))).toEqual([])
  })
})

describe('render — route map', () => {
  const { routeMap } = render(payrollSite(), platform)

  it('emits one row per method, specific routes first, catch-all last', () => {
    expect(routeMap.slice(0, 3)).toEqual([
      { method: 'GET', path: '/health' },
      { method: 'GET', path: '/api/orgs/:orgId/payslips', permission: 'payslips:read', org_param: 'orgId' },
      { method: 'POST', path: '/api/orgs/:orgId/payslips', permission: 'payslips:create', org_param: 'orgId' },
    ])
    const catchAll = routeMap.slice(3)
    expect(catchAll.map((r) => r.method)).toEqual(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
    expect(catchAll.every((r) => r.path === '/:any*' && r.permission === undefined)).toBe(true)
  })

  it('puts the catch-all at the lowest specificity tier', () => {
    const lowest = Math.min(...routeMap.map((r) => routeSpecificity(r.path)))
    expect(routeSpecificity('/:any*')).toBe(lowest)
  })

  it('a catch-all needing a permission carries it', () => {
    const site = payrollSite()
    site.routes.catchAll = { gate: 'web', access: { kind: 'permission', permission: 'payroll:read' } }
    expect(render(site, platform).routeMap.at(-1)).toEqual({ method: 'DELETE', path: '/:any*', permission: 'payroll:read' })
  })

  it('refuses an org_param the policy cannot read', () => {
    const site = payrollSite()
    site.routes.items[1] = { ...site.routes.items[1], orgParam: 'org' }
    expect(errors(render(site, platform))).toContain('org_param')
  })

  it('refuses a route outside the site path prefix', () => {
    const site = payrollSite({ address: { host: 'shared.dev.stairling.com', pathPrefix: '/payroll' } })
    expect(errors(render(site, platform))).toContain('outside_prefix')
  })
})

describe('render — gates become disjoint Oathkeeper rules', () => {
  const { rules } = render(payrollSite(), platform)
  const byGate = (id: string) => rules.find((r) => r.id.startsWith(`site-payroll-${id}-`))!
  const url = (path: string) => `https://payroll.dev.stairling.com${path}`

  it('one rule per gate plus the pre-flight rule', () => {
    expect(rules.map((r) => r.id.replace(/-[0-9a-f]{10}$/, '')).sort()).toEqual([
      'site-payroll-public',
      'site-payroll-web',
      'site-payroll-web-preflight',
    ])
  })

  it('no URL is matched by two rules on the same method', () => {
    const probes = ['/', '/health', '/healthz', '/health/x', '/api/orgs/acme/payslips', '/anything/else']
    for (const probe of probes) {
      for (const method of ['GET', 'POST', 'OPTIONS']) {
        const hits = rules.filter((r) => r.match.methods.includes(method) && oathkeeperRegex(r.match.url).test(url(probe)))
        expect(hits.length, `${method} ${probe}`).toBeLessThanOrEqual(1)
      }
    }
  })

  it('the public gate matches only its route, the catch-all gate everything else', () => {
    expect(oathkeeperRegex(byGate('public').match.url).test(url('/health'))).toBe(true)
    expect(oathkeeperRegex(byGate('public').match.url).test(url('/healthz'))).toBe(false)
    const web = oathkeeperRegex(byGate('web').match.url)
    expect(web.test(url('/health'))).toBe(false)
    expect(web.test(url('/healthz'))).toBe(true)
    expect(web.test(url('/'))).toBe(true)
    expect(web.test('https://other.dev.stairling.com/')).toBe(false)
  })

  it('the pre-flight rule takes OPTIONS off the gate and allows it', () => {
    const web = byGate('web')
    const preflight = rules.find((r) => r.id.startsWith('site-payroll-web-preflight-'))!
    expect(web.match.methods).not.toContain('OPTIONS')
    expect(preflight.match).toEqual({ methods: ['OPTIONS'], url: web.match.url })
    expect(preflight.authorizer).toEqual({ handler: 'allow' })
  })

  it('the policy authorizer is the platform payload plus "app":"<site>"', () => {
    const authz = byGate('web').authorizer as { handler: string; config: { payload: string } }
    expect(authz.handler).toBe('remote_json')
    expect(authz.config.payload).toBe(platformPayload('payroll'))
    expect(authz.config.payload).toContain('"app": "payroll"')
    expect(authz.config.payload).toContain('"object": "{{ .MatchContext.URL.Path }}"')
    expect(Object.keys(authz.config)).toEqual(['payload'])
  })

  it('every rule forwards to the site upstream', () => {
    expect(rules.every((r) => r.upstream.url === 'http://payroll.payroll.svc.cluster.local:8080')).toBe(true)
  })

  it('rule names are content-hashed: same intent same name, a template edit a new name', () => {
    expect(render(payrollSite(), platform).rules.map((r) => r.id)).toEqual(rules.map((r) => r.id))
    const edited = payrollSite()
    edited.gates[0] = { ...edited.gates[0], mutators: [{ handler: 'header', config: { headers: { 'X-Site': 'p' } } }] }
    const renamed = render(edited, platform).rules.find((r) => r.id.startsWith('site-payroll-web-') && !r.id.includes('preflight'))!
    expect(renamed.id).not.toBe(byGate('web').id)
  })

  it('a deny route gets its own deny rule and no route map row', () => {
    const site = payrollSite()
    site.routes.items.push({ id: 'admin', methods: ['GET'], path: '/admin/:any*', gate: 'web', access: { kind: 'deny' }, source: 'manual' })
    const r = render(site, platform)
    const deny = r.rules.find((x) => x.id.startsWith('site-payroll-deny-'))!
    expect(deny.authorizer).toEqual({ handler: 'deny' })
    expect(oathkeeperRegex(deny.match.url).test(url('/admin/x'))).toBe(true)
    expect(r.routeMap.some((row) => row.path === '/admin/:any*')).toBe(false)
  })

  it('refuses two gates claiming one URL on one method', () => {
    const site = payrollSite()
    site.routes.items.push({ id: 'dup', methods: ['GET'], path: '/:x', gate: 'public', access: { kind: 'public' }, source: 'manual' })
    site.routes.items.push({ id: 'h2', methods: ['GET'], path: '/api/:any*', gate: 'public', access: { kind: 'public' }, source: 'manual' })
    site.gates.push({ ...site.gates[0], id: 'api', preflight: false })
    site.routes.items.push({ id: 'dup2', methods: ['GET'], path: '/api/x', gate: 'api', access: { kind: 'signed-in' }, source: 'manual' })
    expect(errors(render(site, platform))).toContain('gate_overlap')
  })

  it('two gates on one path with different methods is fine', () => {
    const site = payrollSite()
    site.gates.push({ ...site.gates[0], id: 'api', preflight: false })
    site.routes.items.push({ id: 'h-post', methods: ['POST'], path: '/hook', gate: 'api', access: { kind: 'signed-in' }, source: 'manual' })
    site.routes.items.push({ id: 'h-get', methods: ['GET'], path: '/hook', gate: 'public', access: { kind: 'public' }, source: 'manual' })
    expect(errors(render(site, platform))).toEqual([])
  })

  it('refuses a handler the gateway has not enabled', () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], authenticators: [{ handler: 'oauth2_introspection' }] }
    expect(errors(render(site, platform))).toContain('handler_disabled')
  })

  it('refuses a public route on a gate that cannot let anonymous callers in', () => {
    const site = payrollSite()
    site.routes.items[0] = { ...site.routes.items[0], gate: 'web' }
    expect(errors(render(site, platform))).toContain('public_needs_anonymous_gate')
  })

  it('serves every host of a pinned path prefix', () => {
    const site = payrollSite({ address: { host: 'shared.dev.stairling.com', pathPrefix: '/payroll' } })
    site.routes.items = [{ id: 'h', methods: ['GET'], path: '/payroll/health', gate: 'public', access: { kind: 'public' }, source: 'manual' }]
    const r = render(site, platform)
    expect(errors(r)).toEqual([])
    const web = r.rules.find((x) => x.id.startsWith('site-payroll-web-') && !x.id.includes('preflight'))!
    expect(oathkeeperRegex(web.match.url).test('https://shared.dev.stairling.com/payroll/x')).toBe(true)
    expect(oathkeeperRegex(web.match.url).test('https://shared.dev.stairling.com/other')).toBe(false)
    expect(r.routeMap.at(-1)?.path).toBe('/payroll/:any*')
  })
})

describe('render — roles and groups', () => {
  it('expands a role template', () => {
    const r = render(payrollSite({ roles: 'readonly' }), { ...platform })
    expect(r.roles).toEqual({ viewer: ['payroll:list', 'payroll:read'] })
  })

  it('maps platform groups to this site only', () => {
    expect(render(payrollSite(), platform).groups.platform).toEqual({ admins: { payroll: ['admin'] } })
  })

  it('org-grantable groups span only this site and never carry "*"', () => {
    const { groups, roles } = render(payrollSite(), platform)
    expect(groups.orgGrantable).toEqual({ 'payroll-editors': { payroll: ['editor'] } })
    for (const [name, def] of Object.entries(groups.orgGrantable)) {
      expect(Object.keys(def)).toEqual(['payroll'])
      expect(orgGrantableProblem('payroll', name, def.payroll, roles)).toBeNull()
    }
  })

  it('refuses an org-grantable group holding an "everything" role', () => {
    const site = payrollSite()
    site.groups.orgGrantable['payroll-admins'] = { label: 'x', roles: ['admin'] }
    expect(errors(render(site, platform))).toContain('org_grantable')
  })

  it('refuses an org-grantable group not named after the site, or without a permission', () => {
    expect(orgGrantableProblem('payroll', 'editors', ['editor'], { editor: ['a:read'] })).toMatch(/payroll-/)
    expect(orgGrantableProblem('payroll', 'payroll-empty', ['none'], { none: [] })).toMatch(/permission/)
  })

  it('refuses a group mapping to an unknown role', () => {
    const site = payrollSite()
    site.groups.platform.devs = ['ghost']
    expect(errors(render(site, platform))).toContain('unknown_role')
  })

  it('adds the site to each listed org', () => {
    expect(render(payrollSite(), platform).orgServiceMap).toEqual({ [ACME]: ['payroll'] })
  })
})

describe('render — Site CR', () => {
  it('is the auth.w6d.io/v1alpha1 Site the operator reconciles (site-operator api/v1alpha1)', () => {
    const { siteCr } = render(payrollSite(), platform)
    expect(siteCr.apiVersion).toBe('auth.w6d.io/v1alpha1')
    expect(siteCr.kind).toBe('Site')
    expect(siteCr.metadata).toMatchObject({ name: 'payroll', namespace: 'auth', labels: { 'auth.w6d.io/site': 'payroll' } })
    expect(Object.keys(siteCr.spec).sort()).toEqual(['exposure', 'gates', 'hosts', 'paused', 'upstream'])
    expect(siteCr.spec.hosts).toEqual(['payroll.dev.stairling.com'])
    expect(siteCr.spec.upstream).toEqual({ service: 'payroll', namespace: 'payroll', port: 8080, scheme: 'http', preserveHost: false })
    // A zone host rides the zone's wildcard Ingress: no per-site Ingress.
    expect(siteCr.spec.exposure).toEqual({ ingress: false })
    expect(siteCr.spec.paused).toBe(false)
    expect(siteCr.spec.gates.map((g) => g.name).sort()).toEqual(['public', 'web', 'web-preflight'])
    expect(siteCr.metadata.annotations['auth.w6d.io/spec-hash']).toMatch(/^[0-9a-f]{64}$/)
  })

  it('every gate name fits the operator pattern and every match URL pins the literal host then "/"', () => {
    const { siteCr } = render(payrollSite(), platform)
    for (const g of siteCr.spec.gates) {
      expect(g.name).toMatch(/^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/)
      expect(g.match.url.startsWith('<https?>://payroll.dev.stairling.com/')).toBe(true)
    }
  })

  it('vanity exposure is opt-in and renders one Ingress with the zone certificate', () => {
    const { siteCr } = render(payrollSite({ exposure: { mode: 'vanity' } }), platform)
    expect(siteCr.spec.exposure).toEqual({ ingress: true, tls: 'wildcard' })
  })

  it('refuses an upstream in a platform namespace', () => {
    const site = payrollSite({ upstream: { service: 'kratos-admin', namespace: 'auth', port: 4434 } })
    expect(errors(render(site, platform))).toContain('upstream_platform_namespace')
  })

  it('refuses the platform data services as upstreams, whatever the namespace', () => {
    for (const service of ['kratos-admin', 'opa', 'opal-server', 'redis-master', 'postgres']) {
      expect(errors(render(payrollSite({ upstream: { service, namespace: 'payroll', port: 80 } }), platform))).toContain('upstream_forbidden_service')
    }
  })

  it('an https upstream keeps its scheme', () => {
    const r = render(payrollSite({ upstream: { service: 'payroll', namespace: 'payroll', port: 8443, scheme: 'https' } }), platform)
    expect(r.rules[0].upstream.url).toBe('https://payroll.payroll.svc.cluster.local:8443')
    expect(r.siteCr.spec.upstream.scheme).toBe('https')
  })

  it('refuses a free-form upstream URL at the schema', () => {
    expect(siteSchema.safeParse({ ...payrollSite(), upstream: { url: 'http://kratos-admin.auth:4434' } }).success).toBe(false)
  })

  it('refuses a host outside every zone', () => {
    expect(errors(render(payrollSite({ address: { host: 'payroll.example.com' } }), platform))).toContain('host_outside_zones')
  })

  it('a paused site renders paused', () => {
    expect(render(payrollSite({ state: 'paused' }), platform).siteCr.spec.paused).toBe(true)
  })

  it('refuses the system services', () => {
    for (const name of ['jinbe', 'kuma', 'global']) {
      expect(errors(render(payrollSite({ name }), platform))).toContain('system_site')
    }
  })
})
