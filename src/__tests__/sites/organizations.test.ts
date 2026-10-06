import { describe, expect, it } from 'vitest'
import { render } from '../../sites/render.js'
import { explicitOrganizations, organizationTemplate, organizationsOn } from '../../sites/organizations.js'
import { ORG_GATE, getsOf, passOf, whoOf } from '../../sites/presets.js'
import type { Site } from '../../sites/schemas.js'
import { siteSchema } from '../../sites/schemas.js'
import { ACME, payrollSite, platform } from './fixtures.js'

// A site's organizations switch (intent `organizations`): off refuses every org feature, on makes
// groups.orgGrantable the org roles and gives owners `ownerRole`; a site's own groups never carry
// everyOrg reach; a gate admitting API tokens lets the policy decide.

const codes = (r: ReturnType<typeof render>, level: 'error' | 'warn' = 'error') => r.checks.filter((c) => c.level === level).map((c) => c.code)
const off = (overrides: Partial<Site> = {}): Site => payrollSite({ organizations: undefined, ...overrides })
const withAdmin = (overrides: Partial<Site> = {}): Site => payrollSite({
  groups: { platform: { admins: ['admin'] }, orgGrantable: { 'payroll-admin': { label: 'Admins', roles: ['admin'] }, 'payroll-member': { label: 'Members', roles: ['viewer'] } } },
  ...overrides,
})

describe('organizations off (absent)', () => {
  it('refuses orgParam routes, org roles, everyOrg, the orgs list and a sign-up making organizations', () => {
    const r = render(off({ everyOrg: { editor: ['payslips:read'] }, signUp: { mode: 'open', domains: [], roles: ['viewer'], orgs: 'personal' } }), platform)
    const paths = r.checks.filter((c) => c.code === 'organizations_off').map((c) => c.path)
    expect(paths).toEqual(['routes.items.1.orgParam', 'routes.items.2.orgParam', 'groups.orgGrantable', 'everyOrg', 'orgs', 'signUp.orgs'])
  })

  it('publishes nothing of organizations, whatever the intent still lists', () => {
    const r = render(off({ everyOrg: { editor: ['payslips:read'] } }), platform)
    expect(r.orgRoles).toEqual({})
    expect(r.everyOrg).toEqual({})
    expect(r.orgServiceMap).toEqual({})
    expect(r.ownerRole).toBeNull()
  })

  it('a site without any org feature renders clean, and a sign-up with orgs none is fine', () => {
    const plain = off({ orgs: [], groups: { platform: { admins: ['admin'] }, orgGrantable: {} }, signUp: { mode: 'open', domains: [], roles: ['viewer'], orgs: 'none' } })
    plain.routes.items = plain.routes.items.map(({ orgParam: _, ...r }) => r)
    expect(codes(render(plain, platform))).not.toContain('organizations_off')
  })
})

describe('organizations on', () => {
  it('org roles come from groups.orgGrantable; owners hold `admin` by default', () => {
    const r = render(withAdmin(), platform)
    expect(r.orgRoles).toEqual({ admin: ['payslips:create', 'payslips:read'], member: ['payslips:read'] })
    expect(r.ownerRole).toBe('admin')
    expect(r.orgServiceMap).toEqual({ [ACME]: ['payroll'] })
    expect(codes(r, 'warn')).not.toContain('no_owner_role')
  })

  it('ownerRole names another org role; an unknown one is an error, a missing default a warning', () => {
    expect(render(withAdmin({ organizations: { enabled: true, ownerRole: 'member' } }), platform).ownerRole).toBe('member')
    const unknown = render(withAdmin({ organizations: { enabled: true, ownerRole: 'boss' } }), platform)
    expect(codes(unknown)).toContain('unknown_owner_role')
    expect(unknown.ownerRole).toBeNull()
    const noAdmin = render(payrollSite(), platform)
    expect(codes(noAdmin, 'warn')).toContain('no_owner_role')
    expect(codes(noAdmin)).not.toContain('unknown_owner_role')
    expect(noAdmin.ownerRole).toBeNull()
  })

  it('the switch is validated at the boundary', () => {
    expect(siteSchema.safeParse({ ...payrollSite(), organizations: { enabled: true, ownerRole: 'Not A Role' } }).success).toBe(false)
    expect(siteSchema.safeParse({ ...payrollSite(), organizations: { enabled: true, extra: 1 } }).success).toBe(false)
    expect(siteSchema.safeParse({ ...payrollSite(), organizations: { enabled: false } }).success).toBe(true)
  })
})

describe('everyOrg never through the site\'s own groups (cross-tenant reach)', () => {
  it("a role bound by a <site>-… group or the sign-up group is an error; a platform group's is not", () => {
    const own = render(payrollSite({ groups: { platform: { 'payroll-ops': ['editor'] }, orgGrantable: {} }, everyOrg: { editor: ['payslips:read'] } }), platform)
    expect(codes(own)).toContain('every_org_own_group')
    const signUp = render(payrollSite({ signUp: { mode: 'open', domains: [], roles: ['viewer'], orgs: 'personal' }, everyOrg: { viewer: ['payslips:read'] } }), platform)
    expect(codes(signUp)).toContain('every_org_own_group')
    const shared = render(payrollSite({ groups: { platform: { admins: ['editor'] }, orgGrantable: {} }, everyOrg: { editor: ['payslips:read'] } }), platform)
    expect(codes(shared)).not.toContain('every_org_own_group')
  })
})

describe('gates admitting API tokens', () => {
  const tokens = (authorizer: Site['gates'][number]['authorizer']): Site => {
    const s = payrollSite()
    s.gates[0] = { ...s.gates[0], authenticators: [{ handler: 'oauth2_introspection' }], authorizer }
    return s
  }
  const enabled = { ...platform, enabled: { ...platform.enabled, authenticators: [...platform.enabled.authenticators, 'oauth2_introspection'] } }

  it('must let the policy decide (it alone checks the key\'s organization); deny stays allowed', () => {
    expect(codes(render(tokens({ handler: 'allow' }), enabled))).toContain('tokens_need_policy')
    expect(codes(render(tokens('policy'), enabled))).not.toContain('tokens_need_policy')
    expect(codes(render(tokens({ handler: 'deny' }), enabled))).not.toContain('tokens_need_policy')
  })
})

describe('explicitOrganizations: a stored intent from before the switch', () => {
  it('using org features renders with organizations on; one using none, or saying either way, is left as it is', () => {
    expect(organizationsOn(explicitOrganizations(off()))).toBe(true)
    const plain = off({ orgs: [], groups: { platform: {}, orgGrantable: {} } })
    plain.routes.items = plain.routes.items.map(({ orgParam: _, ...r }) => r)
    expect(explicitOrganizations(plain)).toBe(plain)
    const said = payrollSite({ organizations: { enabled: false } })
    expect(explicitOrganizations(said)).toBe(said)
  })
})

describe('the organization gate and its template (kuma and MCP templates use these)', () => {
  const tokensOn = { ...platform, decisionUrl: 'http://proxy/v1/data/rbac/decision', enabled: { ...platform.enabled, authenticators: [...platform.enabled.authenticators, 'oauth2_introspection'] } }
  const templated = (): Site => {
    const base = payrollSite({ roles: 'standard', groups: { platform: {}, orgGrantable: {} } })
    const t = organizationTemplate(base)
    return { ...base, organizations: t.organizations, gates: [...base.gates, t.gate], groups: { platform: {}, orgGrantable: t.orgGrantable }, routes: { ...base.routes, items: [...base.routes.items, t.route] } }
  }

  it('people and org keys, the policy, the identity, API errors — a preset of its own', () => {
    expect(ORG_GATE).toMatchObject({ id: 'organization', authorizer: 'policy', errors: 'api' })
    expect(whoOf(ORG_GATE)).toBe('people-and-org-keys')
    expect(ORG_GATE.authenticators.map((a) => a.handler)).toEqual(['cookie_session', 'oauth2_introspection'])
    expect(passOf(ORG_GATE)).toBe('policy')
    expect(getsOf(ORG_GATE)).toBe('identity')
  })

  it('the template: /orgs/:orgId/:any* org-scoped on that gate, admin and member org roles, owners admin', () => {
    const t = organizationTemplate({ name: 'payroll', address: { pathPrefix: '/payroll' } })
    expect(t.route).toMatchObject({ path: '/payroll/orgs/:orgId/:any*', gate: 'organization', orgParam: 'orgId', access: { kind: 'permission', permission: 'payroll:use' } })
    expect(t.orgGrantable).toEqual({ 'payroll-admin': { label: 'Admins', roles: ['admin'] }, 'payroll-member': { label: 'Members', roles: ['user'] } })
    expect(t.organizations).toEqual({ enabled: true, ownerRole: 'admin' })
  })

  it('renders clean, passes tokens_need_policy, forwards X-Org-Id, X-Org-Roles and X-Client-Id', () => {
    const r = render(templated(), tokensOn)
    expect(codes(r)).toEqual([])
    expect(r.orgRoles).toEqual({ admin: expect.arrayContaining(['payroll:use']), member: ['payroll:list', 'payroll:read', 'payroll:use'] })
    expect(r.ownerRole).toBe('admin')
    expect(r.routeMap).toContainEqual(expect.objectContaining({ path: '/orgs/:orgId/:any*', org_param: 'orgId', permission: 'payroll:use' }))
    const gate = r.siteCr.spec.gates.find((g) => g.name === 'organization')!
    expect((gate.authorizer.config as { forward_response_headers_to_upstream: string[] }).forward_response_headers_to_upstream).toEqual(expect.arrayContaining(['X-Org-Id', 'X-Org-Roles', 'X-Client-Id']))
    expect((gate.authorizer.config as { payload: string }).payload).toContain('"client_id"')
  })
})

describe('the partner flow: an org key on a prefixed site, its upstream under another base path', () => {
  const MUNIA = '55555555-5555-4555-8555-555555555555'
  const machines = { id: 'machines', label: 'Machines', authenticators: [{ handler: 'oauth2_introspection' }], authorizer: 'policy' as const, mutators: [{ handler: 'header' }], errors: 'api' as const }
  const earnings = (upstreamPath = true): [Site, typeof platform] => [{
    ...payrollSite(),
    name: 'earnings',
    address: { host: 'api.dev.example.com', pathPrefix: '/api/v1/earnings' },
    upstream: { service: 'earnings', namespace: 'earnings', port: 8080, stripPath: '/api/v1', path: '/api/external' },
    gates: [machines],
    routes: { items: [{ id: 'external', methods: ['GET'], path: '/api/v1/earnings/:any*', gate: 'machines', access: { kind: 'permission', permission: 'earnings.external:read' }, source: 'manual' }], catchAll: { gate: 'machines', access: { kind: 'deny' } } },
    roles: { partner: ['earnings.external:read'] },
    groups: { platform: {}, orgGrantable: {} },
    organizations: { enabled: true },
    orgs: [MUNIA],
  }, { ...platform, upstreamPath, decisionUrl: 'http://proxy/v1/data/rbac/decision', enabled: { ...platform.enabled, authenticators: [...platform.enabled.authenticators, 'oauth2_introspection'] } }]

  it('/api/v1/earnings/days reaches the upstream as /api/external/earnings/days, with X-Client-Id and X-Org-Id', () => {
    const r = render(...earnings())
    expect(codes(r)).toEqual([])
    expect(r.siteCr.spec.upstream).toMatchObject({ stripPath: '/api/v1', path: '/api/external' })
    const rule = r.rules.find((x) => x.id.startsWith('site-earnings-machines-'))!
    // Oathkeeper removes strip_path, then prepends the URL's path.
    expect(rule.upstream).toEqual({ url: 'http://earnings.earnings.svc.cluster.local:8080/api/external', strip_path: '/api/v1' })
    const config = rule.authorizer.config as { forward_response_headers_to_upstream: string[]; payload: string }
    expect(config.forward_response_headers_to_upstream).toEqual(expect.arrayContaining(['X-Client-Id', 'X-Org-Id']))
    expect(config.payload).toContain('"app": "earnings"')
    expect(r.orgServiceMap).toEqual({ [MUNIA]: ['earnings'] })
  })

  it('refused while the operator cannot render upstream.path (SITES_UPSTREAM_PATH off); the path is validated', () => {
    expect(codes(render(...earnings(false)))).toContain('upstream_path_unsupported')
    for (const bad of ['api/external', '/api/:x', '/api/external/', '/a b']) {
      expect(siteSchema.safeParse({ ...earnings()[0], upstream: { ...earnings()[0].upstream, path: bad } }).success, bad).toBe(false)
    }
  })

  it("the key's scope is in Munia's catalogue (the route asks it)", async () => {
    const { expandScopes } = await import('../../services/api-key-scopes.js')
    const r = render(...earnings())
    const model = { orgSites: { [MUNIA]: ['jinbe', 'earnings'] }, roles: { earnings: r.roles }, groups: {}, asked: { earnings: ['earnings.external:read'] } }
    expect(expandScopes(model, MUNIA, ['earnings.external:read'])).toEqual(['earnings.external:read'])
    expect(expandScopes(model, MUNIA, ['role:earnings:partner'])).toEqual(['earnings.external:read'])
  })
})
