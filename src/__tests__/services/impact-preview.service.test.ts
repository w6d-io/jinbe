import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getAllForBundle: vi.fn().mockResolvedValue({
      groups: { devs: { billing: ['viewer'] }, admins: { global: ['super_admin'] } },
      roles: { billing: { viewer: ['billing:read'], editor: ['billing:read', 'billing:write'] }, global: { super_admin: ['*'] } },
      routeMaps: { billing: { rules: [
        { method: 'GET', path: '/api/billing/invoices', permission: 'billing:read' },
        { method: 'POST', path: '/api/billing/invoices', permission: 'billing:write' },
      ] } },
    }),
    getOrgServiceMap: vi.fn().mockResolvedValue({}),
    getOrgAdminMap: vi.fn().mockResolvedValue({}),
  },
}))
vi.mock('../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map([
      ['alice@x.dev', ['devs']],
      ['root@x.dev', ['admins']],
    ])),
  },
}))
vi.mock('../../services/audit-event.service.js', () => ({
  auditEventService: {
    query: vi.fn().mockResolvedValue([
      { who: 'alice@x.dev', method: 'GET', path: '/api/billing/invoices' },
    ]),
  },
}))

const { impactPreviewService } = await import('../../services/impact-preview.service.js')

// Fake OPA: allow iff the DATASET grants the user a role whose permissions
// contain the route permission — a tiny stand-in resolver so the flip-diff
// logic is exercised against two different datasets.
function fakeOpa() {
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
    const { input } = JSON.parse(init.body) as {
      input: { tuples: Array<{ email: string; action: string; object: string }>; ds: {
        bindings: { group_membership: Record<string, string[]>; groups: Record<string, Record<string, string[]>> }
        roles: Record<string, Record<string, string[]>>
        route_map: Record<string, { rules: Array<{ method: string; path: string; permission?: string }> }>
      } }
    }
    const rs = input.tuples.map((t) => {
      const svc = Object.entries(input.ds.route_map).find(([, rm]) =>
        rm.rules.some((r) => r.method === t.action && r.path === t.object))
      let allow = false
      if (svc) {
        const rule = svc[1].rules.find((r) => r.method === t.action && r.path === t.object)!
        const groups = input.ds.bindings.group_membership[t.email] ?? []
        const roles = groups.flatMap((g) => [
          ...(input.ds.bindings.groups[g]?.global ?? []),
          ...(input.ds.bindings.groups[g]?.[svc[0]] ?? []),
        ])
        const perms = roles.flatMap((r) => [
          ...(input.ds.roles.global?.[r] ?? []),
          ...(input.ds.roles[svc[0]]?.[r] ?? []),
        ])
        allow = !rule.permission || perms.includes(rule.permission) || perms.includes('*')
      }
      return { k: `${t.email}|${t.action}|${t.object}`, allow }
    })
    return { ok: true, json: async () => ({ result: [{ rs }] }) }
  }))
}

describe('impactPreviewService', () => {
  beforeEach(() => { vi.unstubAllGlobals(); fakeOpa() })

  it('reports a GAIN when a group is upgraded to a role with more permissions', async () => {
    const res = await impactPreviewService.preview({ groups: { devs: { billing: ['editor'] } } })
    expect(res.evaluated).toBe(true)
    expect(res.losses).toEqual([])
    expect(res.gains).toContainEqual({ email: 'alice@x.dev', action: 'POST', object: '/api/billing/invoices', before: false, after: true })
  })

  it('reports a LOSS when a group loses its role', async () => {
    const res = await impactPreviewService.preview({ groups: { devs: { } } })
    expect(res.evaluated).toBe(true)
    expect(res.losses).toContainEqual({ email: 'alice@x.dev', action: 'GET', object: '/api/billing/invoices', before: true, after: false })
    expect(res.gains).toEqual([])
  })

  it('reports no flips for a no-op change', async () => {
    const res = await impactPreviewService.preview({ groups: { devs: { billing: ['viewer'] } } })
    expect(res.losses).toEqual([])
    expect(res.gains).toEqual([])
  })

  it('scopes the blast radius: super-admin unaffected by a devs-group change', async () => {
    const res = await impactPreviewService.preview({ groups: { devs: { } } })
    const touched = [...res.losses, ...res.gains].map((f) => f.email)
    expect(touched).not.toContain('root@x.dev')
  })

  it('flags evaluated:false when OPA is unreachable — never "no impact"', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false })))
    const res = await impactPreviewService.preview({ groups: { devs: {} } })
    expect(res.evaluated).toBe(false)
    expect(res.losses).toEqual([])
  })
})
