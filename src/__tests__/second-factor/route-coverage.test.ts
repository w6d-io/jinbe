import { describe, it, expect } from 'vitest'

// Every route jinbe serves is either judged by the two-step gate or exempt for a stated reason.
// Walks the running service's own route table, so a route added later is covered by construction
// — and a public route added without a reason, or an admin route slipping out, fails here.

import { declaredRoutes, resetDeclaredRoutes } from '../../policy/declared-routes.js'
import { SECOND_FACTOR_EXEMPT, secondFactorScope } from '../../second-factor/gate.js'

const OPAL_TOKEN_ROUTES = /^\/api\/admin\/rbac\/(develop\/)?(opal|bindings)/

describe('two-step gate — route coverage', () => {
  it('judges every admin route; every exemption is public and gives a reason', async () => {
    process.env.NODE_ENV = 'development'
    process.env.DEV_BYPASS_AUTH = 'true'
    process.env.ENCRYPTION_KEY = 'x'.repeat(32)
    process.env.DEV_USER_EMAIL = 'dev@localhost.io'
    resetDeclaredRoutes()
    const { buildServer } = await import('../../server.js')
    const app = await buildServer()
    try {
      const routes = declaredRoutes()
      expect(routes.length).toBeGreaterThan(150)
      const scoped = routes.map((r) => ({ key: `${r.method} ${r.path}`, cls: r.class, path: r.path, scope: secondFactorScope(r.path) }))

      // The sandbox finding: the Sites API (and everything else under /api/admin) is judged.
      const admin = scoped.filter((r) => r.path.startsWith('/api/admin/') && !OPAL_TOKEN_ROUTES.test(r.path))
      expect(admin.length).toBeGreaterThan(80)
      expect(admin.filter((r) => !r.scope.gated).map((r) => r.key)).toEqual([])
      expect(scoped.find((r) => r.key === 'GET /api/admin/sites')?.scope).toEqual({ gated: true })

      // Every route needing a permission is judged.
      expect(scoped.filter((r) => r.cls === 'authorized' && !r.scope.gated).map((r) => r.key)).toEqual([])

      // Exempt routes: listed with a reason, and never one that takes a session.
      const exempt = scoped.filter((r) => !r.scope.gated)
      expect(exempt.filter((r) => !(r.scope as { reason: string | null }).reason).map((r) => r.key)).toEqual([])
      expect(exempt.filter((r) => r.cls !== 'public').map((r) => r.key)).toEqual([])
      // Every public route is exempt (it has no session to judge), so the two lists cannot drift.
      expect(scoped.filter((r) => r.cls === 'public' && r.scope.gated).map((r) => r.key)).toEqual([])
    } finally {
      await app.close()
    }
  }, 30_000)

  it('every exemption states a real reason, and /api/me/* is not one of them', () => {
    for (const e of SECOND_FACTOR_EXEMPT) expect(e.reason.length, e.prefix).toBeGreaterThan(20)
    expect(secondFactorScope('/api/me/permissions')).toEqual({ gated: true })
    expect(secondFactorScope('/api/me/organizations')).toEqual({ gated: true })
    expect(secondFactorScope('/api/public/second-factor')).toMatchObject({ gated: false })
    expect(secondFactorScope('/api/whoami')).toMatchObject({ gated: false })
  })
})
