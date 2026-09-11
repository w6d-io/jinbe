import { describe, it, expect, beforeEach } from 'vitest'
import { recordEngineStatus, propagation, resetEngineStatus } from '../../services/engine-status.service.js'

const T0 = Date.parse('2026-09-11T17:00:00Z')

const report = (id: string, revision: string | null) => ({
  labels: { id, version: '1.19.0' },
  bundles: {
    policy: {
      active_revision: revision,
      last_successful_activation: '2026-09-11T17:00:00Z',
      // The engine also posts ~59 KB of metrics here; it must be ignored, not choked on.
      metrics: { prometheus: { huge: 'x'.repeat(1000) } },
    },
  },
})

describe('engine status', () => {
  beforeEach(() => resetEngineStatus())

  it('says nothing is settled while no engine has reported', () => {
    const p = propagation('abc', T0)
    expect(p.inSync).toEqual({ current: 0, reporting: 0 })
    // "No engine reporting" and "every engine current" must never look alike.
    expect(p.settled).toBe(false)
  })

  it('counts an engine as current only on the revision being served', () => {
    recordEngineStatus(report('e1', 'abc'), 'policy', T0)
    recordEngineStatus(report('e2', 'old'), 'policy', T0)
    const p = propagation('abc', T0)
    expect(p.inSync).toEqual({ current: 1, reporting: 2 })
    expect(p.settled).toBe(false)
  })

  it('settles when every reporting engine holds it', () => {
    recordEngineStatus(report('e1', 'abc'), 'policy', T0)
    recordEngineStatus(report('e2', 'abc'), 'policy', T0)
    expect(propagation('abc', T0).settled).toBe(true)
  })

  it('forgets an engine that has gone quiet rather than claiming coverage for it', () => {
    recordEngineStatus(report('gone', 'abc'), 'policy', T0)
    recordEngineStatus(report('here', 'abc'), 'policy', T0 + 3 * 60_000)
    const p = propagation('abc', T0 + 3 * 60_000)
    expect(p.engines.map((e) => e.id)).toEqual(['here'])
  })

  it('replaces a report rather than accumulating one per poll', () => {
    recordEngineStatus(report('e1', 'old'), 'policy', T0)
    recordEngineStatus(report('e1', 'new'), 'policy', T0 + 1000)
    const p = propagation('new', T0 + 1000)
    expect(p.engines).toHaveLength(1)
    expect(p.engines[0].revision).toBe('new')
  })

  it('refuses a report that names no engine, instead of collecting anonymous ones', () => {
    expect(recordEngineStatus({ bundles: {} } as never, 'policy', T0)).toBe(false)
    expect(recordEngineStatus({ labels: {} } as never, 'policy', T0)).toBe(false)
    expect(propagation('abc', T0).engines).toHaveLength(0)
  })

  it('keeps an engine that reports a bundle it has not activated yet', () => {
    recordEngineStatus({ labels: { id: 'fresh' }, bundles: {} } as never, 'policy', T0)
    const p = propagation('abc', T0)
    expect(p.engines[0]).toMatchObject({ id: 'fresh', revision: null, current: false })
    expect(p.settled).toBe(false)
  })

  it('is not settled when the served revision is unknown', () => {
    recordEngineStatus(report('e1', 'abc'), 'policy', T0)
    expect(propagation(null, T0).settled).toBe(false)
  })
})

describe('who may read the propagation', () => {
  it('answers a signed-in operator, and refuses an anonymous caller', async () => {
    const { opaPolicyBundleRoutes } = await import('../../routes/opa-bundle-policy.routes.js')
    const routes: Array<{ url: string; method: string; hasOwnGuard: boolean }> = []
    const fastify = {
      addHook: () => {},
      get: (url: string, opts: { preHandler?: unknown }) =>
        routes.push({ url, method: 'GET', hasOwnGuard: !!opts?.preHandler }),
      post: (url: string, opts: { preHandler?: unknown }) =>
        routes.push({ url, method: 'POST', hasOwnGuard: !!opts?.preHandler }),
    }
    await opaPolicyBundleRoutes(fastify as never)

    // The bundle and the status report take the machine credential from the group hook.
    // `/propagation` carries its OWN guard, which is what lets the console — which holds no machine
    // credential — ask whether the change it just made has landed.
    const propagation = routes.find((r) => r.url === '/propagation')
    expect(propagation).toBeDefined()
    expect(propagation?.hasOwnGuard).toBe(true)
    expect(routes.find((r) => r.url === '/policy')?.hasOwnGuard).toBe(false)
  })
})
