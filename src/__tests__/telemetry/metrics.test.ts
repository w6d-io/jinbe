import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import Fastify from 'fastify'
import type { AddressInfo } from 'net'
import type { Server } from 'http'

vi.mock('../../middleware/require-admin.js', () => ({ requireAdmin: vi.fn(async () => undefined) }))
vi.mock('../../middleware/require-opal-client.js', () => ({
  requireOpalClient: vi.fn(async () => undefined),
  redactQueryToken: (u: unknown) => u,
}))
vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { getBindingsFromKratos: vi.fn() } }))
vi.mock('../../services/org-grants.repository.js', () => ({ orgGrantsRepository: { getAll: vi.fn() } }))
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn().mockResolvedValue({ admins: {} }),
    getRoles: vi.fn().mockResolvedValue({}),
    getAccessRules: vi.fn(),
  },
}))

import { register } from 'prom-client'
import { auditRoutes } from '../../routes/audit.routes.js'
import { rbacOpalRoutes } from '../../routes/rbac-opal.routes.js'
import { oathkeeperRoutes } from '../../routes/oathkeeper.routes.js'
import { createMetricsServer } from '../../telemetry/metrics-server.js'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { rbacService } from '../../services/rbac.service.js'

async function value(name: string, labels: Record<string, string> = {}): Promise<number | undefined> {
  const metric = (await register.getMetricsAsJSON()).find((m) => m.name === name)
  const hit = (metric?.values as Array<{ value: number; labels: Record<string, unknown> }> | undefined)
    ?.find((v) => Object.entries(labels).every(([k, want]) => v.labels[k] === want))
  return hit?.value
}

describe('/metrics is not on the app router (OBS-3.2)', () => {
  it('GET /api/admin/audit/metrics is 404 — the app port no longer serves Prometheus', async () => {
    const app = Fastify()
    await app.register(auditRoutes, { prefix: '/api/admin/audit' })
    await app.ready()
    const res = await app.inject({ method: 'GET', url: '/api/admin/audit/metrics' })
    expect(res.statusCode).toBe(404)
    expect(app.hasRoute({ method: 'GET', url: '/api/admin/audit/metrics' })).toBe(false)
  })
})

describe('metrics server on its own port (OBS-3.2)', () => {
  let server: Server | undefined
  afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())))

  async function listen(token?: string) {
    server = createMetricsServer(token)
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve))
    return `http://127.0.0.1:${(server!.address() as AddressInfo).port}`
  }

  it('serves the exposition format on /metrics and nothing else', async () => {
    const base = await listen()
    const res = await fetch(`${base}/metrics`)
    expect(res.status).toBe(200)
    const text = await res.text()
    for (const name of [
      'jinbe_http_requests_total',
      'jinbe_opal_datasource_requests_total',
      'jinbe_opal_datasource_last_success_timestamp_seconds',
      'jinbe_rules_generated',
      'jinbe_rule_compile_errors',
      'jinbe_audit_v1_events_total',
      'jinbe_audit_v1_failures_total',
    ]) expect(text).toContain(name)
    expect((await fetch(`${base}/api/health`)).status).toBe(404)
  })

  it('requires the scrape token when one is configured', async () => {
    const base = await listen('scrape-token-value')
    expect((await fetch(`${base}/metrics`)).status).toBe(401)
    expect((await fetch(`${base}/metrics`, { headers: { authorization: 'Bearer scrape-token-value' } })).status).toBe(200)
  })
})

describe('OPAL datasource metrics (OBS-3.3)', () => {
  beforeEach(() => vi.clearAllMocks())

  it('counts each fetch per entry and stamps the last success', async () => {
    const app = Fastify()
    await app.register(rbacOpalRoutes, { prefix: '/api/admin/rbac' })
    await app.ready()
    const before = (await value('jinbe_opal_datasource_requests_total', { entry: 'opal/groups', status_class: '2xx' })) ?? 0
    await app.inject({ method: 'GET', url: '/api/admin/rbac/opal/groups' })
    expect(await value('jinbe_opal_datasource_requests_total', { entry: 'opal/groups', status_class: '2xx' })).toBe(before + 1)
    expect(await value('jinbe_opal_datasource_last_success_timestamp_seconds', { entry: 'opal/groups' })).toBeGreaterThan(0)
  })

  it('a 503 counts as a failed fetch and leaves the last success alone', async () => {
    vi.mocked(rbacService.getBindingsFromKratos).mockRejectedValue(new Error('kratos down'))
    const app = Fastify({ logger: false })
    await app.register(rbacOpalRoutes, { prefix: '/api/admin/rbac' })
    await app.ready()
    await app.inject({ method: 'GET', url: '/api/admin/rbac/bindings' })
    expect(await value('jinbe_opal_datasource_requests_total', { entry: 'bindings', status_class: '5xx' })).toBeGreaterThan(0)
    expect(await value('jinbe_opal_datasource_last_success_timestamp_seconds', { entry: 'bindings' })).toBeUndefined()
  })
})

describe('rule metrics (OBS-3.3)', () => {
  it('reports how many rules were served and how many would not compile', async () => {
    vi.mocked(redisRbacRepository.getAccessRules).mockResolvedValue([
      { id: 'ok', match: { url: 'https://app.example.com/api/<(users|groups)>/<.*>', methods: ['GET'] } },
      // Glob syntax under the regexp strategy: Oathkeeper refuses the WHOLE rule set on this one.
      { id: 'glob', match: { url: 'https://app.example.com/api/kuma/<**>', methods: ['GET'] } },
    ] as never)
    const app = Fastify({ logger: false })
    await app.register(oathkeeperRoutes, { prefix: '/api/oathkeeper' })
    await app.ready()
    const res = await app.inject({ method: 'GET', url: '/api/oathkeeper/rules' })
    expect(res.statusCode).toBe(200)
    expect(await value('jinbe_rules_generated')).toBe(2)
    expect(await value('jinbe_rule_compile_errors')).toBe(1)
  })
})
