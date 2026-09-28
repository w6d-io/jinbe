import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'

const mocks = vi.hoisted(() => ({
  getServices: vi.fn(),
  getRouteMap: vi.fn(),
  env: {} as Record<string, unknown>,
}))

vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getServices: mocks.getServices, getRouteMap: mocks.getRouteMap },
}))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  Object.assign(mocks.env, real.env)
  return { ...real, env: mocks.env }
})

import { opalPublisher, OPAL_PUSH_WINDOW_MS, OPAL_PUSH_BACKOFF_MS } from '../../../services/opal-publisher.js'
import { rbacOpalRoutes } from '../../../routes/rbac-opal.routes.js'
import { opalPushes } from '../../../telemetry/metrics.js'
import { componentLogger } from '../../../telemetry/logger.js'

const pushLog = componentLogger('opal-push')

const OPAL = 'http://auth-opal-server:7002'
const fetchMock = vi.fn()

function okResponse() {
  return { ok: true, status: 200 } as Response
}

function pushBody(call = 0): { entries: Array<Record<string, unknown>>; reason: string } {
  return JSON.parse(fetchMock.mock.calls[call][1].body as string)
}

async function served(): Promise<Array<Record<string, unknown>>> {
  let handler: ((req: FastifyRequest, reply: FastifyReply) => Promise<unknown>) | undefined
  const fastify = {
    addHook: vi.fn(),
    get: vi.fn((path: string, a: unknown, b?: unknown) => {
      if (path === '/opal-datasource') handler = (typeof a === 'function' ? a : b) as typeof handler
    }),
  } as unknown as FastifyInstance
  await rbacOpalRoutes(fastify)
  let body: { entries: Array<Record<string, unknown>> } | undefined
  const reply = { send: (b: typeof body) => { body = b; return reply } } as unknown as FastifyReply
  await handler!({} as FastifyRequest, reply)
  return body!.entries
}

async function counter(result: 'ok' | 'failed'): Promise<number> {
  const metric = await opalPushes.get()
  return metric.values.find((v) => v.labels.result === result)?.value ?? 0
}

describe('opalPublisher', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    opalPublisher.reset()
    fetchMock.mockReset().mockResolvedValue(okResponse())
    vi.stubGlobal('fetch', fetchMock)
    mocks.getServices.mockResolvedValue(['kuma', 'jinbe'])
    mocks.getRouteMap.mockImplementation(async (svc: string) => (svc === 'kuma' ? { rules: [] } : null))
    Object.assign(mocks.env, {
      OPAL_SERVER_URL: OPAL,
      OPAL_SERVER_TOKEN: undefined,
      OPAL_CLIENT_TOKEN: 't'.repeat(64),
      OPAL_DATA_REFRESH_SECONDS: 60,
      JINBE_INTERNAL_URL: 'http://auth-jinbe:8080',
    })
    vi.spyOn(pushLog, 'info').mockImplementation(() => {})
    vi.spyOn(pushLog, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('pushes the datasource manifest to opal-server after a change, without making the caller wait', async () => {
    opalPublisher.schedule('rbac.group_created')
    expect(fetchMock).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(OPAL_PUSH_WINDOW_MS)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(`${OPAL}/data/config`)
    expect(init.method).toBe('POST')
    expect(init.headers.Authorization).toBeUndefined()
    expect(pushBody().reason).toBe('rbac.group_created')
  })

  it('pushes exactly the entries GET /opal-datasource serves, minus the polling interval', async () => {
    const manifest = await served()
    await opalPublisher.refreshAll('test')

    const pushed = pushBody().entries
    expect(pushed).toEqual(manifest.map(({ periodic_update_interval: _, ...entry }) => entry))
    expect(pushed.map((e) => e.dst_path)).toEqual(expect.arrayContaining(['/bindings', '/site_login', '/roles', '/route_map', '/api_clients']))
    for (const entry of pushed) expect(entry).toMatchObject({ config: { headers: { Authorization: `Bearer ${'t'.repeat(64)}` } } })
  })

  it('coalesces a burst of changes into one push', async () => {
    opalPublisher.schedule('rbac.group_created')
    opalPublisher.schedule('site.permissions_published')
    opalPublisher.schedule('site_login.shop')
    opalPublisher.schedule('rbac.group_created')
    await vi.advanceTimersByTimeAsync(OPAL_PUSH_WINDOW_MS)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(pushBody().reason).toBe('rbac.group_created,site.permissions_published,site_login.shop')
  })

  it('pushes a change made during a push right after it, never concurrently', async () => {
    let release!: () => void
    fetchMock.mockImplementationOnce(() => new Promise<Response>((r) => { release = () => r(okResponse()) }))
    opalPublisher.schedule('first')
    await vi.advanceTimersByTimeAsync(OPAL_PUSH_WINDOW_MS)
    opalPublisher.schedule('second')
    await vi.advanceTimersByTimeAsync(OPAL_PUSH_WINDOW_MS)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    release()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(pushBody(1).reason).toBe('second')
  })

  it('does nothing and logs nothing without OPAL_SERVER_URL', async () => {
    mocks.env.OPAL_SERVER_URL = undefined
    opalPublisher.schedule('rbac.group_created')
    await opalPublisher.refreshAll('jinbe-startup')
    await vi.advanceTimersByTimeAsync(60_000)

    expect(fetchMock).not.toHaveBeenCalled()
    expect(mocks.getServices).not.toHaveBeenCalled()
    expect(pushLog.info).not.toHaveBeenCalled()
    expect(pushLog.error).not.toHaveBeenCalled()
  })

  it('refreshes at startup straight away, without waiting for the window', async () => {
    const done = opalPublisher.refreshAll('jinbe-startup')
    await vi.advanceTimersByTimeAsync(0)
    await done
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(pushBody().reason).toBe('jinbe-startup')
  })

  it('sends the OPAL server token when one is configured', async () => {
    mocks.env.OPAL_SERVER_TOKEN = 'opal-datasource-jwt'
    await opalPublisher.refreshAll('test')
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer opal-datasource-jwt')
  })

  it('retries with backoff and stays quiet when a retry succeeds', async () => {
    fetchMock.mockRejectedValueOnce(new Error('ECONNREFUSED')).mockResolvedValueOnce({ ok: false, status: 503 } as Response)
    const ok = await counter('ok')
    const done = opalPublisher.refreshAll('test')
    await vi.advanceTimersByTimeAsync(OPAL_PUSH_BACKOFF_MS[0] + OPAL_PUSH_BACKOFF_MS[1])
    await done

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(pushLog.error).not.toHaveBeenCalled()
    expect(await counter('ok')).toBe(ok + 1)
  })

  it('logs and counts a failure once per burst, after the retries run out', async () => {
    fetchMock.mockRejectedValue(new Error('getaddrinfo ENOTFOUND auth-opal-server'))
    const failed = await counter('failed')
    for (let i = 0; i < 5; i++) opalPublisher.schedule(`mutation-${i}`)
    await vi.advanceTimersByTimeAsync(OPAL_PUSH_WINDOW_MS + OPAL_PUSH_BACKOFF_MS.reduce((a, b) => a + b, 0))

    expect(fetchMock).toHaveBeenCalledTimes(OPAL_PUSH_BACKOFF_MS.length + 1)
    expect(pushLog.error).toHaveBeenCalledTimes(1)
    expect(vi.mocked(pushLog.error).mock.calls[0][0]).toMatchObject({ reason: expect.stringContaining('mutation-0,mutation-1') })
    expect(await counter('failed')).toBe(failed + 1)
  })
})

describe('GET /opal-datasource — periodic refresh', () => {
  beforeEach(() => {
    mocks.getServices.mockResolvedValue([])
    Object.assign(mocks.env, { OPAL_CLIENT_TOKEN: 't'.repeat(64), OPAL_DATA_REFRESH_SECONDS: 60 })
  })

  it('asks the OPAL client to refetch every entry on its own, so a lost push heals', async () => {
    const entries = await served()
    expect(entries.length).toBeGreaterThan(0)
    for (const entry of entries) expect(entry.periodic_update_interval).toBe(60)
  })

  it('leaves the interval out when it is set to 0', async () => {
    mocks.env.OPAL_DATA_REFRESH_SECONDS = 0
    for (const entry of await served()) expect(entry).not.toHaveProperty('periodic_update_interval')
  })
})
