import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Writable } from 'stream'
import Fastify from 'fastify'

vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ xadd: vi.fn().mockResolvedValue('1-0'), expire: vi.fn(), hset: vi.fn() }),
}))

import { createLogger, fastifyLoggingOptions } from '../../telemetry/logger.js'
import { requestIdMiddleware } from '../../middleware/request-id.js'
import { requestLogger } from '../../middleware/request-logger.js'

const SESSION = 'ory_st_SUPERSECRETsessiontoken123'
const COOKIE = 'ory_kratos_session=MTcwMDAwMDAwMHxDOOKIEVALUE'
const BEARER = 'Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig'

/** Every line the logger wrote, parsed. */
function capture() {
  const lines: string[] = []
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(...chunk.toString().split('\n').filter(Boolean))
      cb()
    },
  })
  return { stream, lines, parsed: () => lines.map((l) => JSON.parse(l) as Record<string, unknown>) }
}

async function app(level = 'info') {
  const out = capture()
  const fastify = Fastify({ loggerInstance: createLogger({ level, destination: out.stream }), ...fastifyLoggingOptions })
  fastify.addHook('onRequest', requestIdMiddleware)
  fastify.addHook('onRequest', async (request) => {
    // What identity-extractor leaves behind for an authenticated caller.
    request.userContext = { id: 'kratos-uuid-1', email: 'alice@example.com', name: 'Alice' } as never
  })
  fastify.addHook('onResponse', requestLogger)
  fastify.get('/api/health', async () => ({ ok: true }))
  fastify.get('/api/oathkeeper/rules', async () => [])
  fastify.get('/api/things/:id', async (request) => {
    // An app line that carries the headers object, the way a careless debug line would.
    request.log.info({ headers: request.headers, req: { headers: request.headers } }, 'debugging')
    return { ok: true }
  })
  await fastify.ready()
  return { fastify, out }
}

describe('logger — redaction (OBS-1.1)', () => {
  it('never writes a cookie, authorization or session token, at any depth used', async () => {
    const { fastify, out } = await app()
    const res = await fastify.inject({
      method: 'GET',
      url: '/api/things/42?token=opal-secret-query',
      headers: { cookie: COOKIE, authorization: BEARER, 'x-session-token': SESSION },
    })
    expect(res.statusCode).toBe(200)
    const all = out.lines.join('\n')
    expect(out.lines.length).toBeGreaterThan(0)
    expect(all).not.toContain('MTcwMDAwMDAwMH')
    expect(all).not.toContain('SUPERSECRET')
    expect(all).not.toContain('eyJhbGciOiJSUzI1NiJ9')
    expect(all).not.toContain('opal-secret-query')
    expect(all).toContain('[redacted]')
  })

  it('redacts set-cookie on a response object and an axios-style error config', () => {
    const out = capture()
    const log = createLogger({ level: 'info', destination: out.stream })
    log.info({ res: { headers: { 'set-cookie': COOKIE } }, err: { config: { headers: { Authorization: BEARER, Cookie: COOKIE } } } }, 'x')
    const all = out.lines.join('\n')
    expect(all).not.toContain('MTcwMDAwMDAwMH')
    expect(all).not.toContain('eyJhbGciOiJSUzI1NiJ9')
  })
})

describe('logger — shape (OBS-1.1)', () => {
  it('writes ISO timestamps, a string level and log_type=app on application lines', () => {
    const out = capture()
    createLogger({ level: 'info', destination: out.stream }).info({ a: 1 }, 'hello')
    const [line] = out.parsed()
    expect(line.log_type).toBe('app')
    expect(line.level).toBe('info')
    expect(String(line.time)).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/)
    expect(line.service).toBe('jinbe')
  })

  it('propagates an incoming x-request-id to the log line and the response', async () => {
    const { fastify, out } = await app()
    const res = await fastify.inject({ method: 'GET', url: '/api/things/1', headers: { 'x-request-id': 'req-9fa6-abc' } })
    expect(res.headers['x-request-id']).toBe('req-9fa6-abc')
    const request = out.parsed().find((l) => l.log_type === 'request')!
    expect(request.request_id).toBe('req-9fa6-abc')
    // The app line written inside the handler carries the same id.
    expect(out.parsed().find((l) => l.msg === 'debugging')!.request_id).toBe('req-9fa6-abc')
  })

  it('generates a request id when none is sent, and refuses a header that could forge a log line', async () => {
    const { fastify, out } = await app()
    const res = await fastify.inject({ method: 'GET', url: '/api/things/1', headers: { 'x-request-id': 'bad"\n{"level":"fatal"' } })
    const id = res.headers['x-request-id'] as string
    expect(id).toMatch(/^[0-9a-f-]{36}$/)
    expect(out.parsed().find((l) => l.log_type === 'request')!.request_id).toBe(id)
  })
})

describe('request log (OBS-1.2)', () => {
  beforeEach(() => vi.clearAllMocks())

  it('writes one request line with route pattern and subject id — never the email', async () => {
    const { fastify, out } = await app()
    await fastify.inject({ method: 'GET', url: '/api/things/42' })
    const requests = out.parsed().filter((l) => l.log_type === 'request')
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ method: 'GET', route: '/api/things/:id', status: 200, subject: 'kratos-uuid-1' })
    expect(typeof requests[0].latency_ms).toBe('number')
    expect(out.lines.join('\n')).not.toContain('alice@example.com')
  })

  it('does not log /api/health', async () => {
    const { fastify, out } = await app()
    await fastify.inject({ method: 'GET', url: '/api/health' })
    expect(out.parsed().filter((l) => l.log_type === 'request')).toHaveLength(0)
  })

  it('logs the rules-sync poll only at debug', async () => {
    const info = await app('info')
    await info.fastify.inject({ method: 'GET', url: '/api/oathkeeper/rules' })
    expect(info.out.parsed().filter((l) => l.log_type === 'request')).toHaveLength(0)

    const debug = await app('debug')
    await debug.fastify.inject({ method: 'GET', url: '/api/oathkeeper/rules' })
    const lines = debug.out.parsed().filter((l) => l.log_type === 'request')
    expect(lines).toHaveLength(1)
    expect(lines[0].level).toBe('debug')
  })
})
