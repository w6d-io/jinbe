import { createServer, type Server } from 'http'
import { timingSafeEqual } from 'crypto'
import { register } from 'prom-client'
import type { FastifyBaseLogger } from 'fastify'
import { env } from '../config/index.js'
import './metrics.js'

/**
 * Prometheus exposition on a port of its own.
 *
 * The app port is what Oathkeeper fronts; `/metrics` used to sit on it (under /api/admin/audit),
 * reachable by any signed-in caller through the gateway. A separate port is reachable only by what
 * the network lets reach the pod — the ServiceMonitor — and a scrape token can be required on top.
 */

function sameToken(given: string | undefined, expected: string): boolean {
  if (!given?.startsWith('Bearer ')) return false
  const a = Buffer.from(given.slice('Bearer '.length))
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

export function createMetricsServer(token: string | undefined = env.METRICS_TOKEN): Server {
  return createServer((req, res) => {
    if (req.method !== 'GET' || (req.url ?? '').split('?')[0] !== '/metrics') {
      res.writeHead(404).end()
      return
    }
    if (token && !sameToken(req.headers.authorization, token)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer' }).end()
      return
    }
    register.metrics().then(
      (body) => res.writeHead(200, { 'Content-Type': register.contentType }).end(body),
      () => res.writeHead(500).end(),
    )
  })
}

/** Listens on METRICS_PORT (0 = off). A failure to bind is logged; the app keeps serving. */
export function startMetricsServer(log: FastifyBaseLogger): Server | null {
  if (!env.METRICS_PORT) return null
  const server = createMetricsServer()
  server.on('error', (err) => log.error({ err }, 'metrics server failed'))
  server.listen(env.METRICS_PORT, env.METRICS_HOST, () =>
    log.info({ port: env.METRICS_PORT }, 'metrics listening'),
  )
  return server
}
