import { getRedisClient } from '../services/redis-client.service.js'
import type { BootstrapLogger } from './types.js'

export class DependencyTimeoutError extends Error {
  constructor(public readonly dependency: string, public readonly attempts: number) {
    super(`Dependency '${dependency}' not ready after ${attempts} attempts`)
    this.name = 'DependencyTimeoutError'
  }
}

/**
 * Wait until Redis responds to PING or the timeout is exceeded.
 */
export async function waitForRedis(opts: {
  logger: BootstrapLogger
  timeoutMs?: number
  intervalMs?: number
}): Promise<void> {
  const { logger, timeoutMs = 60_000, intervalMs = 2_000 } = opts
  const deadline = Date.now() + timeoutMs
  let attempt = 0

  while (Date.now() < deadline) {
    attempt++
    try {
      const reply = await getRedisClient().ping()
      if (reply === 'PONG') {
        logger.info({ attempt }, 'Redis ready')
        return
      }
    } catch (err) {
      logger.debug({ err: (err as Error).message, attempt }, 'Redis not ready, retrying')
    }
    await sleep(intervalMs)
  }
  throw new DependencyTimeoutError('redis', attempt)
}

/**
 * Wait until Kratos public/admin API responds with a 2xx on /health/ready.
 */
export async function waitForKratos(opts: {
  url: string
  logger: BootstrapLogger
  timeoutMs?: number
  intervalMs?: number
}): Promise<void> {
  const { url, logger, timeoutMs = 60_000, intervalMs = 2_000 } = opts
  const deadline = Date.now() + timeoutMs
  let attempt = 0
  const probeUrl = url.replace(/\/$/, '') + '/health/ready'

  while (Date.now() < deadline) {
    attempt++
    try {
      const res = await fetch(probeUrl, { method: 'GET', signal: AbortSignal.timeout(3000) })
      if (res.ok) {
        logger.info({ attempt, url: probeUrl }, 'Kratos ready')
        return
      }
      logger.debug({ status: res.status, attempt }, 'Kratos not ready, retrying')
    } catch (err) {
      logger.debug({ err: (err as Error).message, attempt }, 'Kratos unreachable, retrying')
    }
    await sleep(intervalMs)
  }
  throw new DependencyTimeoutError('kratos', attempt)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
