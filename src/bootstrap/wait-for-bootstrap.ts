import { readMarker, MarkerCorruptError, type BootstrapMarker } from './marker.js'
import type { BootstrapLogger } from './types.js'

export class BootstrapTimeoutError extends Error {
  constructor(public readonly elapsedMs: number) {
    super(`Bootstrap marker not present after ${Math.round(elapsedMs / 1000)}s`)
    this.name = 'BootstrapTimeoutError'
  }
}

/**
 * Block until the bootstrap marker is present in Redis or the timeout elapses.
 *
 * Distinguishes:
 *   - Redis unreachable           — debug-level log, retry until deadline
 *   - Marker absent               — info-level log, retry until deadline
 *   - Marker present and parseable — return immediately
 *   - Marker corrupt              — throw MarkerCorruptError (do not retry)
 *
 * Default timeout: 6 minutes (matches the API Deployment startupProbe budget
 * configured in the Helm chart).
 */
export async function waitForBootstrap(opts: {
  logger: BootstrapLogger
  timeoutMs?: number
  intervalMs?: number
}): Promise<BootstrapMarker> {
  const { logger, timeoutMs = 360_000, intervalMs = 5_000 } = opts
  const start = Date.now()
  const deadline = start + timeoutMs
  let lastLoggedState: 'absent' | 'unreachable' | null = null

  for (;;) {
    try {
      const marker = await readMarker()
      if (marker) {
        logger.info(
          { elapsedMs: Date.now() - start, schemaVersion: marker.schemaVersion, gitSha: marker.gitSha },
          'Bootstrap marker present — proceeding',
        )
        return marker
      }
      if (lastLoggedState !== 'absent') {
        logger.info('Bootstrap marker absent — waiting for bootstrap Job to finish')
        lastLoggedState = 'absent'
      }
    } catch (err) {
      if (err instanceof MarkerCorruptError) {
        throw err
      }
      if (lastLoggedState !== 'unreachable') {
        logger.warn(
          { err: (err as Error).message },
          'Redis unreachable while waiting for bootstrap marker — retrying',
        )
        lastLoggedState = 'unreachable'
      }
    }

    if (Date.now() >= deadline) {
      throw new BootstrapTimeoutError(Date.now() - start)
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}
