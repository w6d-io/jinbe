import { getRedisClient } from '../services/redis-client.service.js'

export const MARKER_KEY = 'rbac:bootstrap:state'

export interface BootstrapMarker {
  version: string
  schemaVersion: number
  gitSha: string
  bootstrappedAt: string
  lastUpgradeAt: string
  previousSchemaVersion: number | null
  manualMigration?: boolean
  migrations: Array<{
    from: number | null
    to: number
    appliedAt: string
    gitSha: string
    manual?: boolean
  }>
  builtInsHash: {
    rules: string
    routeMap: string
  }
}

export class MarkerCorruptError extends Error {
  constructor(message: string, public readonly raw: string) {
    super(message)
    this.name = 'MarkerCorruptError'
  }
}

/**
 * Read the bootstrap marker from Redis.
 *
 * Returns:
 *   null            — marker absent (first bootstrap)
 *   BootstrapMarker — parsed marker
 *
 * Throws MarkerCorruptError if the value exists but cannot be parsed
 * or is missing required fields.
 */
export async function readMarker(): Promise<BootstrapMarker | null> {
  const raw = await getRedisClient().get(MARKER_KEY)
  if (!raw) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new MarkerCorruptError(
      `Bootstrap marker is not valid JSON: ${(err as Error).message}`,
      raw,
    )
  }
  if (!isMarker(parsed)) {
    throw new MarkerCorruptError('Bootstrap marker is missing required fields', raw)
  }
  return parsed
}

/**
 * Write the marker to Redis (overwrites any existing value).
 */
export async function writeMarker(marker: BootstrapMarker): Promise<void> {
  await getRedisClient().set(MARKER_KEY, JSON.stringify(marker))
}

/**
 * Delete the marker (used by reset path).
 */
export async function clearMarker(): Promise<void> {
  await getRedisClient().del(MARKER_KEY)
}

function isMarker(v: unknown): v is BootstrapMarker {
  if (!v || typeof v !== 'object') return false
  const m = v as Record<string, unknown>
  return (
    typeof m.version === 'string' &&
    typeof m.schemaVersion === 'number' &&
    typeof m.gitSha === 'string' &&
    typeof m.bootstrappedAt === 'string' &&
    Array.isArray(m.migrations) &&
    typeof m.builtInsHash === 'object' &&
    m.builtInsHash !== null
  )
}
