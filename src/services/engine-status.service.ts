/**
 * Which revision each authorization engine is actually deciding against.
 *
 * The bundle is PULLED, so nothing here knows how many engines exist or where they are — which is
 * what makes the design resilient and, until now, unobservable: a change was committed the moment
 * the write returned and enforced at some unknown point inside a 20-40 second window. "Applied"
 * meant "stored", and an operator testing immediately tested the old answer.
 *
 * Each engine reports its own state after every bundle activation. Comparing what this service
 * SERVES to what each engine REPORTS answers the only question that matters: is this change live,
 * and on how many engines.
 *
 * Held in memory on purpose. It is a liveness observation, worthless once stale, and a restart of
 * this service simply means waiting one reporting interval to know again — which is cheaper and
 * more honest than persisting a claim about a world that may have moved.
 */

/** Beyond this, an engine has stopped reporting and is no longer counted as present. */
const PRESENCE_WINDOW_MS = 2 * 60 * 1000

export type EngineReport = {
  /** The engine's own instance id. New on restart, which is correct: that is a new reporter. */
  id: string
  revision: string | null
  activatedAt: string | null
  version: string | null
  /** When THIS service heard from it, which is what presence is judged on. */
  heardAt: number
}

export type Propagation = {
  /** The revision this service currently serves, or null when it cannot build one. */
  serving: string | null
  engines: Array<Omit<EngineReport, 'heardAt'> & { current: boolean; heardAt: string }>
  /** How many reporting engines hold the served revision, out of how many are reporting. */
  inSync: { current: number; reporting: number }
  /** True only when at least one engine reports and every one of them holds it. */
  settled: boolean
}

const reports = new Map<string, EngineReport>()

/** The shape OPA posts. Everything else it sends — a large metrics dump — is deliberately ignored. */
type StatusPayload = {
  labels?: { id?: unknown; version?: unknown }
  bundles?: Record<string, { active_revision?: unknown; last_successful_activation?: unknown } | undefined>
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null)

/**
 * Records one engine's report. Returns false when the payload names no engine, so the caller can
 * answer 400 rather than accumulate anonymous entries.
 */
export function recordEngineStatus(payload: StatusPayload, bundleName: string, now = Date.now()): boolean {
  const id = str(payload?.labels?.id)
  if (!id) return false
  const bundle = payload?.bundles?.[bundleName]
  reports.set(id, {
    id,
    revision: str(bundle?.active_revision),
    activatedAt: str(bundle?.last_successful_activation),
    version: str(payload?.labels?.version),
    heardAt: now,
  })
  forgetSilentEngines(now)
  return true
}

/**
 * Presence by recent report rather than by asking Kubernetes how many replicas there should be.
 * This service holds no permission to read pods, and a count derived from a reporter that has gone
 * quiet would claim a coverage nobody can observe.
 */
function forgetSilentEngines(now: number): void {
  for (const [id, r] of reports) {
    if (now - r.heardAt > PRESENCE_WINDOW_MS) reports.delete(id)
  }
}

export function propagation(serving: string | null, now = Date.now()): Propagation {
  forgetSilentEngines(now)
  const engines = [...reports.values()]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map(({ heardAt, ...rest }) => ({
      ...rest,
      current: serving !== null && rest.revision === serving,
      heardAt: new Date(heardAt).toISOString(),
    }))
  const current = engines.filter((e) => e.current).length
  return {
    serving,
    engines,
    inSync: { current, reporting: engines.length },
    // No engine reporting is NOT "settled": it is "not known", and the two must not look alike.
    settled: engines.length > 0 && current === engines.length,
  }
}

/** Test seam. */
export function resetEngineStatus(): void {
  reports.clear()
}
