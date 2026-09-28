import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('../../home/sources.js', async () => (await import('./world.js')).sourcesMock())
vi.mock('../../services/redis-client.service.js', async () => (await import('./world.js')).redisMock())

import { world, resetWorld } from './world.js'
import { archiveComponent, opaComponent, opalComponent, platformFacts, wafComponent, type PlatformFacts } from '../../home/modules/health.js'

const NOW = 1_800_000_000_000
const MIN = 60_000

function facts(over: Partial<PlatformFacts> = {}): PlatformFacts {
  return {
    now: NOW,
    gateway: { kind: 'off' },
    engines: { serving: null, since: null, reporting: 0, current: 0, silent: 0 },
    opaDirect: null,
    opal: { entries: 0, oldestMs: null },
    rules: null,
    outbox: { length: 0, oldestMs: null },
    auditFailures: 0,
    notificationsDead: 0,
    certs: { state: 'not_configured' },
    sources: {},
    ...over,
  }
}

beforeEach(() => resetWorld())

describe('policy sync (opal_data)', () => {
  it('is judged on the oldest entry: ok < 10 min, degraded < 30 min, down past it', () => {
    expect(opalComponent(facts({ opal: { entries: 3, oldestMs: NOW - 2 * MIN } }))).toMatchObject({ state: 'ok', summary: '2 min ago' })
    expect(opalComponent(facts({ opal: { entries: 3, oldestMs: NOW - 12 * MIN } })).state).toBe('degraded')
    expect(opalComponent(facts({ opal: { entries: 3, oldestMs: NOW - 675 * MIN } })).state).toBe('down')
    expect(opalComponent(facts()).state).toBe('unknown')
  })

  it('platformFacts takes the oldest of what opalLastSuccess returns (the source already keeps the current manifest only)', async () => {
    const now = Date.now()
    world.override.opalLastSuccess = async () => ({ bindings: now - MIN, 'opal/roles': now - 3 * MIN })
    const f = await platformFacts(now)
    expect(f.opal).toEqual({ entries: 2, oldestMs: now - 3 * MIN })
    expect(opalComponent(f).state).toBe('ok')
  })
})

describe('policy engine (opa)', () => {
  it('no engine ever reported and OPA answers /health → ok, reachable (OPAL-managed)', () => {
    expect(opaComponent(facts({ opaDirect: 'ok' }))).toMatchObject({ state: 'ok', summary: 'reachable (OPAL-managed)' })
  })

  it('no engine ever reported and OPA does not answer → down', () => {
    expect(opaComponent(facts({ opaDirect: 'down' }))).toMatchObject({ state: 'down', summary: 'OPA did not answer' })
  })

  it('no engine ever reported and no OPA_URL → unknown, as before', () => {
    expect(opaComponent(facts())).toMatchObject({ state: 'unknown', summary: 'no engine has reported' })
  })

  it('engines that reported and went silent stay down whatever /health says', () => {
    expect(opaComponent(facts({ opaDirect: 'ok', engines: { serving: 'rev', since: null, reporting: 0, current: 0, silent: 2 } })).state).toBe('down')
  })

  it('bundle mode keeps the revision logic', () => {
    const e = { serving: 'rev-abcdef12', since: NOW - 5 * MIN, reporting: 2, current: 1, silent: 0 }
    expect(opaComponent(facts({ opaDirect: 'ok', engines: e }))).toMatchObject({ state: 'degraded', summary: '1/2 engines on rev-abcd' })
    expect(opaComponent(facts({ engines: { ...e, current: 2 } })).state).toBe('ok')
  })

  it('platformFacts asks OPA /health only when OPA_URL is set', async () => {
    world.engines = []
    expect((await platformFacts()).opaDirect).toBeNull()
    expect(world.calls.opaHealthy).toBeUndefined()
    world.opaConfigured = true
    expect((await platformFacts()).opaDirect).toBe('ok')
    world.opaHealthy = false
    expect((await platformFacts()).opaDirect).toBe('down')
  })
})

describe('audit archive', () => {
  it('without an archiver: not_deployed, whatever the backlog', () => {
    world.archiveEnabled = false
    expect(archiveComponent(facts({ outbox: { length: 710, oldestMs: NOW - 53 * 60 * MIN } }))).toMatchObject({ state: 'not_deployed', summary: 'no archiver configured' })
  })

  it('with an archiver: lag drives the state', () => {
    world.archiveEnabled = true
    expect(archiveComponent(facts({ outbox: { length: 710, oldestMs: NOW - 53 * 60 * MIN } })).state).toBe('down')
    expect(archiveComponent(facts({ outbox: { length: 5, oldestMs: NOW - 2 * 60 * MIN } })).state).toBe('degraded')
    expect(archiveComponent(facts()).state).toBe('ok')
  })

  it('audit/v1 off wins over both', () => {
    world.auditSink = 'legacy'
    world.archiveEnabled = false
    expect(archiveComponent(facts()).summary).toBe('audit/v1 is off')
  })
})

describe('WAF', () => {
  it('carries unprotected sites and their distinct hosts beside the summary', () => {
    expect(wafComponent({ total: 5, waf: 1, unknown: 0, unprotectedHosts: 3 })).toMatchObject({
      state: 'degraded', summary: '1/5 sites behind the WAF',
      metrics: { total: 5, waf: 1, unknown: 0, unprotected: 4, unprotectedHosts: 3 },
    })
  })

  it('all behind the WAF → ok with zero unprotected', () => {
    expect(wafComponent({ total: 2, waf: 2, unknown: 0, unprotectedHosts: 0 })).toMatchObject({ state: 'ok', metrics: { unprotected: 0, unprotectedHosts: 0 } })
  })
})
