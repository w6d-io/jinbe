import { describe, it, expect, beforeEach, vi } from 'vitest'

// First init (no marker) and the S3 backup, per BACKUP_RESTORE_ON_FIRST_INIT: auto restores latest.json
// when there is one and keeps the seeded model otherwise; false never restores; true restores or fails
// the run before the marker is written.

const h = vi.hoisted(() => ({
  enabled: true,
  latest: { version: 1 } as unknown,
  getLatest: vi.fn(),
  importBundle: vi.fn(),
  writeMarker: vi.fn(),
  applyModel: vi.fn(),
  seedAdmin: vi.fn(),
}))

vi.mock('../../services/backup-store.service.js', () => ({ backupStore: { enabled: () => h.enabled, getLatest: h.getLatest } }))
vi.mock('../../services/rbac-bundle.service.js', () => ({ rbacBundleService: { import: h.importBundle } }))
vi.mock('../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { invalidateBundleEtag: vi.fn() } }))
vi.mock('../../bootstrap/marker.js', () => ({ readMarker: vi.fn(async () => null), writeMarker: h.writeMarker, clearMarker: vi.fn() }))
vi.mock('../../bootstrap/lock.js', () => ({ acquireLock: vi.fn(async () => 'lock'), releaseLock: vi.fn(async () => {}), generateHolderId: () => 'holder' }))
vi.mock('../../bootstrap/build-rules.js', () => ({ buildBuiltInRules: () => [] }))
vi.mock('../../bootstrap/upsert-rules.js', () => ({ upsertBuiltInRules: vi.fn() }))
vi.mock('../../bootstrap/apply.js', () => ({ applyModel: h.applyModel }))
vi.mock('../../bootstrap/converge.js', () => ({ convergeJinbe: vi.fn() }))
vi.mock('../../bootstrap/seed-admin.js', () => ({ seedDefaultAdmin: h.seedAdmin }))
vi.mock('../../bootstrap/break-glass.js', () => ({ sweepBreakGlass: vi.fn(async () => {}) }))
vi.mock('../../sites/republish.js', () => ({ persistExplicitRoles: vi.fn() }))
vi.mock('../../second-factor/settings.js', () => ({ migrateSecondFactorFlags: vi.fn(async () => ({ pinned: [] })) }))

import { runBootstrap, RestoreRequiredError } from '../../bootstrap/index.js'
import type { RestoreOnFirstInit } from '../../bootstrap/types.js'

const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
const run = (restoreOnFirstInit?: RestoreOnFirstInit) =>
  runBootstrap({ logger: logger as never, config: { domains: {}, urls: {} } as never, gitSha: 'sha', version: 'v', ...(restoreOnFirstInit ? { restoreOnFirstInit } : {}) })

beforeEach(() => {
  vi.clearAllMocks()
  h.enabled = true
  h.getLatest.mockImplementation(async () => h.latest)
  h.importBundle.mockResolvedValue(undefined)
})

describe('BACKUP_RESTORE_ON_FIRST_INIT', () => {
  it('auto (the default): restores latest.json after seeding, then writes the marker', async () => {
    expect((await run()).outcome).toBe('first-run')
    expect(h.applyModel).toHaveBeenCalled()
    expect(h.importBundle).toHaveBeenCalledWith(h.latest)
    expect(h.writeMarker).toHaveBeenCalled()
  })

  it('auto: no latest.json, or a failed import, keeps the seeded model and completes', async () => {
    h.getLatest.mockResolvedValueOnce(null)
    expect((await run('auto')).outcome).toBe('first-run')
    expect(h.importBundle).not.toHaveBeenCalled()
    h.importBundle.mockRejectedValueOnce(new Error('bad bundle'))
    expect((await run('auto')).outcome).toBe('first-run')
    expect(logger.warn).toHaveBeenCalledWith(expect.objectContaining({ err: 'Error: bad bundle' }), 'Backup restore failed — keeping the seeded model')
    expect(h.writeMarker).toHaveBeenCalledTimes(2)
  })

  it('false: never restores, says so, and completes on the seeded model', async () => {
    expect((await run('false')).outcome).toBe('first-run')
    expect(h.getLatest).not.toHaveBeenCalled()
    expect(h.importBundle).not.toHaveBeenCalled()
    expect(logger.info).toHaveBeenCalledWith('first init: restore skipped (BACKUP_RESTORE_ON_FIRST_INIT=false)')
    expect(h.writeMarker).toHaveBeenCalled()
  })

  it('true: restores like auto when latest.json is there', async () => {
    expect((await run('true')).outcome).toBe('first-run')
    expect(h.importBundle).toHaveBeenCalledWith(h.latest)
    expect(h.writeMarker).toHaveBeenCalled()
  })

  it.each([
    ['no latest.json', () => { h.getLatest.mockResolvedValue(null) }, /no latest\.json/],
    ['latest.json unreadable', () => { h.getLatest.mockRejectedValue(new Error('AccessDenied')) }, /could not be read: Error: AccessDenied/],
    ['the import fails', () => { h.importBundle.mockRejectedValue(new Error('bad bundle')) }, /importing latest\.json failed/],
    ['backup not configured', () => { h.enabled = false }, /backup is not configured/],
  ])('true: %s fails the run with RestoreRequiredError and writes no marker', async (_label, arrange, message) => {
    arrange()
    const err = await run('true').catch((e) => e)
    expect(err).toBeInstanceOf(RestoreRequiredError)
    expect(err.message).toMatch(message)
    expect(h.writeMarker).not.toHaveBeenCalled()
    expect(h.seedAdmin).not.toHaveBeenCalled()
  })
})
