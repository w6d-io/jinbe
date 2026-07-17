import { describe, it, expect } from 'vitest'
import { createJobRequestSchema } from '../../../schemas/job.schema.js'

// Finding #12: a restore job must reference an existing backup snapshot. An
// omitted date used to silently default to "now", targeting a snapshot that
// never existed. The schema now rejects a dateless restore (→ 400 via the
// global ZodError handler).
describe('createJobRequestSchema — restore requires a date', () => {
  const bases = [{ database: 'db', username: 'u', adminUsername: 'a' }]

  it('rejects a restore job with no date', () => {
    const r = createJobRequestSchema.safeParse({
      database_type: 'postgresql',
      action: 'restore',
      bases,
    })
    expect(r.success).toBe(false)
    if (!r.success) {
      expect(r.error.errors.some((e) => e.path.includes('date'))).toBe(true)
    }
  })

  it('accepts a restore job with a date', () => {
    const r = createJobRequestSchema.safeParse({
      database_type: 'postgresql',
      action: 'restore',
      date: '2026-07-15T10:00:00Z',
      bases,
    })
    expect(r.success).toBe(true)
  })

  it('accepts a backup job with no date (defaults to now downstream)', () => {
    const r = createJobRequestSchema.safeParse({
      database_type: 'mongodb',
      action: 'backup',
      bases,
    })
    expect(r.success).toBe(true)
  })
})
