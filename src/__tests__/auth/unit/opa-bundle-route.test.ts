import { describe, it, expect } from 'vitest'
import { isPublicRoute } from '../../../middleware/require-auth.js'

// The trap this locks: a route with its own credential must be lifted out of the SESSION gate, or
// that gate refuses the machine token before the route's own hook ever runs — and the refusal looks
// exactly like a bad token. Measured: a credential that worked on /api/directory answered 401 here.

describe('the routes that carry their own credential', () => {
  it('lets the bundle route reach its own hook', () => {
    expect(isPublicRoute('/api/opa/policy')).toBe(true)
  })

  it('lets the directory route reach its own hook', () => {
    expect(isPublicRoute('/api/directory/organisations')).toBe(true)
  })

  it('still gates everything that has no hook of its own', () => {
    expect(isPublicRoute('/api/admin/users')).toBe(false)
    expect(isPublicRoute('/api/admin/enforced-config')).toBe(false)
  })

  it('does not open a path that merely starts with the same letters', () => {
    // `startsWith` on a prefix is how '/api/webhooks' once made every sub-path public.
    expect(isPublicRoute('/api/opaque-thing')).toBe(false)
  })
})
