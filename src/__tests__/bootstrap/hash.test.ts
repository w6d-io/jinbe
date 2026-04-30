import { describe, it, expect } from 'vitest'
import { canonicalHash } from '../../bootstrap/hash.js'

describe('bootstrap/hash', () => {
  it('returns sha256-prefixed hex digests', () => {
    const h = canonicalHash({ a: 1 })
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('produces identical hashes for objects with different key orderings', () => {
    expect(canonicalHash({ a: 1, b: 2 })).toBe(canonicalHash({ b: 2, a: 1 }))
  })

  it('produces different hashes for different content', () => {
    expect(canonicalHash({ a: 1 })).not.toBe(canonicalHash({ a: 2 }))
  })

  it('handles nested structures recursively', () => {
    const x = { outer: { b: [1, 2], a: 'x' } }
    const y = { outer: { a: 'x', b: [1, 2] } }
    expect(canonicalHash(x)).toBe(canonicalHash(y))
  })

  it('preserves array ordering (arrays are not sorted)', () => {
    expect(canonicalHash([1, 2, 3])).not.toBe(canonicalHash([3, 2, 1]))
  })

  it('handles primitives without throwing', () => {
    expect(canonicalHash(null)).toMatch(/^sha256:/)
    expect(canonicalHash(42)).toMatch(/^sha256:/)
    expect(canonicalHash('hello')).toMatch(/^sha256:/)
    expect(canonicalHash(true)).toMatch(/^sha256:/)
  })
})
