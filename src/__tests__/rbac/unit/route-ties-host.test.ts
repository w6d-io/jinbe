import { describe, it, expect } from 'vitest'
import { findRouteTies } from '../../../policy/route-ties.js'

// Sites pin `app` in their Oathkeeper payload, so the policy never has to pick an owner for a
// request that reached them through their own host. Two app-pinned services on DIFFERENT hosts may
// therefore both serve `/`; anything unpinned (a legacy service) still competes on every host.

describe('findRouteTies — keyed by host for app-pinned services', () => {
  const catchAll = [{ method: 'GET', path: '/:any*' }]

  it('two pinned services on different hosts do not tie', () => {
    const ties = findRouteTies('payroll', catchAll, { billing: catchAll }, {
      payroll: ['payroll.dev.stairling.com'],
      billing: ['billing.dev.stairling.com'],
    })
    expect(ties).toEqual([])
  })

  it('two pinned services sharing a host still tie', () => {
    const ties = findRouteTies('payroll', catchAll, { billing: catchAll }, {
      payroll: ['shared.dev.stairling.com'],
      billing: ['Shared.dev.stairling.com', 'billing.dev.stairling.com'],
    })
    expect(ties).toHaveLength(1)
  })

  it('a pinned service still ties with an unpinned one', () => {
    const ties = findRouteTies('payroll', catchAll, { legacy: catchAll }, {
      payroll: ['payroll.dev.stairling.com'],
    })
    expect(ties).toHaveLength(1)
  })

  it('without host information the check is unchanged', () => {
    expect(findRouteTies('payroll', catchAll, { billing: catchAll })).toHaveLength(1)
  })
})
