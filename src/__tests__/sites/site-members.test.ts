import { describe, expect, it } from 'vitest'
import { payrollSite } from './fixtures.js'
import { siteGroupsOf } from '../../sites/members.js'

describe("a site's own groups (sites.members:write)", () => {
  it('are the <site>-… platform groups of its intent and its sign-up group, nothing else', () => {
    const site = payrollSite({
      groups: { platform: { 'payroll-editors': ['editor'], devs: ['viewer'], 'other-site-x': ['viewer'] }, orgGrantable: {} },
      signUp: { mode: 'open', domains: [], roles: ['viewer'], orgs: 'none' },
    })
    expect(siteGroupsOf(site)).toEqual({ 'payroll-editors': ['editor'], 'payroll-users': ['viewer'] })
  })

  it('a sign-up with no roles makes no group', () => {
    expect(siteGroupsOf(payrollSite({ signUp: { mode: 'closed', domains: [], roles: [], orgs: 'none' } }))).toEqual({})
  })
})
