import { describe, expect, it } from 'vitest'
import { withOwnerRoles } from '../../services/org-owner-roles.js'
import { buildPolicyData } from '../../authz/model/dataset.js'

// An organization's owners hold each serving site's owner role there, derived where the policy data is
// assembled (never stored): jinbe:owner in acme + shop serving acme with ownerRole admin → shop:admin.

const assignments = {
  acme: { ann: ['jinbe:owner'], bob: ['shop:member'], cat: ['jinbe:owner', 'shop:admin'] },
  globex: { ann: ['jinbe:owner'] },
}

describe('withOwnerRoles', () => {
  it("adds each serving site's owner role to every owner, nothing to the others", () => {
    expect(withOwnerRoles(assignments, { shop: 'admin', wiki: 'editor', crm: 'boss' }, { acme: ['jinbe', 'shop', 'wiki'], globex: ['jinbe'] })).toEqual({
      acme: { ann: ['jinbe:owner', 'shop:admin', 'wiki:editor'], bob: ['shop:member'], cat: ['jinbe:owner', 'shop:admin', 'wiki:editor'] },
      globex: { ann: ['jinbe:owner'] },
    })
  })

  it('a site that stops serving the org, or has no owner role, takes it away', () => {
    expect(withOwnerRoles(assignments, { shop: 'admin' }, { acme: ['jinbe'] }).acme.ann).toEqual(['jinbe:owner'])
    expect(withOwnerRoles(assignments, {}, { acme: ['jinbe', 'shop'] }).acme.ann).toEqual(['jinbe:owner'])
  })
})

describe('the policy data (plan, feeds) carries it', () => {
  it('in data.bindings.org_assignments, for members only', () => {
    const d = buildPolicyData(
      { roles: {}, groups: {}, orgRoles: { shop: { admin: ['cars:write'] } }, everyOrg: {}, routeMap: {}, orgSites: { acme: ['shop'] }, ownerRoles: { shop: 'admin' } },
      new Map([
        ['ann@x', { id: 'ann', groups: [], organizations: ['acme'] }],
        ['dan@x', { id: 'dan', groups: [], organizations: [] }],
      ]),
      { acme: { ann: ['jinbe:owner'], dan: ['jinbe:owner'] } },
      [],
    )
    expect(d.org_assignments).toEqual({ 'ann@x': { acme: ['jinbe:owner', 'shop:admin'] } })
  })
})
