import { describe, it, expect } from 'vitest'
import { orgParamProblem } from '../../../policy/route-org-param.js'

// opal-policies org.rego `rule_org`: org_param must name exactly one `:param` segment of the path,
// or the org id cannot be read and every request on the route is denied.

describe('orgParamProblem', () => {
  it('accepts a rule without org_param', () => {
    expect(orgParamProblem({ method: 'GET', path: '/api/x/:id' })).toBeNull()
  })

  it('accepts org_param naming exactly one :param segment', () => {
    expect(orgParamProblem({ method: 'GET', path: '/api/fleet/orgs/:orgId/x', org_param: 'orgId' })).toBeNull()
  })

  it('refuses a param the path does not carry', () => {
    expect(orgParamProblem({ method: 'GET', path: '/api/fleet/orgs/:id', org_param: 'orgId' })).toMatch(/orgId/)
  })

  it('refuses a param carried twice (ambiguous in policy)', () => {
    expect(orgParamProblem({ method: 'GET', path: '/api/:orgId/x/:orgId', org_param: 'orgId' })).toMatch(/more than once/)
  })

  it('refuses a non-string or empty org_param', () => {
    expect(orgParamProblem({ method: 'GET', path: '/api/:orgId', org_param: '' })).not.toBeNull()
    expect(orgParamProblem({ method: 'GET', path: '/api/:orgId', org_param: 3 as unknown as string })).not.toBeNull()
  })
})
