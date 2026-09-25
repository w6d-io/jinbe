import { describe, it, expect } from 'vitest'
import {
  routeSpecificity,
  routesTie,
  findRouteTies,
  findAllRouteTies,
  describeRouteTie,
} from '../../../policy/route-ties.js'

// These mirror opal-policies rbac.rego `route_specificity` / `path_matches`: two services tie when
// both hold the best-ranked match for some request, which the policy resolves to not_found.

describe('routeSpecificity — same bands as rbac.rego', () => {
  it('ranks exact > :param > :any*', () => {
    expect(routeSpecificity('/api/clusters')).toBe(100000 + 3)
    expect(routeSpecificity('/api/clusters/:id')).toBe(10000 + 3) // '' + api + clusters
    expect(routeSpecificity('/api/:any*')).toBe(1000 + 1)
    expect(routeSpecificity('/api/v1/:any*')).toBe(1000 + 2)
  })
})

describe('routesTie', () => {
  const r = (path: string, method = 'GET') => ({ method, path })

  it('exact == exact on the same method ties', () => {
    expect(routesTie(r('/api/x'), r('/api/x'))).toBe(true)
  })

  it('a different method never ties', () => {
    expect(routesTie(r('/api/x', 'GET'), r('/api/x', 'POST'))).toBe(false)
  })

  it('the same :param shape ties whatever the param names', () => {
    expect(routesTie(r('/api/x/:id'), r('/api/x/:name'))).toBe(true)
  })

  it(':param routes at the same rank that cover one URL tie (policy sees both as best)', () => {
    // /api/foo/bar matches both, both score 10002.
    expect(routesTie(r('/api/foo/:id'), r('/api/:x/bar'))).toBe(true)
  })

  it(':param routes that cannot cover one URL do not tie', () => {
    expect(routesTie(r('/api/foo/:id'), r('/api/bar/:id'))).toBe(false)
    expect(routesTie(r('/api/foo/:id'), r('/api/foo/:id/x'))).toBe(false)
  })

  it('the same :any* prefix ties', () => {
    expect(routesTie(r('/api/:any*'), r('/api/:any*'))).toBe(true)
    expect(routesTie(r('/api/:any*'), r('/api/:any*', 'POST'))).toBe(false)
  })

  it('different specificity is allowed — most specific wins in policy', () => {
    expect(routesTie(r('/api/x'), r('/api/:id'))).toBe(false)
    expect(routesTie(r('/api/x/:id'), r('/api/:any*'))).toBe(false)
    expect(routesTie(r('/api/v1/:any*'), r('/api/:any*'))).toBe(false)
  })

  it(':any* prefixes at the same depth that diverge do not tie', () => {
    expect(routesTie(r('/api/a/:any*'), r('/api/b/:any*'))).toBe(false)
  })
})

describe('findRouteTies', () => {
  it('reports each tie with both services and both paths', () => {
    const ties = findRouteTies('billing', [{ method: 'GET', path: '/api/clusters/:clusterId' }], {
      jinbe: [{ method: 'GET', path: '/api/clusters/:id', permission: 'clusters:read' }],
      kuma: [{ method: 'GET', path: '/app/:any*' }],
    })
    expect(ties).toEqual([
      {
        method: 'GET',
        service: 'billing',
        path: '/api/clusters/:clusterId',
        otherService: 'jinbe',
        otherPath: '/api/clusters/:id',
      },
    ])
    expect(describeRouteTie(ties[0])).toMatch(/billing.*GET \/api\/clusters\/:clusterId.*jinbe.*\/api\/clusters\/:id/)
  })

  it('ignores the service itself — one path with several permissions is an intended OR', () => {
    expect(findRouteTies('jinbe', [{ method: 'GET', path: '/api/x', permission: 'a' }], {
      jinbe: [{ method: 'GET', path: '/api/x', permission: 'b' }],
    })).toEqual([])
  })
})

describe('findAllRouteTies', () => {
  it('reports each colliding pair once', () => {
    const ties = findAllRouteTies({
      a: [{ method: 'GET', path: '/api/x' }],
      b: [{ method: 'GET', path: '/api/x' }],
      c: [{ method: 'GET', path: '/api/y' }],
    })
    expect(ties).toHaveLength(1)
    expect(ties[0]).toMatchObject({ service: 'a', otherService: 'b', path: '/api/x' })
  })
})
