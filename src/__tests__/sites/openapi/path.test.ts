import { describe, it, expect } from 'vitest'
import { joinPaths, shapeOf, toRoutePath } from '../../../sites/openapi/path.js'

// W1: path templates are tokenized linearly — no regex over the spec's text, so no ReDoS — and only
// what the route-path grammar can hold is imported.

describe('toRoutePath', () => {
  it('turns {param} into :param', () => {
    expect(toRoutePath('/orgs/{orgId}/invoices/{id}')).toEqual({ ok: true, path: '/orgs/:orgId/invoices/:id', params: ['orgId', 'id'], broadened: false })
    expect(toRoutePath('/')).toMatchObject({ ok: true, path: '/' })
    expect(toRoutePath('/a//b/')).toMatchObject({ ok: true, path: '/a/b' })
  })

  it('offers a partial template as one whole-segment parameter, flagged broadened', () => {
    expect(toRoutePath('/report.{fmt}')).toEqual({ ok: true, path: '/:fmt', params: ['fmt'], broadened: true })
    expect(toRoutePath('/a/{x}{y}')).toEqual({ ok: true, path: '/a/:x', params: ['x'], broadened: true })
    expect(toRoutePath('/a/{x}-{y}')).toMatchObject({ ok: true, broadened: true })
  })

  it.each([
    ['/a/{((a+)+)}'],
    ['/%2e%2e/admin'],
    ['/a/*'],
    ['/a/../b'],
    ['/a/./b'],
    ['/a/:id'],
    ['/a/(x)'],
    ['/a/{id'],
    ['/a/id}'],
    ['/a/{}'],
    ['/a/{1x}'],
    ['/a/{id}/b/{id}'],
    ['relative/path'],
    [`/${'a'.repeat(600)}`],
    [`/${Array.from({ length: 33 }, (_, i) => `s${i}`).join('/')}`],
    [`/${Array.from({ length: 17 }, (_, i) => `{p${i}}`).join('/')}`],
  ])('refuses %s as unsupported', (path) => {
    expect(toRoutePath(path)).toMatchObject({ ok: false, code: 'unsupported_path' })
  })

  it('stays linear on hostile input', () => {
    const hostile = `/${'{'.repeat(250)}${'a'.repeat(250)}`
    const t = Date.now()
    for (let i = 0; i < 1000; i++) toRoutePath(hostile)
    expect(Date.now() - t).toBeLessThan(500)
  })
})

describe('joinPaths / shapeOf', () => {
  it('joins a base path without doubling slashes', () => {
    expect(joinPaths('/v1', '/pets')).toBe('/v1/pets')
    expect(joinPaths('/v1/', '/')).toBe('/v1')
    expect(joinPaths('', '/pets')).toBe('/pets')
  })

  it('gives /a/:id and /a/:name the same shape', () => {
    expect(shapeOf('/a/:id')).toBe(shapeOf('/a/:name'))
    expect(shapeOf('/a/:id')).not.toBe(shapeOf('/a/b'))
  })
})
