import { describe, it, expect, vi, beforeEach } from 'vitest'

// The importer must never leave the document: no URL fetch, no file or http $ref.
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    serviceExists: vi.fn(async () => true),
    getRouteMap: vi.fn(async () => ({ rules: [] })),
    getRoles: vi.fn(async () => []),
  },
}))

const fetchSpy = vi.fn(async () => new Response('{}'))

import { previewImport } from '../../../services/openapi-import/importer.js'

const spec = (extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    openapi: '3.0.3',
    info: { title: 't', version: '1' },
    paths: { '/things': { get: { tags: ['things'], responses: { '200': { description: 'ok' } } } } },
    ...extra,
  })

describe('openapi import: in-document refs only', () => {
  beforeEach(() => {
    fetchSpy.mockClear()
    vi.stubGlobal('fetch', fetchSpy)
  })

  it('refuses source.url (SSRF)', async () => {
    await expect(previewImport('svc', { url: 'http://169.254.169.254/latest/meta-data/' }, {})).rejects.toMatchObject({ code: 'invalid_spec', statusCode: 422 })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('refuses a file $ref (local file read)', async () => {
    const content = spec({
      paths: { '/x': { get: { summary: { $ref: 'file:///var/run/secrets/kubernetes.io/serviceaccount/token' }, responses: { '200': { description: 'ok' } } } } },
    })
    await expect(previewImport('svc', { content }, {})).rejects.toMatchObject({ code: 'invalid_spec', statusCode: 422 })
  })

  it('refuses a relative-file $ref', async () => {
    const content = spec({ components: { schemas: { A: { $ref: '../../etc/passwd' } } } })
    await expect(previewImport('svc', { content }, {})).rejects.toMatchObject({ code: 'invalid_spec', statusCode: 422 })
  })

  it('refuses an http $ref and never fetches it', async () => {
    const content = spec({ components: { schemas: { A: { $ref: 'http://opa.auth:8181/v1/data' } } } })
    await expect(previewImport('svc', { content }, {})).rejects.toMatchObject({ code: 'invalid_spec', statusCode: 422 })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('refuses unreadable content as invalid_spec', async () => {
    await expect(previewImport('svc', { content: '{ not json', format: 'json' }, {})).rejects.toMatchObject({ code: 'invalid_spec', statusCode: 422 })
  })

  it('still resolves in-document refs', async () => {
    const content = spec({
      paths: { '/things': { get: { tags: ['things'], responses: { '200': { $ref: '#/components/responses/Ok' } } } } },
      components: { responses: { Ok: { description: 'ok' } } },
    })
    const out = await previewImport('svc', { content }, {})
    expect(out).toBeTruthy()
  })
})
