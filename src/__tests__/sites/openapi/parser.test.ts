import { describe, it, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import fs from 'node:fs'
import { parseSpecSync } from '../../../sites/openapi/parse.js'
import { loadSpec } from '../../../sites/openapi/load.js'
import { SpecError } from '../../../sites/openapi/limits.js'

// W1: the Sites OpenAPI parser. Swagger 2.0 / OpenAPI 3.0 / 3.1 read into one model; every malicious
// input of the corpus refused fast, with a stable code, without reading a file or the network.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')

function codeOf(fn: () => unknown): string {
  try {
    fn()
  } catch (e) {
    expect(e).toBeInstanceOf(SpecError)
    return (e as SpecError).code
  }
  throw new Error('expected the spec to be refused')
}

const deep = (levels: number) => {
  let node = '{}'
  for (let i = 0; i < levels; i++) node = `{"a":${node}}`
  return `{"openapi":"3.0.0","info":{"title":"d","version":"1"},"x":${node},"paths":{}}`
}
const manyPaths = (n: number) => JSON.stringify({ openapi: '3.0.0', info: { title: 'n', version: '1' }, paths: Object.fromEntries(Array.from({ length: n }, (_, i) => [`/p${i}`, { get: { operationId: `op${i}` } }])) })
// `hops` references in a row: the path item's own $ref, then hops - 1 more.
const chain = (hops: number) => {
  const items: Record<string, unknown> = {}
  for (let i = 0; i < hops - 1; i++) items[`P${i}`] = { $ref: `#/components/pathItems/P${i + 1}` }
  items[`P${hops - 1}`] = { get: { operationId: 'end' } }
  return JSON.stringify({ openapi: '3.1.0', info: { title: 'c', version: '1' }, paths: { '/a': { $ref: '#/components/pathItems/P0' } }, components: { pathItems: items } })
}

describe('parse: the three formats', () => {
  it('reads Swagger 2.0: basePath, host (information only), shared parameters, never the schemas', () => {
    const spec = parseSpecSync(fixture('petstore-2.0.json'))
    expect(spec.format).toBe('2.0')
    expect(spec.basePaths).toEqual(['/v1'])
    expect(spec.hosts).toEqual(['10.0.0.1'])
    expect(spec.securitySchemes).toEqual(['petstore_auth'])
    expect(spec.operations.map((o) => `${o.method} ${o.path} ${o.operationId}`)).toEqual(['GET /pets listPets', 'POST /pets createPets', 'GET /pets/{petId} showPetById'])
    expect(spec.operations[2].params).toEqual(['petId'])
    expect(spec.operations[0].security).toEqual([{ petstore_auth: ['read:pets'] }])
  })

  it('reads OpenAPI 3.0: server variables, root security inherited, security: [] kept as said', () => {
    const spec = parseSpecSync(fixture('petstore-3.0.yaml'))
    expect(spec.format).toBe('3.0')
    expect(spec.basePaths).toEqual(['/v1'])
    expect(spec.hosts).toEqual(['petstore.example.com'])
    const health = spec.operations.find((o) => o.operationId === 'health')!
    expect(health).toMatchObject({ security: [], securityFrom: 'operation' })
    expect(spec.operations.find((o) => o.operationId === 'listPets')).toMatchObject({ securityFrom: 'root', security: [{ bearer: [] }] })
  })

  it('reads OpenAPI 3.1: components.pathItems through $ref; webhooks counted, not routes', () => {
    const spec = parseSpecSync(fixture('petstore-3.1.yaml'))
    expect(spec.format).toBe('3.1')
    expect(spec.operations.map((o) => o.operationId)).toEqual(['listOrgPets', 'deleteOrgPets'])
    expect(spec.operations[1].deprecated).toBe(true)
    expect(spec.counts.webhooks).toBe(1)
  })

  it('refuses what is not Swagger 2.0 / OpenAPI 3.0 / 3.1', () => {
    expect(codeOf(() => parseSpecSync('{"openapi":"4.0.0","paths":{}}'))).toBe('unsupported_version')
    expect(codeOf(() => parseSpecSync('{"swagger":"1.2"}'))).toBe('unsupported_version')
    expect(codeOf(() => parseSpecSync('[1,2]'))).toBe('invalid_spec')
    expect(codeOf(() => parseSpecSync('openapi: 3.0.0\n---\nopenapi: 3.0.0\n'))).toBe('unreadable_spec')
  })
})

describe('parse: the malicious corpus is refused, fast', () => {
  const cases: Array<[string, () => string, string]> = [
    ['billion laughs', () => fixture('billion-laughs.yaml'), 'too_many_aliases'],
    ['<< merge fan-out', () => fixture('merge-bomb.yaml'), 'too_many_aliases'],
    ['65-deep nesting', () => deep(65), 'too_deep'],
    ['2 001 paths', () => manyPaths(2001), 'too_many_paths'],
    ['a 10 MiB string', () => `{"openapi":"3.0.0","x":"${'a'.repeat(10 * 1024 * 1024)}"}`, 'spec_too_large'],
    ['a 70 KiB string', () => `{"openapi":"3.0.0","x":"${'a'.repeat(70 * 1024)}"}`, 'string_too_long'],
    ['__proto__ key', () => fixture('proto.json'), 'forbidden_key'],
    ['constructor.prototype keys', () => fixture('constructor-prototype.yaml'), 'forbidden_key'],
    ['!!js/function tag', () => fixture('js-function.yaml'), 'unreadable_spec'],
    ['circular $ref', () => fixture('ref-circular.yaml'), 'ref_cycle'],
    ['17-hop $ref chain', () => chain(17), 'ref_too_deep'],
    ['$ref file:///etc/passwd', () => fixture('ref-file-passwd.yaml'), 'external_ref'],
    ['$ref to the service-account token', () => fixture('ref-sa-token.yaml'), 'external_ref'],
    ['$ref http://169.254.169.254', () => fixture('ref-imds.yaml'), 'external_ref'],
  ]
  it.each(cases)('%s', (_label, input, code) => {
    const src = input()
    const t = Date.now()
    expect(codeOf(() => parseSpecSync(src))).toBe(code)
    expect(Date.now() - t).toBeLessThan(2000)
  })

  it('a 16-hop chain is still followed', () => {
    expect(parseSpecSync(chain(16)).operations.map((o) => o.operationId)).toEqual(['end'])
  })

  it('pollutes no prototype and runs no tag', () => {
    for (const f of ['proto.json', 'constructor-prototype.yaml', 'js-function.yaml']) expect(() => parseSpecSync(fixture(f))).toThrow()
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
    expect((globalThis as Record<string, unknown>).pwned).toBeUndefined()
  })

  it('schemas are never resolved: an external $ref in a response schema is ignored, not fetched', () => {
    const spec = parseSpecSync(JSON.stringify({ openapi: '3.0.0', info: { title: 's', version: '1' }, paths: { '/a': { get: { operationId: 'a', responses: { 200: { content: { 'application/json': { schema: { $ref: 'http://169.254.169.254/x' } } } } } } } } }))
    expect(spec.operations).toHaveLength(1)
  })
})

describe('loadSpec: the parse runs in a bounded worker', () => {
  afterEach(() => vi.restoreAllMocks())

  it('answers the model from the worker, and reads no file doing it', async () => {
    const src = fixture('petstore-3.0.yaml')
    const read = vi.spyOn(fs, 'readFileSync')
    const spec = await loadSpec(src)
    expect(spec.operations).toHaveLength(4)
    expect(read).not.toHaveBeenCalled()
  })

  it.each([
    ['billion-laughs.yaml', 'too_many_aliases'],
    ['ref-sa-token.yaml', 'external_ref'],
    ['proto.json', 'forbidden_key'],
  ])('refuses %s from the worker with its code', async (file, code) => {
    await expect(loadSpec(fixture(file))).rejects.toMatchObject({ code, statusCode: 422 })
  })

  it('refuses an oversized spec before starting a worker', async () => {
    await expect(loadSpec('x'.repeat(5 * 1024 * 1024 + 1))).rejects.toMatchObject({ code: 'spec_too_large' })
  })

  it('kills a parse that runs past its clock', async () => {
    const t = Date.now()
    await expect(loadSpec(manyPaths(2000), 'json', { parseMs: 1 })).rejects.toMatchObject({ code: 'parse_timeout' })
    expect(Date.now() - t).toBeLessThan(5000)
  })

  it('reads a 2 000-operation spec within the clock', async () => {
    const spec = await loadSpec(manyPaths(2000))
    expect(spec.operations).toHaveLength(2000)
  }, 15_000)
})
