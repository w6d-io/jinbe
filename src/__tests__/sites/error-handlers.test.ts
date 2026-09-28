import { describe, expect, it } from 'vitest'
import { WHEN_ERRORS, errorHandlerProblems, errorHandlers, parseAccept, whenMatches } from '../../sites/error-handlers.js'
import { render } from '../../sites/render.js'
import type { Handler } from '../../sites/schemas.js'
import { payrollSite, platform } from './fixtures.js'

const ACCESS = 'https://auth.dev.example.com/access'
const CHROME = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
const FIREFOX = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8'

// Accept → what a website gate should do with a refusal, as a class.
const BROWSERS = [CHROME, FIREFOX, 'text/html']
const API_CLIENTS = [undefined, 'application/json', 'application/json, text/plain, */*', 'application/problem+json']
// No positive `when` separates these from a browser (whose Accept also has */*): platform fallback.
const UNCLAIMED = ['*/*', 'text/plain', 'image/png', 'application/xml', 'text/*', 'application/*']

/** Indexes of the handlers Oathkeeper would find responsible. */
const responsible = (hs: Handler[], error: string, accept: string | undefined) =>
  hs.flatMap((h, i) => (whenMatches(h.config?.when, error, accept) ? [i] : []))

describe('parseAccept mirrors gddo ParseAccept', () => {
  it('keeps q-weighted types, q=0 included', () => {
    expect(parseAccept('text/html, application/json;q=0.5, */*;q=0')).toEqual(['text/html', 'application/json', '*/*'])
  })
  it('stops at the first parameter that is not q', () => {
    expect(parseAccept(CHROME)).not.toContain('application/signed-exchange')
    expect(parseAccept(CHROME)).toContain('*/*')
    expect(parseAccept('text/html;charset=utf-8, application/json')).toEqual([])
  })
})

describe('when matching mirrors pipeline/errors/when.go', () => {
  it('a missing Accept reads as application/octet-stream', () => {
    expect(whenMatches([{ request: { header: { accept: ['application/octet-stream'] } } }], 'forbidden', undefined)).toBe(true)
    expect(whenMatches([{ request: { header: { accept: ['text/html'] } } }], 'forbidden', undefined)).toBe(false)
  })
  it('a request */* matches only a handler */*; a handler */* or type/* matches broadly', () => {
    expect(whenMatches([{ request: { header: { accept: ['text/html', 'application/json'] } } }], 'forbidden', '*/*')).toBe(false)
    expect(whenMatches([{ request: { header: { accept: ['*/*'] } } }], 'forbidden', CHROME)).toBe(true)
    expect(whenMatches([{ request: { header: { accept: ['text/*'] } } }], 'forbidden', 'text/html')).toBe(true)
  })
  it('no when, or an empty one, is responsible for everything; entries are OR-ed', () => {
    expect(whenMatches(undefined, 'not_found', 'text/html')).toBe(true)
    expect(whenMatches([], 'not_found', 'text/html')).toBe(true)
    expect(whenMatches([{ error: ['forbidden'] }, { error: ['not_found'] }], 'not_found', undefined)).toBe(true)
    expect(whenMatches([{ error: ['forbidden'] }], 'unauthorized', undefined)).toBe(false)
  })
})

describe('website preset: exactly one handler per refusal', () => {
  const hs = errorHandlers('website', 'payroll')!

  it('renders a when on every handler (none left to the gateway config)', () => {
    expect(hs.map((h) => h.handler)).toEqual(['redirect', 'json'])
    expect(hs.every((h) => Array.isArray(h.config?.when))).toBe(true)
    expect(hs[0].config).not.toHaveProperty('to')
  })

  for (const error of ['unauthorized', 'forbidden']) {
    it.each(BROWSERS)(`${error} from a browser (%s) → sign-in redirect`, (accept) => expect(responsible(hs, error, accept)).toEqual([0]))
    it.each(API_CLIENTS)(`${error} from an API client (Accept %s) → json`, (accept) => expect(responsible(hs, error, accept)).toEqual([1]))
    it.each(UNCLAIMED)(`${error} with Accept %s → no rule handler (platform fallback), never two`, (accept) => expect(responsible(hs, error, accept)).toEqual([]))
  }
  for (const error of ['not_found', 'internal_server_error']) {
    it.each([...BROWSERS, ...API_CLIENTS, ...UNCLAIMED])(`${error} (Accept %s) → json`, (accept) => expect(responsible(hs, error, accept)).toEqual([1]))
  }
})

describe('website preset on a 2FA site', () => {
  const hs = errorHandlers('website', 'payroll', ACCESS)!

  it('sends browsers refused by the policy to /access and unsigned ones to sign-in', () => {
    expect(hs.map((h) => h.handler)).toEqual(['redirect', 'redirect', 'json'])
    expect(hs[0].config).toMatchObject({ to: `${ACCESS}?site=payroll`, return_to_query_param: 'return_to' })
    for (const accept of BROWSERS) {
      expect(responsible(hs, 'forbidden', accept)).toEqual([0])
      expect(responsible(hs, 'unauthorized', accept)).toEqual([1])
    }
  })

  it('answers every other refusal with json at most once', () => {
    for (const error of WHEN_ERRORS) {
      for (const accept of [...API_CLIENTS, ...UNCLAIMED]) {
        expect(responsible(hs, error, accept)).toEqual(error === 'unauthorized' || error === 'forbidden' ? (API_CLIENTS.includes(accept) ? [2] : []) : [2])
      }
    }
  })
})

describe('api preset', () => {
  it('json owns every refusal through an explicit empty when (the global one is replaced)', () => {
    const hs = errorHandlers('api', 'payroll')!
    expect(hs).toEqual([{ handler: 'json', config: { when: [] } }])
    for (const error of WHEN_ERRORS) for (const accept of [...BROWSERS, ...API_CLIENTS, ...UNCLAIMED]) expect(responsible(hs, error, accept)).toEqual([0])
  })

  it('platform leaves the rule without handlers (the fallback list, first match wins)', () => {
    expect(errorHandlers('platform', 'payroll')).toBeUndefined()
  })
})

describe('errorHandlerProblems', () => {
  it('passes every preset', () => {
    for (const hs of [errorHandlers('website', 'p'), errorHandlers('website', 'p', ACCESS), errorHandlers('api', 'p')]) expect(errorHandlerProblems(hs!)).toEqual([])
  })

  it('refuses two handlers that take their when from the gateway (the sandbox 500)', () => {
    const [problem] = errorHandlerProblems([{ handler: 'redirect' }, { handler: 'json' }])
    expect(problem).toMatch(/#1 \(redirect\) and #2 \(json\) both answer unauthorized/)
  })

  it('refuses overlapping explicit conditions', () => {
    const html = (accept: string[]): Handler => ({ handler: 'redirect', config: { when: [{ error: ['forbidden'], request: { header: { accept } } }] } })
    expect(errorHandlerProblems([html(['text/html']), html(['text/html'])])).toHaveLength(1)
    expect(errorHandlerProblems([html(['text/*']), html(['text/html'])])).toHaveLength(1)
    expect(errorHandlerProblems([html(['text/html']), { handler: 'json', config: { when: [{ error: ['forbidden'] }] } }])).toHaveLength(1)
    expect(errorHandlerProblems([html(['text/html']), { handler: 'json', config: { when: [{ error: ['unauthorized'] }] } }])).toEqual([])
  })

  it('accepts one handler without a when', () => {
    expect(errorHandlerProblems([{ handler: 'json' }])).toEqual([])
  })

  it('refuses an error name the Oathkeeper schema does not know', () => {
    expect(errorHandlerProblems([{ handler: 'json', config: { when: [{ error: ['bad_request'] }] } }])[0]).toMatch(/no error 'bad_request'/)
  })
})

describe('render', () => {
  it('website gates render disjoint handlers and no ambiguity check', () => {
    const r = render(payrollSite(), platform)
    expect(r.checks.filter((c) => c.code === 'error_handlers_ambiguous')).toEqual([])
    expect(r.siteCr.spec.gates.find((g) => g.name === 'web')!.errors).toEqual(errorHandlers('website', 'payroll'))
  })

  it('an explicit error set where two handlers answer one refusal is an error, not a warning', () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], errors: [{ handler: 'redirect' }, { handler: 'json' }] }
    expect(render(site, platform).checks).toContainEqual(expect.objectContaining({ level: 'error', code: 'error_handlers_ambiguous', path: 'gates.0.errors' }))
  })
})
