import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { render } from '../../sites/render.js'
import { payrollSite, platform } from './fixtures.js'
import { convertLegacy } from '../../sites/migration/convert.js'
import { buildBuiltInRules } from '../../bootstrap/build-rules.js'

// CONTRACT: every Site jinbe renders must be accepted by site-operator's CRD exactly as sent.
// The API server silently PRUNES a field the schema does not declare — the write succeeds and the
// field is gone (a vanity `exposure.ingress: true` would quietly become a zone site). So an unknown
// field anywhere is a failure here, as are type, enum, pattern, bound and required violations.
//
// The CRD is a copy (crd/auth.w6d.io_sites.yaml); its header says how to refresh it. CEL rules
// (x-kubernetes-validations) are not evaluated here — render's own checks mirror them.

type Schema = {
  type?: string
  properties?: Record<string, Schema>
  additionalProperties?: Schema | boolean
  items?: Schema
  required?: string[]
  enum?: unknown[]
  pattern?: string
  minLength?: number
  maxLength?: number
  minimum?: number
  maximum?: number
  minItems?: number
  maxItems?: number
  'x-kubernetes-preserve-unknown-fields'?: boolean
}

const crdPath = fileURLToPath(new URL('./crd/auth.w6d.io_sites.yaml', import.meta.url))
const crd = parse(readFileSync(crdPath, 'utf8')) as {
  spec: { group: string; names: { kind: string }; versions: Array<{ name: string; schema: { openAPIV3Schema: Schema } }> }
}
const version = crd.spec.versions.find((v) => v.name === 'v1alpha1')!
const root = version.schema.openAPIV3Schema

/** Every way `value` breaks `schema`, as `path: problem`. */
function violations(schema: Schema, value: unknown, path: string): string[] {
  const out: string[] = []
  const kind = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value
  const expected = schema.type === 'integer' ? 'number' : schema.type
  if (expected && kind !== expected) return [`${path}: ${kind} where the schema wants ${schema.type}`]
  if (schema.type === 'integer' && !Number.isInteger(value)) out.push(`${path}: not an integer`)
  if (schema.enum && !schema.enum.includes(value)) out.push(`${path}: ${JSON.stringify(value)} not in ${JSON.stringify(schema.enum)}`)
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) out.push(`${path}: ${JSON.stringify(value)} does not match ${schema.pattern}`)
    if (schema.minLength !== undefined && value.length < schema.minLength) out.push(`${path}: shorter than ${schema.minLength}`)
    if (schema.maxLength !== undefined && value.length > schema.maxLength) out.push(`${path}: longer than ${schema.maxLength}`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) out.push(`${path}: below ${schema.minimum}`)
    if (schema.maximum !== undefined && value > schema.maximum) out.push(`${path}: above ${schema.maximum}`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) out.push(`${path}: fewer than ${schema.minItems} items`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) out.push(`${path}: more than ${schema.maxItems} items`)
    if (schema.items) value.forEach((v, i) => out.push(...violations(schema.items!, v, `${path}[${i}]`)))
  }
  if (kind === 'object') {
    const obj = value as Record<string, unknown>
    for (const key of schema.required ?? []) if (!(key in obj)) out.push(`${path}.${key}: required`)
    for (const [key, v] of Object.entries(obj)) {
      if (v === undefined) continue
      const sub = schema.properties?.[key]
      if (sub) out.push(...violations(sub, v, `${path}.${key}`))
      else if (typeof schema.additionalProperties === 'object') out.push(...violations(schema.additionalProperties, v, `${path}.${key}`))
      else if (!schema['x-kubernetes-preserve-unknown-fields'] && schema.additionalProperties !== true) out.push(`${path}.${key}: not in the CRD schema (the API server would prune it)`)
    }
  }
  return out
}

/** The CR as jinbe sends it. `metadata` is the API server's own object, checked for shape only. */
function crViolations(cr: ReturnType<typeof render>['siteCr']): string[] {
  const { metadata, ...rest } = cr
  const out = violations({ ...root, properties: { ...root.properties, metadata: { type: 'object', 'x-kubernetes-preserve-unknown-fields': true } } }, { metadata, ...rest }, 'Site')
  if (cr.apiVersion !== `${crd.spec.group}/v1alpha1`) out.push(`Site.apiVersion: ${cr.apiVersion}`)
  if (cr.kind !== crd.spec.names.kind) out.push(`Site.kind: ${cr.kind}`)
  if ('status' in cr) out.push('Site.status: written by the operator only')
  return out
}

const variants: Array<[string, ReturnType<typeof payrollSite>]> = [
  ['a zone site', payrollSite()],
  ['a vanity site', payrollSite({ exposure: { mode: 'vanity' } })],
  ['a paused site', payrollSite({ state: 'paused' })],
  ['an https upstream with preserveHost and stripPath', payrollSite({ upstream: { service: 'payroll', namespace: 'payroll', port: 8443, scheme: 'https', preserveHost: true, stripPath: '/api' } })],
  ['a site with a path prefix', (() => {
    const s = payrollSite({ address: { host: 'shared.dev.stairling.com', pathPrefix: '/payroll' } })
    s.routes.items = [{ id: 'h', methods: ['GET'], path: '/payroll/health', gate: 'public', access: { kind: 'public' }, source: 'manual' }]
    return s
  })()],
  ['a site with a deny route and header templates', (() => {
    const s = payrollSite()
    s.routes.items.push({ id: 'adm', methods: ['GET', 'DELETE'], path: '/admin/:any*', gate: 'web', access: { kind: 'deny' }, source: 'manual' })
    s.gates[0] = { ...s.gates[0], mutators: [{ handler: 'header', config: { headers: { 'X-User': '{{ print .Subject }}' } } }] }
    return s
  })()],
  ['a site asking for 2FA (per-rule /access redirect, aal in the payload)', payrollSite({
    login: { twoFactor: { scope: 'writes', clients: 'exempt' }, reach: 'granted' },
  })],
]
const withAccess = { ...platform, accessUrl: 'https://auth.dev.stairling.com/access' }

describe('Site CR contract with site-operator (config/crd/bases/auth.w6d.io_sites.yaml)', () => {
  it('the fixture is the Site CRD, v1alpha1', () => {
    expect(crd.spec.group).toBe('auth.w6d.io')
    expect(root.properties?.spec?.properties?.gates).toBeDefined()
  })

  it.each(variants)('%s renders to a Site the CRD accepts as sent, with no field pruned', (_label, site) => {
    const r = render(site, withAccess)
    expect(r.checks.filter((c) => c.level === 'error')).toEqual([])
    expect(crViolations(r.siteCr)).toEqual([])
  })

  it('migrated legacy rules (system sites, per-gate upstreams) convert to Sites the CRD accepts as sent', () => {
    const rules = buildBuiltInRules({
      domains: { auth: 'auth.dev.stairling.com', app: 'kuma.dev.stairling.com', api: 'jinbe.dev.stairling.com' },
      urls: { loginUi: 'http://auth-kratos-login-ui:3000', kratosPublic: 'http://auth-kratos-public:80', kratosAdmin: 'x', adminUi: 'http://auth-kuma:80', jinbeInternal: 'http://auth-jinbe:8080' },
    })
    const groups = convertLegacy(rules, { namespace: 'auth', fixes: { kuma: ['pin-app'], jinbe: ['pin-app'] } })
    expect(groups.find((g) => g.proposedSite === 'sign-in')!.siteCr!.spec.gates.some((g) => g.upstream)).toBe(true)
    for (const g of groups) expect(crViolations(g.siteCr!)).toEqual([])
  })

  it('the checker catches a field the schema does not declare', () => {
    const { siteCr } = render(payrollSite(), platform)
    const bad = { ...siteCr, spec: { ...siteCr.spec, zone: 'dev.stairling.com', exposure: { ingress: true } } } as unknown as typeof siteCr
    expect(crViolations(bad)).toEqual(expect.arrayContaining([
      'Site.spec.zone: not in the CRD schema (the API server would prune it)',
      'Site.spec.exposure.ingress: not in the CRD schema (the API server would prune it)',
    ]))
  })
})
