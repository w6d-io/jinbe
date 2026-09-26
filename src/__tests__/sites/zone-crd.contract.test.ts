import { describe, it, expect, beforeEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { violations, type Schema } from './crd-schema.js'

// CONTRACT: every Zone jinbe creates must be accepted by site-operator's CRD exactly as sent — an
// undeclared field would be pruned without a word. CEL rules (name ≤ 50, mode secret needs
// secretName) are not evaluated by the checker; the request schema mirrors them and they are
// asserted below.

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => {}) } }))

import { createZone, zoneNameFor } from '../../sites/zones.service.js'
import { createZoneBodySchema } from '../../sites/schemas.js'
import { setKubeSites, type KubeSites, type ZoneCr } from '../../sites/kube-sites.js'
import { resetSitesConfig } from '../../sites/config.js'
import { setDnsLookup } from '../../sites/dns-probe.js'

const crdPath = fileURLToPath(new URL('./crd/auth.w6d.io_zones.yaml', import.meta.url))
const crd = parse(readFileSync(crdPath, 'utf8')) as {
  spec: { group: string; scope: string; names: { kind: string; plural: string }; versions: Array<{ name: string; schema: { openAPIV3Schema: Schema } }> }
}
const root = crd.spec.versions.find((v) => v.name === 'v1alpha1')!.schema.openAPIV3Schema

function crViolations(cr: ZoneCr): string[] {
  const { metadata, ...rest } = cr
  const out = violations({ ...root, properties: { ...root.properties, metadata: { type: 'object', 'x-kubernetes-preserve-unknown-fields': true } } }, { metadata, ...rest }, 'Zone')
  if (cr.apiVersion !== `${crd.spec.group}/v1alpha1`) out.push(`Zone.apiVersion: ${cr.apiVersion}`)
  if (cr.kind !== crd.spec.names.kind) out.push(`Zone.kind: ${cr.kind}`)
  if (cr.metadata.name.length > 50) out.push('Zone.metadata.name: longer than 50 (CEL)')
  if (cr.spec.tls?.mode === 'secret' && !cr.spec.tls.secretName) out.push('Zone.spec.tls: mode secret needs secretName (CEL)')
  if ('status' in cr) out.push('Zone.status: written by the operator only')
  return out
}

const sent: ZoneCr[] = []
const actor = { id: 'sam', email: 'sam@x.test' }

beforeEach(() => {
  sent.length = 0
  process.env.SITES_KUBE = 'in-cluster'
  process.env.SITES_ZONE_ALLOWED_PARENTS = 'dev.stairling.com,stairfleet.com'
  process.env.SITES_ZONE_ISSUERS = 'letsencrypt-dns'
  resetSitesConfig()
  setDnsLookup({ addresses: async () => [] })
  setKubeSites({ listZones: async () => [], listIngresses: async () => [], createZone: async (cr: ZoneCr) => { sent.push(cr) } } as unknown as KubeSites)
})

const variants: Array<[string, unknown]> = [
  ['default TLS', { domain: 'apps.stairfleet.com' }],
  ['a per-site zone on a shared domain', { domain: 'dev.stairling.com', ingress: 'per-site' }],
  ['a named issuer and an ingress class', { domain: 'shop.dev.stairling.com', tls: { mode: 'issuer', issuer: 'letsencrypt-dns' }, ingressClass: 'nginx' }],
  ['the operator default issuer', { domain: 'stairfleet.com', tls: { mode: 'issuer' } }],
  ['an existing secret, explicit name', { domain: 'b2b.stairfleet.com', name: 'b2b', tls: { mode: 'secret', secretName: 'wildcard-b2b-tls' } }],
  ['a domain long enough to be hashed down to 50', { domain: 'a-rather-long-team-name.and-a-long-project.dev.stairling.com' }],
]

describe('Zone CR contract with site-operator (config/crd/bases/auth.w6d.io_zones.yaml)', () => {
  it('the fixture is the cluster-scoped Zone CRD, v1alpha1', () => {
    expect(crd.spec.group).toBe('auth.w6d.io')
    expect(crd.spec.scope).toBe('Cluster')
    expect(crd.spec.names.plural).toBe('zones')
    expect(root.properties?.spec?.properties?.domain).toBeDefined()
  })

  it.each(variants)('%s creates a Zone the CRD accepts as sent, with no field pruned', async (_label, body) => {
    await createZone(createZoneBodySchema.parse(body), actor)
    expect(sent).toHaveLength(1)
    expect(crViolations(sent[0])).toEqual([])
  })

  it('the checker catches a field the schema does not declare', () => {
    const bad = { apiVersion: 'auth.w6d.io/v1alpha1', kind: 'Zone', metadata: { name: 'x' }, spec: { domain: 'x.stairfleet.com', cookieDomain: '.stairfleet.com' } } as unknown as ZoneCr
    expect(crViolations(bad)).toContain('Zone.spec.cookieDomain: not in the CRD schema (the API server would prune it)')
  })
})

describe('zone names', () => {
  it('flattens the domain, and hashes a long one down to 50 characters', () => {
    expect(zoneNameFor('apps.stairfleet.com')).toBe('apps-stairfleet-com')
    const long = zoneNameFor('a-rather-long-team-name.and-a-long-project.dev.stairling.com')
    expect(long.length).toBeLessThanOrEqual(50)
    expect(long).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/)
  })
})
