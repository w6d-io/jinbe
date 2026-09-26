import * as k8s from '@kubernetes/client-node'
import { sitesConfig } from './config.js'
import type { SiteCr } from './render.js'

/**
 * The only Kubernetes surface jinbe touches for Sites: `sites.auth.w6d.io` in one namespace, and the
 * cluster-scoped `zones.auth.w6d.io` (list/get/create/delete — never update: a domain is immutable),
 * and a read-only list of every Ingress (host collisions).
 *
 * jinbe never writes a Rule, Ingress or Certificate — the site-operator renders those from the Site
 * CR through fixed templates (SERVICE_PLUG.md). Anything that is not a clean answer from the API
 * server is `KubeUnavailable` (503), and callers write nothing after it.
 */

export const SITE_GROUP = 'auth.w6d.io'
export const SITE_VERSION = 'v1alpha1'
export const SITE_PLURAL = 'sites'

/** A metav1.Condition as the operator writes it on Site.status.conditions. */
export interface SiteCondition {
  type: string
  status: string
  reason?: string
  message?: string
  observedGeneration?: number
  lastTransitionTime?: string
}

export interface SiteCrObject extends SiteCr {
  metadata: SiteCr['metadata'] & { resourceVersion?: string; generation?: number }
  /** site-operator api/v1alpha1 SiteStatus. */
  status?: { observedGeneration?: number; conditions?: SiteCondition[]; children?: Array<{ kind: string; name: string; specHash: string }> }
}

export type ZoneTlsMode = 'default' | 'secret' | 'issuer'
/** wildcard: one `*.<domain>` Ingress; per-site: one exact-host Ingress per Site (a shared domain). */
export type ZoneIngressMode = 'wildcard' | 'per-site'

/** A cluster-scoped Zone (zones.auth.w6d.io): an admin-defined wildcard domain. */
export interface ZoneCrObject {
  metadata: { name: string; generation?: number; creationTimestamp?: string; resourceVersion?: string }
  spec: { domain: string; ingress?: ZoneIngressMode; ingressClass?: string; tls?: { mode?: ZoneTlsMode; secretName?: string; issuer?: string } }
  /** site-operator api/v1alpha1 ZoneStatus. */
  status?: { observedGeneration?: number; conditions?: SiteCondition[] }
}

/** The Zone jinbe creates: spec only, the operator writes the status. */
export interface ZoneCr {
  apiVersion: 'auth.w6d.io/v1alpha1'
  kind: 'Zone'
  metadata: { name: string; labels?: Record<string, string> }
  spec: ZoneCrObject['spec']
}

/** An Ingress anywhere in the cluster, reduced to what a host collision needs. */
export interface IngressHosts {
  namespace: string
  name: string
  /** Rule hosts as written: `beta.dev.stairling.com`, `*.dev.stairling.com`. */
  hosts: string[]
  /** The paths each rule host routes (`/collect`), for saying what a shadowed wildcard stops serving. */
  paths: Record<string, string[]>
  labels: Record<string, string>
}

export interface KubeSites {
  /** Every Ingress of the cluster (read-only), for host collisions. */
  listIngresses(): Promise<IngressHosts[]>
  /** Every Zone CR (cluster-scoped). */
  listZones(): Promise<ZoneCrObject[]>
  getZone(name: string): Promise<ZoneCrObject | null>
  /** Create only: an existing Zone is 409, never replaced (its domain is immutable). */
  createZone(cr: ZoneCr): Promise<void>
  /** Idempotent: an absent Zone is not an error. */
  deleteZone(name: string): Promise<void>
  /** Proves the API server answers and the Site CRD is reachable with our RBAC. */
  ping(): Promise<void>
  get(name: string): Promise<SiteCrObject | null>
  /** Create or replace. */
  apply(cr: SiteCr): Promise<void>
  /** Idempotent: an absent Site is not an error. */
  delete(name: string): Promise<void>
}

export class KubeUnavailable extends Error {
  readonly statusCode = 503
  readonly code = 'kubernetes_unavailable'
  constructor(detail: string) {
    super(`The Kubernetes API is unavailable, nothing was changed (${detail})`)
  }
}

/** The API server refused the object itself (conflict, schema, CEL, admission): not an outage. */
export class KubeRefused extends Error {
  constructor(readonly statusCode: 409 | 422, readonly code: string, message: string) {
    super(message)
  }
}

const statusOf = (err: unknown): number | undefined => {
  const e = err as { code?: number; statusCode?: number; response?: { statusCode?: number } }
  return e?.code ?? e?.statusCode ?? e?.response?.statusCode
}

/** The `message` of a Kubernetes Status body, bounded. */
function apiMessage(err: unknown): string {
  const e = err as { body?: unknown; message?: string }
  try {
    const body = typeof e?.body === 'string' ? JSON.parse(e.body) : e?.body
    if (body && typeof (body as { message?: unknown }).message === 'string') return (body as { message: string }).message.slice(0, 500)
  } catch {
    // not JSON
  }
  return (e?.message ?? 'refused').slice(0, 500)
}

class ClientNodeKubeSites implements KubeSites {
  constructor(private readonly api: k8s.CustomObjectsApi, private readonly net: k8s.NetworkingV1Api, private readonly namespace: string) {}

  async listIngresses(): Promise<IngressHosts[]> {
    const out = await this.call('list ingresses', () => this.net.listIngressForAllNamespaces({}))
    return (out.items ?? []).map((i) => ({
      namespace: i.metadata?.namespace ?? '',
      name: i.metadata?.name ?? '',
      hosts: (i.spec?.rules ?? []).map((r) => r.host).filter((h): h is string => !!h),
      paths: Object.fromEntries((i.spec?.rules ?? []).filter((r) => r.host).map((r) => [r.host!, (r.http?.paths ?? []).map((p) => p.path ?? '/')])),
      labels: i.metadata?.labels ?? {},
    }))
  }

  private base() {
    return { group: SITE_GROUP, version: SITE_VERSION, namespace: this.namespace, plural: SITE_PLURAL }
  }

  private async call<T>(what: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (err) {
      throw new KubeUnavailable(`${what}: ${statusOf(err) ?? (err instanceof Error ? err.message : 'error')}`)
    }
  }

  async ping(): Promise<void> {
    await this.call('list sites', () => this.api.listNamespacedCustomObject({ ...this.base(), limit: 1 }))
  }

  async listZones(): Promise<ZoneCrObject[]> {
    const out = await this.call('list zones', () => this.api.listClusterCustomObject({ group: SITE_GROUP, version: SITE_VERSION, plural: 'zones' }))
    return ((out as { items?: ZoneCrObject[] }).items ?? []).filter((z) => typeof z?.spec?.domain === 'string')
  }

  private zones() {
    return { group: SITE_GROUP, version: SITE_VERSION, plural: 'zones' }
  }

  async getZone(name: string): Promise<ZoneCrObject | null> {
    try {
      return (await this.api.getClusterCustomObject({ ...this.zones(), name })) as ZoneCrObject
    } catch (err) {
      if (statusOf(err) === 404) return null
      throw new KubeUnavailable(`get zone: ${statusOf(err) ?? 'error'}`)
    }
  }

  async createZone(cr: ZoneCr): Promise<void> {
    try {
      await this.api.createClusterCustomObject({ ...this.zones(), body: cr })
    } catch (err) {
      const status = statusOf(err)
      if (status === 409) throw new KubeRefused(409, 'zone_exists', `A Zone named ${cr.metadata.name} already exists`)
      // Schema, CEL or admission refusal: the API server's own words say which rule.
      if (status === 400 || status === 422) throw new KubeRefused(422, 'zone_rejected', `The cluster refused the Zone: ${apiMessage(err)}`)
      throw new KubeUnavailable(`create zone: ${status ?? 'error'}`)
    }
  }

  async deleteZone(name: string): Promise<void> {
    try {
      await this.api.deleteClusterCustomObject({ ...this.zones(), name })
    } catch (err) {
      if (statusOf(err) === 404) return
      throw new KubeUnavailable(`delete zone: ${statusOf(err) ?? 'error'}`)
    }
  }

  async get(name: string): Promise<SiteCrObject | null> {
    try {
      return (await this.api.getNamespacedCustomObject({ ...this.base(), name })) as SiteCrObject
    } catch (err) {
      if (statusOf(err) === 404) return null
      throw new KubeUnavailable(`get site: ${statusOf(err) ?? 'error'}`)
    }
  }

  async apply(cr: SiteCr): Promise<void> {
    const existing = await this.get(cr.metadata.name)
    if (!existing) {
      await this.call('create site', () => this.api.createNamespacedCustomObject({ ...this.base(), body: cr }))
      return
    }
    const body = { ...cr, metadata: { ...cr.metadata, resourceVersion: existing.metadata.resourceVersion } }
    await this.call('replace site', () => this.api.replaceNamespacedCustomObject({ ...this.base(), name: cr.metadata.name, body }))
  }

  async delete(name: string): Promise<void> {
    try {
      await this.api.deleteNamespacedCustomObject({ ...this.base(), name })
    } catch (err) {
      if (statusOf(err) === 404) return
      throw new KubeUnavailable(`delete site: ${statusOf(err) ?? 'error'}`)
    }
  }
}

class OffKubeSites implements KubeSites {
  private refuse(): never {
    throw new KubeUnavailable('SITES_KUBE is off')
  }
  async ping(): Promise<void> { this.refuse() }
  async listZones(): Promise<ZoneCrObject[]> { this.refuse() }
  async listIngresses(): Promise<IngressHosts[]> { this.refuse() }
  async getZone(): Promise<ZoneCrObject | null> { this.refuse() }
  async createZone(): Promise<void> { this.refuse() }
  async deleteZone(): Promise<void> { this.refuse() }
  async get(): Promise<SiteCrObject | null> { this.refuse() }
  async apply(): Promise<void> { this.refuse() }
  async delete(): Promise<void> { this.refuse() }
}

let instance: KubeSites | null = null

export function kubeSites(): KubeSites {
  if (instance) return instance
  const cfg = sitesConfig()
  if (cfg.SITES_KUBE === 'off') {
    instance = new OffKubeSites()
  } else {
    const kc = new k8s.KubeConfig()
    if (cfg.SITES_KUBE === 'in-cluster') kc.loadFromCluster()
    else kc.loadFromDefault()
    instance = new ClientNodeKubeSites(kc.makeApiClient(k8s.CustomObjectsApi), kc.makeApiClient(k8s.NetworkingV1Api), cfg.namespace)
  }
  return instance
}

/** Test seam. */
export function setKubeSites(k: KubeSites | null): void {
  instance = k
}
