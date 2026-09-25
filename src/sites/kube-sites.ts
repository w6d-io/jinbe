import * as k8s from '@kubernetes/client-node'
import { sitesConfig } from './config.js'
import type { SiteCr } from './render.js'

/**
 * The only Kubernetes surface jinbe touches for Sites: `sites.auth.w6d.io` in one namespace.
 *
 * jinbe never writes a Rule, Ingress or Certificate — the site-operator renders those from the Site
 * CR through fixed templates (SERVICE_PLUG.md). Anything that is not a clean answer from the API
 * server is `KubeUnavailable` (503), and callers write nothing after it.
 */

export const SITE_GROUP = 'auth.w6d.io'
export const SITE_VERSION = 'v1alpha1'
export const SITE_PLURAL = 'sites'

export interface SiteCrObject extends SiteCr {
  metadata: SiteCr['metadata'] & { resourceVersion?: string; generation?: number }
  status?: { observedGeneration?: number; conditions?: Array<{ type: string; status: string; reason?: string; message?: string }> }
}

/** A cluster-scoped Zone (zones.auth.w6d.io): an admin-defined wildcard domain. */
export interface ZoneCrObject {
  metadata: { name: string }
  spec: { domain: string; ingressClass?: string; tls?: { mode?: 'default' | 'secret' | 'issuer'; secretName?: string; issuer?: string } }
}

export interface KubeSites {
  /** Every Zone CR (cluster-scoped, read-only for jinbe). */
  listZones(): Promise<ZoneCrObject[]>
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

const statusOf = (err: unknown): number | undefined => {
  const e = err as { code?: number; statusCode?: number; response?: { statusCode?: number } }
  return e?.code ?? e?.statusCode ?? e?.response?.statusCode
}

class ClientNodeKubeSites implements KubeSites {
  constructor(private readonly api: k8s.CustomObjectsApi, private readonly namespace: string) {}

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
    instance = new ClientNodeKubeSites(kc.makeApiClient(k8s.CustomObjectsApi), cfg.namespace)
  }
  return instance
}

/** Test seam. */
export function setKubeSites(k: KubeSites | null): void {
  instance = k
}
