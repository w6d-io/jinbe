import * as k8s from '@kubernetes/client-node'
import { sitesConfig } from './config.js'
import type { SiteCr } from './render.js'

/**
 * The only Kubernetes surface jinbe touches for Sites: `sites.auth.w6d.io` in one namespace, and the
 * cluster-scoped `zones.auth.w6d.io` (list/get/create/delete, and update of the exposure — never the
 * domain, which the CRD keeps immutable), and read-only lists of every Ingress, and — when
 * SITES_GATEWAYS names Gateways — every HTTPRoute and ListenerSet (host collisions), those
 * Gateways and the Envoy Gateway policies in their namespace (discovery).
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
/**
 * wildcard: one `*.<domain>` Ingress; per-site: one exact-host Ingress per Site (a shared domain);
 * none: no Ingress, the zone's Gateway alone serves it.
 */
export type ZoneIngressMode = 'wildcard' | 'per-site' | 'none'

/** The Gateway API Gateway a zone's hosts are attached to (one HTTPRoute per host, behind its WAF). */
export interface ZoneGatewayRef { namespace: string; name: string; sectionName?: string }

/** A cluster-scoped Zone (zones.auth.w6d.io): an admin-defined wildcard domain. */
export interface ZoneCrObject {
  metadata: { name: string; generation?: number; creationTimestamp?: string; resourceVersion?: string; labels?: Record<string, string> }
  spec: {
    domain: string
    ingress?: ZoneIngressMode
    ingressClass?: string
    tls?: { mode?: ZoneTlsMode; secretName?: string; issuer?: string }
    gateway?: ZoneGatewayRef
  }
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
  /** Rule hosts as written: `beta.dev.example.com`, `*.dev.example.com`. */
  hosts: string[]
  /** The paths each rule host routes (`/collect`), for saying what a shadowed wildcard stops serving. */
  paths: Record<string, string[]>
  labels: Record<string, string>
  /** `auth.w6d.io/host` names the one host of an operator's shared `host-<hash8>` Ingress. */
  annotations?: Record<string, string>
}

/** An HTTPRoute anywhere in the cluster, reduced to what a host collision needs. */
export interface RouteHosts {
  namespace: string
  name: string
  hostnames: string[]
  labels: Record<string, string>
  annotations?: Record<string, string>
}

/** The listeners of a Gateway or of a ListenerSet attached to one (`gateway`: namespace/name). */
export interface ListenerHosts {
  kind: 'Gateway' | 'ListenerSet'
  namespace: string
  name: string
  gateway: string
  listeners: Array<{ name: string; hostname?: string; port?: number; protocol?: string }>
}

/** A Gateway as discovery reads it (gateway.networking.k8s.io/v1). */
export interface GatewayObject {
  metadata: { name: string; namespace: string }
  spec: {
    gatewayClassName?: string
    listeners?: Array<{ name: string; hostname?: string; port?: number; protocol?: string; tls?: { certificateRefs?: Array<{ name: string }> }; allowedRoutes?: { namespaces?: { from?: string } } }>
  }
  status?: {
    addresses?: Array<{ type?: string; value: string }>
    conditions?: SiteCondition[]
    listeners?: Array<{ name: string; attachedRoutes?: number; conditions?: SiteCondition[] }>
  }
}

/**
 * An Envoy Gateway SecurityPolicy or EnvoyExtensionPolicy, reduced to what the protection report
 * needs: its targets, which features it sets, the modules it loads, and whether EG accepted it.
 */
export interface EdgePolicy {
  kind: 'SecurityPolicy' | 'EnvoyExtensionPolicy'
  namespace: string
  name: string
  targets: Array<{ kind: string; name: string; sectionName?: string }>
  /** Top-level spec keys: extAuth, authorization, cors, dynamicModule, wasm… */
  features: string[]
  /** EnvoyExtensionPolicy: module and filter names (e.g. composer, coraza-waf). */
  modules: string[]
  /** SecurityPolicy extAuth: failOpen, and the backend it calls (namespace/name). */
  extAuth?: { failOpen: boolean; backend: string | null }
  /** Accepted on some ancestor (null: EG has not reported). */
  accepted: boolean | null
}

export interface KubeSites {
  /** Every Ingress of the cluster (read-only), for host collisions. */
  listIngresses(): Promise<IngressHosts[]>
  /** Every HTTPRoute of the cluster (read-only), for host collisions. Optional: absent = not read. */
  listHTTPRoutes?(): Promise<RouteHosts[]>
  /** Every ListenerSet of the cluster (read-only), for exact-hostname listeners. */
  listListenerSets?(): Promise<ListenerHosts[]>
  /** One Gateway, or null when it does not exist. */
  getGateway?(namespace: string, name: string): Promise<GatewayObject | null>
  /** The SecurityPolicies and EnvoyExtensionPolicies of a namespace (a Gateway's). */
  listEdgePolicies?(namespace: string): Promise<EdgePolicy[]>
  /** Replace a Zone's spec (the exposure), optimistic on resourceVersion: a concurrent change is 409. */
  updateZone?(cr: ZoneCrObject): Promise<void>
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
  /**
   * Every Site CR of the namespace in ONE list (the RBAC already grants `list`), for the Home's
   * conditions view. Optional so a partial fake still satisfies the interface; absent reads as unknown.
   */
  list?(): Promise<SiteCrObject[]>
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

export const GATEWAY_GROUP = 'gateway.networking.k8s.io'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Raw = any
const items = (out: unknown): Raw[] => ((out as { items?: Raw[] })?.items ?? []).filter((x) => x && typeof x === 'object')

/** An EG policy as the protection report reads it. */
export function edgePolicyOf(kind: EdgePolicy['kind'], p: Raw): EdgePolicy {
  const spec = p?.spec ?? {}
  const targets = [...(spec.targetRefs ?? []), ...(spec.targetRef ? [spec.targetRef] : [])]
    .map((t: Raw) => ({ kind: String(t?.kind ?? ''), name: String(t?.name ?? ''), ...(t?.sectionName ? { sectionName: String(t.sectionName) } : {}) }))
  const modules = [...(spec.dynamicModule ?? []), ...(spec.wasm ?? [])]
    .flatMap((m: Raw) => [m?.name, m?.filterName]).filter((x: unknown): x is string => typeof x === 'string' && x !== '')
  const conds: Raw[] = (p?.status?.ancestors ?? []).flatMap((a: Raw) => a?.conditions ?? [])
  const acc = conds.filter((c) => c?.type === 'Accepted')
  const backend = spec.extAuth?.grpc?.backendRefs?.[0] ?? spec.extAuth?.http?.backendRefs?.[0] ?? spec.extAuth?.grpc?.backendRef ?? spec.extAuth?.http?.backendRef
  return {
    kind,
    namespace: p?.metadata?.namespace ?? '',
    name: p?.metadata?.name ?? '',
    targets,
    features: Object.keys(spec).filter((k) => !['targetRef', 'targetRefs', 'targetSelectors', 'mergeType'].includes(k)).sort(),
    modules,
    ...(spec.extAuth ? { extAuth: { failOpen: spec.extAuth.failOpen === true, backend: backend?.name ? `${backend.namespace ?? p?.metadata?.namespace ?? ''}/${backend.name}` : null } } : {}),
    accepted: acc.length === 0 ? null : acc.some((c) => c.status === 'True'),
  }
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
      annotations: i.metadata?.annotations ?? {},
    }))
  }

  async listHTTPRoutes(): Promise<RouteHosts[]> {
    const out = await this.call('list httproutes', () => this.api.listClusterCustomObject({ group: GATEWAY_GROUP, version: 'v1', plural: 'httproutes' }))
    return items(out).map((r) => ({
      namespace: r.metadata?.namespace ?? '',
      name: r.metadata?.name ?? '',
      hostnames: (r.spec?.hostnames ?? []).filter((h: unknown): h is string => typeof h === 'string'),
      labels: r.metadata?.labels ?? {},
      annotations: r.metadata?.annotations ?? {},
    }))
  }

  async listListenerSets(): Promise<ListenerHosts[]> {
    const out = await this.call('list listenersets', () => this.api.listClusterCustomObject({ group: GATEWAY_GROUP, version: 'v1', plural: 'listenersets' }))
    return items(out).map((l) => ({
      kind: 'ListenerSet' as const,
      namespace: l.metadata?.namespace ?? '',
      name: l.metadata?.name ?? '',
      gateway: `${l.spec?.parentRef?.namespace ?? l.metadata?.namespace ?? ''}/${l.spec?.parentRef?.name ?? ''}`,
      listeners: (l.spec?.listeners ?? []).map((x: { name: string; hostname?: string; port?: number; protocol?: string }) => ({ name: x.name, hostname: x.hostname, port: x.port, protocol: x.protocol })),
    }))
  }

  async getGateway(namespace: string, name: string): Promise<GatewayObject | null> {
    try {
      return (await this.api.getNamespacedCustomObject({ group: GATEWAY_GROUP, version: 'v1', namespace, plural: 'gateways', name })) as GatewayObject
    } catch (err) {
      if (statusOf(err) === 404) return null
      throw new KubeUnavailable(`get gateway: ${statusOf(err) ?? 'error'}`)
    }
  }

  async listEdgePolicies(namespace: string): Promise<EdgePolicy[]> {
    const read = async (plural: string, kind: EdgePolicy['kind']) => {
      const out = await this.call(`list ${plural}`, () => this.api.listNamespacedCustomObject({ group: 'gateway.envoyproxy.io', version: 'v1alpha1', namespace, plural }))
      return items(out).map((p) => edgePolicyOf(kind, p))
    }
    return [...(await read('securitypolicies', 'SecurityPolicy')), ...(await read('envoyextensionpolicies', 'EnvoyExtensionPolicy'))]
  }

  async updateZone(cr: ZoneCrObject): Promise<void> {
    const body = { apiVersion: `${SITE_GROUP}/${SITE_VERSION}`, kind: 'Zone', metadata: { name: cr.metadata.name, resourceVersion: cr.metadata.resourceVersion, labels: cr.metadata.labels }, spec: cr.spec }
    try {
      await this.api.replaceClusterCustomObject({ ...this.zones(), name: cr.metadata.name, body })
    } catch (err) {
      const status = statusOf(err)
      if (status === 409) throw new KubeRefused(409, 'zone_conflict', `Zone ${cr.metadata.name} changed meanwhile; reload and try again`)
      if (status === 400 || status === 422) throw new KubeRefused(422, 'zone_rejected', `The cluster refused the Zone: ${apiMessage(err)}`)
      if (status === 404) throw new KubeRefused(409, 'zone_gone', `Zone ${cr.metadata.name} no longer exists`)
      throw new KubeUnavailable(`update zone: ${status ?? 'error'}`)
    }
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

  async list(): Promise<SiteCrObject[]> {
    const out = await this.call('list sites', () => this.api.listNamespacedCustomObject(this.base()))
    return ((out as { items?: SiteCrObject[] }).items ?? []).filter((s) => typeof s?.metadata?.name === 'string')
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
  async list(): Promise<SiteCrObject[]> { this.refuse() }
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
