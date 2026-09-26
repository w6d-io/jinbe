import * as k8s from '@kubernetes/client-node'
import { parse as parseYaml } from 'yaml'
import { sitesConfig } from '../sites/config.js'
import { KubeUnavailable, SITE_GROUP, SITE_PLURAL, SITE_VERSION, type SiteCrObject } from '../sites/kube-sites.js'
import type { HandlerKind } from './catalog.js'

/**
 * The Kubernetes surface of the gateway module: the `Gateway` singleton (gateways.auth.w6d.io,
 * named `gateway` in the Sites namespace), the Site CRs (read, for "in use"), and — only while no
 * Gateway exists — the live Oathkeeper ConfigMap, read-only.
 *
 * jinbe writes the Gateway spec and nothing else. The site-operator renders it into Oathkeeper's
 * config and rolls the pods; its progress comes back in `status`.
 */

export const GATEWAY_PLURAL = 'gateways'
export const GATEWAY_NAME = 'gateway'
export const PREVIOUS_SPEC_ANNOTATION = 'auth.w6d.io/previous-spec'

export type SpecKey = 'authenticators' | 'authorizers' | 'mutators' | 'errors'
export const SPEC_KEY: Record<HandlerKind, SpecKey> = {
  authenticator: 'authenticators', authorizer: 'authorizers', mutator: 'mutators', error: 'errors',
}

export interface HandlerSpec { enabled: boolean; config?: Record<string, unknown> }
export type GatewaySpec = Record<SpecKey, Record<string, HandlerSpec>> & { errorFallback: string[] }

export interface Condition { type: string; status: string; reason?: string; message?: string; lastTransitionTime?: string }
export interface Rollout {
  phase?: 'Pending' | 'Progressing' | 'Complete' | 'Failed' | 'RolledBack'
  configHash?: string
  replicas?: number
  updatedReplicas?: number
  readyReplicas?: number
  startedAt?: string
  finishedAt?: string
  message?: string
}

export interface GatewayCr {
  apiVersion: 'auth.w6d.io/v1alpha1'
  kind: 'Gateway'
  metadata: { name: string; namespace: string; resourceVersion?: string; generation?: number; annotations?: Record<string, string>; labels?: Record<string, string> }
  spec: GatewaySpec
  status?: { observedGeneration?: number; conditions?: Condition[]; rollout?: Rollout }
}

export interface KubeGateway {
  get(): Promise<GatewayCr | null>
  /** Create (no resourceVersion) or replace at exactly `resourceVersion`; a stale one throws 409. */
  write(cr: GatewayCr, resourceVersion: string | null): Promise<GatewayCr>
  listSites(): Promise<SiteCrObject[]>
  /** The live Oathkeeper config.yaml, parsed; null when the ConfigMap is absent. */
  liveOathkeeperConfig(): Promise<Record<string, unknown> | null>
}

export class GatewayConflict extends Error {
  readonly statusCode = 412
  readonly code = 'precondition_failed'
  constructor() {
    super('The gateway configuration changed since you read it; reload and retry')
  }
}

const statusOf = (err: unknown): number | undefined => {
  const e = err as { code?: number; statusCode?: number; response?: { statusCode?: number } }
  return e?.code ?? e?.statusCode ?? e?.response?.statusCode
}

const unavailable = (what: string, err: unknown) =>
  new KubeUnavailable(`${what}: ${statusOf(err) ?? (err instanceof Error ? err.message : 'error')}`)

class ClientNodeKubeGateway implements KubeGateway {
  constructor(
    private readonly custom: k8s.CustomObjectsApi,
    private readonly core: k8s.CoreV1Api,
    private readonly namespace: string,
    private readonly configMap: { name: string; key: string },
  ) {}

  private base() {
    return { group: SITE_GROUP, version: SITE_VERSION, namespace: this.namespace, plural: GATEWAY_PLURAL }
  }

  async get(): Promise<GatewayCr | null> {
    try {
      return (await this.custom.getNamespacedCustomObject({ ...this.base(), name: GATEWAY_NAME })) as GatewayCr
    } catch (err) {
      if (statusOf(err) === 404) return null
      throw unavailable('get gateway', err)
    }
  }

  async write(cr: GatewayCr, resourceVersion: string | null): Promise<GatewayCr> {
    try {
      if (resourceVersion === null) {
        return (await this.custom.createNamespacedCustomObject({ ...this.base(), body: cr })) as GatewayCr
      }
      const body = { ...cr, metadata: { ...cr.metadata, resourceVersion } }
      return (await this.custom.replaceNamespacedCustomObject({ ...this.base(), name: GATEWAY_NAME, body })) as GatewayCr
    } catch (err) {
      if (statusOf(err) === 409) throw new GatewayConflict()
      throw unavailable('write gateway', err)
    }
  }

  async listSites(): Promise<SiteCrObject[]> {
    try {
      const out = await this.custom.listNamespacedCustomObject({ group: SITE_GROUP, version: SITE_VERSION, namespace: this.namespace, plural: SITE_PLURAL })
      return (out as { items?: SiteCrObject[] }).items ?? []
    } catch (err) {
      throw unavailable('list sites', err)
    }
  }

  async liveOathkeeperConfig(): Promise<Record<string, unknown> | null> {
    let cm: k8s.V1ConfigMap
    try {
      cm = await this.core.readNamespacedConfigMap({ name: this.configMap.name, namespace: this.namespace })
    } catch (err) {
      if (statusOf(err) === 404) return null
      throw unavailable('read oathkeeper config', err)
    }
    const raw = cm.data?.[this.configMap.key]
    if (!raw) return null
    const doc = parseYaml(raw) as unknown
    return doc && typeof doc === 'object' ? (doc as Record<string, unknown>) : null
  }
}

class OffKubeGateway implements KubeGateway {
  private refuse(): never {
    throw new KubeUnavailable('SITES_KUBE is off')
  }
  async get(): Promise<GatewayCr | null> { this.refuse() }
  async write(): Promise<GatewayCr> { this.refuse() }
  async listSites(): Promise<SiteCrObject[]> { this.refuse() }
  async liveOathkeeperConfig(): Promise<Record<string, unknown> | null> { this.refuse() }
}

let instance: KubeGateway | null = null

export function kubeGateway(): KubeGateway {
  if (instance) return instance
  const cfg = sitesConfig()
  if (cfg.SITES_KUBE === 'off') {
    instance = new OffKubeGateway()
  } else {
    const kc = new k8s.KubeConfig()
    if (cfg.SITES_KUBE === 'in-cluster') kc.loadFromCluster()
    else kc.loadFromDefault()
    instance = new ClientNodeKubeGateway(kc.makeApiClient(k8s.CustomObjectsApi), kc.makeApiClient(k8s.CoreV1Api), cfg.namespace, {
      name: process.env.GATEWAY_OATHKEEPER_CONFIGMAP ?? 'auth-oathkeeper-config',
      key: process.env.GATEWAY_OATHKEEPER_CONFIG_KEY ?? 'config.yaml',
    })
  }
  return instance
}

/** Test seam. */
export function setKubeGateway(k: KubeGateway | null): void {
  instance = k
}
