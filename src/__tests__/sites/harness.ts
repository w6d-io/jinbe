import type { SiteCrObject } from '../../sites/kube-sites.js'
import type { SiteCr } from '../../sites/render.js'

/** A fake cluster holding Site CRs the way the API server does: generation bumps on spec change. */
export function fakeCluster() {
  const crs = new Map<string, SiteCrObject>()
  const kube = {
    ping: async () => {},
    listZones: async () => [],
    get: async (name: string) => (crs.has(name) ? structuredClone(crs.get(name)!) : null),
    apply: async (cr: SiteCr) => {
      const old = crs.get(cr.metadata.name)
      const generation = (old?.metadata.generation ?? 0) + 1
      crs.set(cr.metadata.name, { ...structuredClone(cr), metadata: { ...structuredClone(cr.metadata), generation }, ...(old?.status ? { status: old.status } : {}) })
      kube.applied.push(structuredClone(cr))
    },
    delete: async (name: string) => {
      crs.delete(name)
      kube.deleted.push(name)
    },
    applied: [] as SiteCr[],
    deleted: [] as string[],
  }
  /** Set the operator's status on a CR: conditions True unless listed as false (`{RulesLoaded: 'Pending'}`). */
  const operator = (name: string, falses: Record<string, string> = {}, observed?: number) => {
    const cr = crs.get(name)!
    const gen = observed ?? cr.metadata.generation ?? 1
    const types = ['Validated', 'RulesSynced', 'RulesLoaded', 'IngressReady', 'CertificateReady', 'Ready']
    cr.status = {
      observedGeneration: gen,
      conditions: types.map((type) => ({
        type,
        status: falses[type] ? 'False' : 'True',
        reason: falses[type] ?? 'Ok',
        message: falses[type] ? `${type} is ${falses[type]}` : '',
        observedGeneration: gen,
        lastTransitionTime: '2026-09-25T10:00:00Z',
      })),
      children: [{ kind: 'Rule', name: `${name}-web-abc`, specHash: 'h1' }],
    }
  }
  const reset = () => {
    crs.clear()
    kube.applied = []
    kube.deleted = []
  }
  return { crs, kube, operator, reset }
}
