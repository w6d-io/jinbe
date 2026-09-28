import { sitesConfig } from './config.js'
import { kubeSites, type EdgePolicy, type GatewayObject, type SiteCondition } from './kube-sites.js'
import { siteError } from './checks.js'

/**
 * Gateway discovery for zones (`GET /sites/gateways`): the Gateway API Gateways a zone may be
 * attached to (SITES_GATEWAYS, the operator's --gateways), their listeners and addresses, and
 * whether their Gateway-level policies put every route behind the WAF and the IP reputation check.
 *
 * "Protected" is read from the cluster, never assumed from the allow-list: an EnvoyExtensionPolicy
 * loading a WAF module (Coraza) and a SecurityPolicy with extAuth (the CrowdSec bouncer), both
 * targeting the whole Gateway and accepted by Envoy Gateway. Every listener and ListenerSet of that
 * Gateway inherits them; a route-level policy that could replace them is refused by the operator's
 * admission policy (site-operator-route-policies) in the gateway namespace.
 */

export interface ListenerView {
  name: string
  hostname: string | null
  port: number | null
  protocol: string | null
  /** HTTPS listener serving its own certificate. */
  tls: boolean
  /** Routes from any namespace may attach (the operator's routes live in the site namespace). */
  routesFromAll: boolean
  programmed: boolean | null
  attachedRoutes: number | null
}

export interface Protection {
  waf: { policy: string | null; modules: string[]; accepted: boolean }
  ipReputation: { policy: string | null; backend: string | null; failOpen: boolean | null; accepted: boolean }
  denylist: { policy: string | null }
  /** WAF and IP reputation both in force on the whole Gateway. */
  protected: boolean
  summary: string
}

export interface GatewayView {
  key: string
  namespace: string
  name: string
  exists: boolean
  className: string | null
  addresses: string[]
  programmed: boolean
  message: string
  listeners: ListenerView[]
  protection: Protection
}

const WAF_MODULE = /coraza|waf|modsec/i

const condition = (list: SiteCondition[] | undefined, type: string) => list?.find((c) => c.type === type)

const targetsGateway = (p: EdgePolicy, name: string) => p.targets.some((t) => t.kind === 'Gateway' && t.name === name && !t.sectionName)

/** What the Gateway-level policies of `name` enforce on every route. */
export function protectionOf(name: string, policies: readonly EdgePolicy[]): Protection {
  const gatewayLevel = policies.filter((p) => targetsGateway(p, name))
  const waf = gatewayLevel.find((p) => p.kind === 'EnvoyExtensionPolicy' && p.modules.some((m) => WAF_MODULE.test(m)))
  const ext = gatewayLevel.find((p) => p.kind === 'SecurityPolicy' && p.extAuth)
  const deny = gatewayLevel.find((p) => p.kind === 'SecurityPolicy' && p.features.includes('authorization'))
  const wafOn = !!waf && waf.accepted === true
  const extOn = !!ext && ext.accepted === true
  const missing = [...(wafOn ? [] : [waf ? `WAF policy ${waf.name} not accepted` : 'no WAF policy']), ...(extOn ? [] : [ext ? `IP reputation policy ${ext.name} not accepted` : 'no IP reputation (ext_authz) policy'])]
  return {
    waf: { policy: waf ? `${waf.namespace}/${waf.name}` : null, modules: waf?.modules ?? [], accepted: wafOn },
    ipReputation: { policy: ext ? `${ext.namespace}/${ext.name}` : null, backend: ext?.extAuth?.backend ?? null, failOpen: ext?.extAuth?.failOpen ?? null, accepted: extOn },
    denylist: { policy: deny ? `${deny.namespace}/${deny.name}` : null },
    protected: wafOn && extOn,
    summary: wafOn && extOn
      ? `Every route is inspected by the WAF (${waf!.modules.join(', ')}) and checked against IP bans (${ext!.extAuth?.backend ?? 'ext_authz'}${ext!.extAuth?.failOpen ? ', fail-open' : ''})`
      : `Not protected: ${missing.join('; ')}`,
  }
}

function view(key: string, gw: GatewayObject | null, policies: readonly EdgePolicy[]): GatewayView {
  const [namespace, name] = key.split('/')
  if (!gw) {
    return { key, namespace, name, exists: false, className: null, addresses: [], programmed: false, message: `Gateway ${key} does not exist`, listeners: [], protection: protectionOf(name, []) }
  }
  const programmed = condition(gw.status?.conditions, 'Programmed')
  const listeners = (gw.spec.listeners ?? []).map((l): ListenerView => {
    const st = gw.status?.listeners?.find((x) => x.name === l.name)
    const p = condition(st?.conditions, 'Programmed')
    return {
      name: l.name,
      hostname: l.hostname ?? null,
      port: l.port ?? null,
      protocol: l.protocol ?? null,
      tls: l.protocol === 'HTTPS' && (l.tls?.certificateRefs?.length ?? 0) > 0,
      routesFromAll: l.allowedRoutes?.namespaces?.from === 'All',
      programmed: p ? p.status === 'True' : null,
      attachedRoutes: st?.attachedRoutes ?? null,
    }
  })
  return {
    key, namespace, name, exists: true,
    className: gw.spec.gatewayClassName ?? null,
    addresses: (gw.status?.addresses ?? []).map((a) => a.value).filter(Boolean),
    programmed: programmed?.status === 'True',
    message: programmed?.message ?? (programmed ? '' : 'not programmed yet'),
    listeners,
    protection: protectionOf(name, policies),
  }
}

/** One allowed Gateway as discovery sees it; 422 when it is not in SITES_GATEWAYS. */
export async function gatewayView(key: string): Promise<GatewayView> {
  if (!sitesConfig().SITES_GATEWAYS.includes(key)) throw siteError(422, 'gateway_not_allowed', `Gateway ${key} is not one zones may use (${sitesConfig().SITES_GATEWAYS.join(', ') || 'none configured'})`)
  const kube = kubeSites()
  const [namespace, name] = key.split('/')
  const gw = kube.getGateway ? await kube.getGateway(namespace, name) : null
  const policies = gw && kube.listEdgePolicies ? await kube.listEdgePolicies(namespace) : []
  return view(key, gw, policies)
}

/** Every allowed Gateway (SITES_GATEWAYS order). Empty when none is configured. */
export async function listGateways(): Promise<{ gateways: GatewayView[] }> {
  if (sitesConfig().SITES_KUBE === 'off') return { gateways: [] }
  return { gateways: await Promise.all(sitesConfig().SITES_GATEWAYS.map((k) => gatewayView(k))) }
}

/**
 * The HTTPS listener serving `*.<domain>` with its own certificate — what a zone with TLS `default`
 * needs (the operator's coveringListener: exactly `*.<domain>`, since a TLS wildcard covers one label).
 */
export function coveringListener(gw: GatewayView, domain: string, sectionName?: string): ListenerView | null {
  return gw.listeners.find((l) => (!sectionName || l.name === sectionName) && l.protocol === 'HTTPS' && l.hostname === `*.${domain}`) ?? null
}
