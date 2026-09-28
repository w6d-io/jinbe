import { coveringListener, type GatewayView } from './gateways.service.js'

/**
 * Is a zone — and so every site under it — behind the WAF? (owner decision 2026-09-28: zones default
 * to a WAF-protected Gateway, the nginx Ingress is the fallback, and the state is shown everywhere.)
 *
 * `waf` needs the zone attached to an allowed Gateway whose WAF policy is in force AND no Ingress
 * left: while one answers, anyone reaches the hosts around the WAF. Everything else is `none`, with
 * the reason and the policy names so the console can say what to fix.
 */

export type ProtectionState = 'waf' | 'none'
export type ProtectionReason = 'gateway' | 'no_gateway' | 'ingress_bypass' | 'gateway_not_protected' | 'gateway_unknown' | 'no_zone'

export interface ProtectionStatus {
  state: ProtectionState
  reason: ProtectionReason
  /** namespace/name of the zone's Gateway, if any. */
  gateway: string | null
  /** namespace/name of the WAF (Coraza) policy in force, if any. */
  waf: string | null
  /** namespace/name of the IP reputation (CrowdSec ext_authz) policy in force, if any. */
  ipReputation: string | null
  message: string
}

export interface ZoneExposure { ingress?: 'wildcard' | 'per-site' | 'none'; gateway?: string }

export function protectionFor(zone: ZoneExposure | null | undefined, gateways: readonly GatewayView[]): ProtectionStatus {
  const none = (reason: ProtectionReason, message: string, gw: GatewayView | null = null): ProtectionStatus => ({
    state: 'none', reason, gateway: gw?.key ?? zone?.gateway ?? null,
    waf: gw?.protection.waf.accepted ? gw.protection.waf.policy : null,
    ipReputation: gw?.protection.ipReputation.accepted ? gw.protection.ipReputation.policy : null,
    message,
  })
  if (!zone) return none('no_zone', 'No zone serves this host')
  if (!zone.gateway) return none('no_gateway', 'Served by the nginx Ingress: no WAF, no IP bans')
  const gw = gateways.find((g) => g.key === zone.gateway)
  if (!gw) return none('gateway_unknown', `Gateway ${zone.gateway} could not be inspected here`)
  if (!gw.protection.protected) return none('gateway_not_protected', `Gateway ${gw.key}: ${gw.protection.summary}`, gw)
  if ((zone.ingress ?? 'wildcard') !== 'none') return none('ingress_bypass', `Gateway ${gw.key} has the WAF, but the nginx Ingress still answers: the WAF can be bypassed until the Ingress is dropped`, gw)
  return {
    state: 'waf', reason: 'gateway', gateway: gw.key,
    waf: gw.protection.waf.policy,
    ipReputation: gw.protection.ipReputation.accepted ? gw.protection.ipReputation.policy : null,
    message: gw.protection.summary,
  }
}

/**
 * The Gateway a new zone gets by default: the first allowed Gateway with the WAF in force that can
 * serve `*.<domain>` — a listener for exactly it (TLS default), or any (TLS issuer/secret brings the
 * zone's own ListenerSet). Null = no WAF-protected Gateway here: the zone falls back to the Ingress.
 */
export function defaultGateway(gateways: readonly GatewayView[], domain: string, tlsMode: string): GatewayView | null {
  return gateways.find((g) => g.exists && g.protection.protected && (tlsMode !== 'default' || !!coveringListener(g, domain))) ?? null
}

/** Any allowed Gateway with the WAF in force (the opt-out question is asked whenever one exists). */
export function anyProtected(gateways: readonly GatewayView[]): GatewayView | null {
  return gateways.find((g) => g.exists && g.protection.protected) ?? null
}
