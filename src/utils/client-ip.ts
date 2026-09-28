import type { FastifyRequest } from 'fastify'
import { env } from '../config/index.js'

/**
 * Who is calling, as far as the proxies in front of jinbe can vouch for it.
 *
 * X-Forwarded-For is a list the client starts: every entry left of the ones a trusted proxy wrote is
 * the client's to invent. Fastify's `trustProxy: true` answered with the leftmost entry, so audit
 * trails and per-IP limits read an address the caller chose. Trusting the first n hops instead walks
 * back from the socket peer (proxy-addr): with n = 1 the socket peer is trusted and the last
 * X-Forwarded-For entry is the answer. (A bare number is no use: Fastify >= 5.12 treats
 * `trustProxy: <n>` as trusting nothing, since a hop count cannot tell a proxy from a pod calling
 * jinbe directly — which is why jinbe's ingress belongs to Oathkeeper alone.)
 *
 * Measured on the stack (Oathkeeper v25.4.0, `serve.proxy.trust_forwarded_headers: true`): Oathkeeper
 * forwards X-Forwarded-For exactly as it received it and appends nothing, and Envoy (or ingress-nginx)
 * appends the address it accepted the connection from. So Envoy -> Oathkeeper -> jinbe is one trusted
 * hop (Oathkeeper, the socket peer) and the client is the last entry: TRUSTED_PROXY_HOPS=1.
 */
export function trustProxySetting(hops: number = env.TRUSTED_PROXY_HOPS): ((address: string, hop: number) => boolean) | false {
  return hops > 0 ? (_address, hop) => hop < hops : false
}

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[v.length - 1] : v)

/**
 * The client address for audit and rate limits: Envoy's x-envoy-external-address when this
 * deployment trusts it (TRUST_ENVOY_EXTERNAL_ADDRESS — Envoy overwrites it on every external request,
 * but a client reaching Oathkeeper another way writes it freely), else request.ip under the hop count.
 */
export function clientIp(
  request: Pick<FastifyRequest, 'headers' | 'ip'>,
  trustEnvoy: boolean = env.TRUST_ENVOY_EXTERNAL_ADDRESS,
): string {
  if (trustEnvoy) {
    const edge = one(request.headers?.['x-envoy-external-address'])?.trim()
    if (edge) return edge
  }
  return request.ip
}
