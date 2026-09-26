import { randomBytes } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { sitesConfig } from './config.js'

/**
 * Does the wildcard DNS of a domain reach the platform ingress? Asked by resolving a random name
 * under it (a wildcard record answers any label), so a cached or hand-made record for one host
 * cannot pass for the wildcard.
 *
 * A report, never a gate: DNS is managed outside the platform, often after the Zone is created, and
 * a resolver inside the cluster may not see the public view. Every failure is an answer, not a throw.
 */

export interface DnsLookup {
  /** IPv4 and IPv6 addresses of a name, CNAMEs followed; [] when it does not resolve. */
  addresses(name: string): Promise<string[]>
}

export type DnsStatus = 'ok' | 'elsewhere' | 'unresolved' | 'unverified'

export interface DnsReport {
  /** The name that was resolved, e.g. `jinbe-probe-1a2b3c4d.apps.stairfleet.com`. */
  probe: string
  status: DnsStatus
  addresses: string[]
  /** The platform ingress, as addresses. [] when it is not known: status is then `unverified`. */
  expected: string[]
  message: string
}

const IP = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:.]*)$/i

class NodeDnsLookup implements DnsLookup {
  async addresses(name: string): Promise<string[]> {
    const resolver = new Resolver({ timeout: sitesConfig().SITES_ZONE_DNS_TIMEOUT_MS, tries: 1 })
    const [v4, v6] = await Promise.all([
      resolver.resolve4(name).catch(() => [] as string[]),
      resolver.resolve6(name).catch(() => [] as string[]),
    ])
    return [...v4, ...v6]
  }
}

let lookup: DnsLookup = new NodeDnsLookup()

/** Test seam. */
export function setDnsLookup(l: DnsLookup | null): void {
  lookup = l ?? new NodeDnsLookup()
}

/** The ingress load balancer as addresses: IPs kept, hostnames (an AWS ELB) resolved. */
async function expectedAddresses(ingress: string[]): Promise<string[]> {
  const out = await Promise.all(ingress.map((a) => (IP.test(a) ? Promise.resolve([a]) : lookup.addresses(a))))
  return [...new Set(out.flat())]
}

export async function probeWildcard(domain: string, ingress: string[]): Promise<DnsReport> {
  const probe = `jinbe-probe-${randomBytes(4).toString('hex')}.${domain}`
  const [addresses, expected] = await Promise.all([lookup.addresses(probe), expectedAddresses(ingress)])
  if (addresses.length === 0) {
    return { probe, status: 'unresolved', addresses, expected, message: `*.${domain} does not resolve yet; create a wildcard DNS record pointing at the platform ingress` }
  }
  if (expected.length === 0) {
    return { probe, status: 'unverified', addresses, expected, message: `*.${domain} resolves, but the platform ingress address is not known here to compare it with` }
  }
  if (addresses.some((a) => expected.includes(a))) {
    return { probe, status: 'ok', addresses, expected, message: `*.${domain} resolves to the platform ingress` }
  }
  return { probe, status: 'elsewhere', addresses, expected, message: `*.${domain} resolves to ${addresses.join(', ')}, not to the platform ingress (${expected.join(', ')})` }
}
