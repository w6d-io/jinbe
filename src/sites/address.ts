import type { OathkeeperRule } from '../services/redis-rbac.repository.js'
import type { Site } from './schemas.js'
import type { Check, Rendered } from './render.js'
import { placeHost, type Zone } from './host.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { gatekit, type Probe } from './gatekit.client.js'
import { examplePath } from './patterns.js'

/**
 * A site's address (host = label + zone, and path prefix) changing on a site visitors already reach.
 *
 * The address a change is measured against is the APPLIED one — what bookmarks, links and OAuth
 * redirect URIs point at — never the saved one. Until the move is applied the site still holds its
 * live address, so another site cannot take it in the meantime (`liveAddresses`, `hostOwner`).
 *
 * The site-operator moves a Site in place: the gate Rules keep their names (the name hashes the
 * authorizer and mutator templates only), so each Rule's match URL changes from the old host to the
 * new one in one write — never both live, never a gap for the same gate — then the Site's own
 * Ingress follows (vanity: updated; per-site zone: the new `host-<hash>` Ingress is created and the
 * old one released).
 */

export type Address = Site['address']

/** A check with the old and new addresses, or a value the editor can write back as the fix. */
export type AddressCheck = Check & {
  address?: { from: AddressView; to: AddressView }
  fix?: { path: string; value: string }
}

export interface AddressView { host: string; pathPrefix: string | null; zone: string | null; url: string }

export const addressUrl = (a: Address) => `https://${a.host}${a.pathPrefix ?? ''}/`

export const sameAddress = (a: Address, b: Address) => a.host.toLowerCase() === b.host.toLowerCase() && (a.pathPrefix ?? '') === (b.pathPrefix ?? '')

export function addressView(a: Address, zones: readonly Zone[]): AddressView {
  return { host: a.host, pathPrefix: a.pathPrefix ?? null, zone: placeHost(a.host, zones, undefined).zone, url: addressUrl(a) }
}

/** The address each applied site serves now, by name (its applied version's, which a later save may not share). */
export async function liveAddresses(records: readonly SiteRecord[]): Promise<Map<string, Address>> {
  const out = new Map<string, Address>()
  await Promise.all(records.filter((r) => r.applied).map(async (r) => {
    const v = r.applied!.version === r.version ? null : await sitesRepository.version(r.site.name, r.applied!.version)
    out.set(r.site.name, v?.site.address ?? r.site.address)
  }))
  return out
}

/** A URL on the old address, moved to the same path under the new one (null when it is not on the old host). */
export function movedUrl(raw: string, from: Address, to: Address): string | null {
  const url = new URL(raw)
  if (url.hostname.toLowerCase() !== from.host.toLowerCase()) return null
  const oldPrefix = from.pathPrefix ?? ''
  const underOld = !oldPrefix || url.pathname === oldPrefix || url.pathname.startsWith(`${oldPrefix}/`)
  const rest = underOld ? url.pathname.slice(oldPrefix.length) : url.pathname
  url.hostname = to.host
  url.pathname = `${to.pathPrefix ?? ''}${rest || '/'}`
  return url.toString()
}

/**
 * The checks only an address change needs. `before` is the applied intent (null: nothing live, so
 * nothing breaks). Render's own checks already cover the new address as such (zone, depth, SSO,
 * landing page host); this adds what the MOVE costs, and the fixes the editor can offer.
 */
export function addressChecks(before: Site | null, after: Site, zones: readonly Zone[], opts: { allowedParents?: readonly string[] } = {}): AddressCheck[] {
  if (!before || sameAddress(before.address, after.address)) return []
  const from = addressView(before.address, zones)
  const to = addressView(after.address, zones)
  const checks: AddressCheck[] = []
  const zoneMove = from.zone !== to.zone ? ` (zone ${from.zone ?? 'none'} → ${to.zone ?? 'none'})` : ''
  checks.push({
    level: 'warn', code: 'address_changed', path: 'address', address: { from, to },
    message: `The address moves from ${from.url} to ${to.url}${zoneMove}. Once applied, ${from.url} stops answering (404): bookmarks, links and OAuth redirect URIs registered for it break.`,
  })

  const landing = after.login?.defaultReturnUrl
  const movedLanding = landing ? movedUrl(landing, before.address, after.address) : null
  if (landing && movedLanding && new URL(landing).hostname.toLowerCase() !== after.address.host.toLowerCase()) {
    checks.push({
      level: 'error', code: 'return_url_old_address', path: 'login.defaultReturnUrl', fix: { path: 'login.defaultReturnUrl', value: movedLanding },
      message: `The landing page after sign-in (${landing}) is on the old address; move it to ${movedLanding}`,
    })
  }
  const logout = after.login?.postLogoutUrl
  const movedLogout = logout ? movedUrl(logout, before.address, after.address) : null
  if (logout && movedLogout && new URL(logout).hostname.toLowerCase() !== after.address.host.toLowerCase()) {
    checks.push({
      level: 'warn', code: 'post_logout_old_address', path: 'login.postLogoutUrl', fix: { path: 'login.postLogoutUrl', value: movedLogout },
      message: `After signing out, visitors are sent to ${logout}, on the old address; move it to ${movedLogout}`,
    })
  }

  const zone = zones.find((z) => z.suffix === to.zone)
  if (zone && from.zone !== to.zone) {
    if (zone.ready === false) {
      checks.push({ level: 'warn', code: 'zone_not_ready', path: 'address.host', message: `Zone ${zone.suffix} is not ready yet (its Ingress or certificate is not admitted); ${to.host} may not answer until it is` })
    }
    const parents = opts.allowedParents ?? []
    if (parents.length > 0 && !parents.some((p) => zone.suffix === p || zone.suffix.endsWith(`.${p}`))) {
      checks.push({ level: 'warn', code: 'zone_parent_not_allowed', path: 'address.host', message: `Zone ${zone.suffix} is not under a parent this platform serves (${parents.join(', ')}); it may be going away` })
    }
  }
  const placement = placeHost(after.address.host, zones, undefined)
  if (placement.zone && after.exposure.mode === 'vanity' && placement.tls === 'per-site') {
    checks.push({ level: 'warn', code: 'certificate_pending', path: 'address.host', message: `${to.host} gets its own certificate (issued in about a minute); HTTPS fails there until it is` })
  }
  return checks
}

/** The gate a jinbe rule id names: `site-<name>-<gate>-<hash10>`. */
export function gateOfRule(site: string, id: string): string {
  return id.slice(`site-${site}-`.length).replace(/-[0-9a-f]{10}$/, '')
}

/**
 * While the operator moves a site, its Rules are rewritten one after the other: for a moment some
 * gates match the new address and the others still the old one. Two DIFFERENT gates matching one
 * URL in that moment is a 500 (a prefix moved under the old one, /pay → /pay/v2). gatekit is asked
 * about the old rules (those that change) next to the new ones, on both addresses.
 */
export async function swapChecks(before: { site: Site; rules: OathkeeperRule[] } | null, after: Site, rendered: Rendered, others: OathkeeperRule[]): Promise<Check[]> {
  if (!before || sameAddress(before.site.address, after.address)) return []
  const kept = new Set(rendered.rules.map((r) => r.id))
  const old = before.rules.filter((r) => !kept.has(r.id))
  if (old.length === 0) return []
  const oldIds = new Set(old.map((r) => r.id))
  const probes: Probe[] = []
  const probe = (host: string, prefix: string | undefined, rows: Rendered['routeMap']) => {
    for (const row of rows) probes.push({ method: row.method, url: `https://${host}${examplePath(row.path)}` })
    probes.push({ method: 'GET', url: `https://${host}${prefix ?? ''}/` })
  }
  probe(after.address.host, after.address.pathPrefix, rendered.routeMap)
  probe(before.site.address.host, before.site.address.pathPrefix, rendered.routeMap.map((r) => ({ ...r, path: `${before.site.address.pathPrefix ?? ''}${r.path.slice((after.address.pathPrefix ?? '').length)}` })))
  const seen = new Set<string>()
  const unique = probes.filter((p) => (seen.has(`${p.method} ${p.url}`) ? false : (seen.add(`${p.method} ${p.url}`), true)))
  const hosts = [...new Set([after.address.host, before.site.address.host])]
  const result = await gatekit.overlap([...others, ...old, ...rendered.rules], unique, hosts)
  const checks: Check[] = []
  for (const o of result.overlaps) {
    const [was, now] = oldIds.has(o.a) && kept.has(o.b) ? [o.a, o.b] : oldIds.has(o.b) && kept.has(o.a) ? [o.b, o.a] : ['', '']
    if (!was || gateOfRule(after.name, was) === gateOfRule(after.name, now)) continue
    checks.push({
      level: 'error', code: 'swap_overlap', path: 'address',
      message: `While the gateway moves the site, ${o.method} ${o.exampleUrl} would be matched by gate '${gateOfRule(after.name, was)}' (old address) and gate '${gateOfRule(after.name, now)}' (new address) at once; move the address in two steps (first to a prefix that does not nest in the old one)`,
    })
  }
  return checks
}
