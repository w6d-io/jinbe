import type { OathkeeperRule } from '../services/redis-rbac.repository.js'
import type { Site } from './schemas.js'
import { render, type Platform, type Rendered } from './render.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { liveAddresses, type Address } from './address.js'

/**
 * Sites nested on one host: /cab under a site at the root, /cab/api/pricing under /cab. The longest
 * prefix wins: a site leaves out (render `nested`) the prefixes of the sites below it, so no request
 * is matched by two rules. Its rules therefore depend on the other sites, not only on its own intent:
 * a site appearing, moving or going under it changes them, and the enclosing site is applied again
 * (apply.service.ts) — before the nested site's rules, so the gateway never holds both.
 *
 * Only what the gateway serves counts: applied sites, at the address they serve now (`live`), plus
 * the candidate's own address when it is about to be applied.
 */

const sameHost = (a: Address, b: Address) => a.host.toLowerCase() === b.host.toLowerCase()

/** Whether `inner` sits strictly under `outer` (any prefix sits under the root). */
export const prefixContains = (outer: string | undefined, inner: string | undefined): boolean =>
  !!inner && (!outer || inner.startsWith(`${outer}/`))

/**
 * The prefixes nested under `address`, served by the other applied sites (and `extra`): the outermost
 * ones only — /cab/api/pricing is already left out with /cab, and listing it too would change the
 * enclosing site's rules (an apply) for nothing.
 */
export function nestedPrefixes(address: Address, except: string, records: readonly SiteRecord[], live: ReadonlyMap<string, Address>, extra: readonly Address[] = []): string[] {
  const served = records.filter((r) => r.applied && r.site.name !== except).map((r) => live.get(r.site.name) ?? r.site.address)
  const prefixes = [...served, ...extra]
    .filter((a): a is Address => !!a?.host && sameHost(a, address) && prefixContains(address.pathPrefix, a.pathPrefix))
    .map((a) => a.pathPrefix!)
  const unique = [...new Set(prefixes)]
  return unique.filter((p) => !unique.some((q) => prefixContains(q, p))).sort()
}

/** The applied sites whose live address encloses `address` (same host, a strictly shorter prefix or the root). */
export function enclosingSites(address: Address, except: string, records: readonly SiteRecord[], live: ReadonlyMap<string, Address>): SiteRecord[] {
  return records.filter((r) => {
    if (!r.applied || r.site.name === except) return false
    const at = live.get(r.site.name) ?? r.site.address
    return !!at?.host && sameHost(at, address) && prefixContains(at.pathPrefix, address.pathPrefix)
  })
}

/** The context render needs for `site` now. */
export async function nestingContext(site: Site, records?: readonly SiteRecord[], extra: readonly Address[] = [], live?: ReadonlyMap<string, Address>): Promise<{ nested: string[] }> {
  const all = records ?? (await sitesRepository.list())
  return { nested: nestedPrefixes(site.address, site.name, all, live ?? (await liveAddresses(all)), extra) }
}

/** render() with the nested sites of the site's host taken into account. */
export async function renderNested(site: Site, platform: Platform, records?: readonly SiteRecord[]): Promise<Rendered> {
  return render(site, platform, await nestingContext(site, records))
}

/** An enclosing site as it renders once `around` is served too. */
export interface EnclosingRender {
  record: SiteRecord
  site: Site
  version: number
  rendered: Rendered
  /** Its rules differ from the ones the gateway holds: it must be applied again. */
  changed: boolean
}

/**
 * The applied sites enclosing any of `addresses`, rendered from their applied version with the nested
 * prefixes the gateway will hold: the other applied sites' (`records`, `live`) and `extra`. Without
 * `extra` it is the cleanup after a site moved or went: its old prefix is no longer left out.
 */
export async function renderEnclosing(
  candidate: string,
  addresses: readonly Address[],
  platform: Platform,
  records: readonly SiteRecord[],
  extra: readonly Address[] = [],
): Promise<EnclosingRender[]> {
  const live = await liveAddresses(records)
  const enclosing = new Map<string, SiteRecord>()
  for (const address of addresses) for (const r of enclosingSites(address, candidate, records, live)) enclosing.set(r.site.name, r)
  const out: EnclosingRender[] = []
  for (const record of enclosing.values()) {
    const version = record.applied!.version
    const stored = await sitesRepository.version(record.site.name, version)
    if (!stored) throw new Error(`applied version ${version} of ${record.site.name} is gone`)
    const site = { ...stored.site, state: record.site.state }
    const at = live.get(record.site.name) ?? record.site.address
    // The candidate is left out of `records` (its address is the one in `extra`, or gone).
    const others = records.filter((r) => r.site.name !== candidate)
    const rendered = render(site, platform, { nested: nestedPrefixes(at, record.site.name, others, live, extra) })
    out.push({ record, site, version, rendered, changed: rulesKey(rendered.rules) !== rulesKey(record.applied!.rules) })
  }
  return out
}

/** The rules the gateway would hold with the enclosing sites rendered again: what gatekit is asked about. */
export function rulesOverride(enclosing: readonly EnclosingRender[]): Map<string, OathkeeperRule[]> {
  return new Map(enclosing.map((e) => [e.record.site.name, e.rendered.rules]))
}

const rulesKey = (rules: readonly OathkeeperRule[]) => JSON.stringify([...rules].sort((a, b) => a.id.localeCompare(b.id)))
