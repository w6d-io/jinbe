import type { Site } from './schemas.js'
import { render } from './render.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { loadPlatform } from './platform.js'
import { kubeSites, type SiteCondition } from './kube-sites.js'
import { siteError } from './checks.js'
import { getRecord, protectionLookup } from './sites.service.js'
import { resolveHost } from './dns-probe.js'
import { curlFor, probeRoutes, probeTransport, wafCheck, type ProbeReport, type ProbeTarget, type WafReport } from './verify-probe.js'
import { accessMatrix, type AccessMatrix } from './verify-access.js'

/**
 * POST /api/admin/sites/:name/verify — after publishing, is the site really served the way it was
 * designed? (a) the rollout: version, Site CR, gateway rules, route, DNS, TLS, WAF; (b) one anonymous
 * request per route to the public URL; (c) the access matrix from the policy; (d) one WAF check, only
 * when asked; (e) curl commands to repeat any of it by hand.
 *
 * About the version the gateway serves (the applied one), not a later save. Once per site per 30 s
 * on this replica: it sends real requests to the site, and repeated WAF trips get an address banned.
 */

export const VERIFY_INTERVAL_MS = 30_000
const TLS_WARN_DAYS = 14
const lastRun = new Map<string, number>()

/** Test seam. */
export const resetVerifyLimiter = () => lastRun.clear()

export type CheckStatus = 'ok' | 'pending' | 'warn' | 'fail' | 'unknown' | 'skipped'
export interface RolloutCheck { id: string; label: string; status: CheckStatus; message: string }

type Target = ProbeTarget & { orgParam?: string }

/** Every route of the version, then the catch-all (unless it denies: nothing to reach there). */
export function targetsOf(site: Site): Target[] {
  const routes: Target[] = site.routes.items.map((r) => ({ route: r.id, methods: r.methods, path: r.path, access: r.access, ...(r.orgParam ? { orgParam: r.orgParam } : {}) }))
  const catchAll = site.routes.catchAll.access
  return catchAll.kind === 'deny' ? routes : [...routes, { route: 'catch-all', methods: ['GET'], path: `${site.address.pathPrefix ?? ''}/:any*`, access: catchAll }]
}

const condition = (conditions: SiteCondition[], type: string) => conditions.find((c) => c.type === type)
const said = (c: SiteCondition | undefined) => (c ? [c.reason, c.message].filter(Boolean).join(': ') || c.status : 'not reported yet')

async function rollout(record: SiteRecord, site: Site): Promise<RolloutCheck[]> {
  const checks: RolloutCheck[] = []
  const add = (id: string, label: string, status: CheckStatus, message: string) => checks.push({ id, label, status, message })
  const applied = record.applied
  if (!applied) add('applied', 'Published', 'fail', `version ${record.version} is saved but was never published`)
  else if (applied.version !== record.version) add('applied', 'Published', 'warn', `version ${applied.version} is live; version ${record.version} is saved but not published`)
  else add('applied', 'Published', 'ok', `version ${applied.version} is live`)

  let conditions: SiteCondition[] | null = null
  try {
    const cr = await kubeSites().get(site.name)
    conditions = cr ? cr.status?.conditions ?? [] : null
    if (!cr) add('site', 'Site accepted', applied ? 'fail' : 'skipped', 'no Site object in the cluster')
  } catch (err) {
    add('site', 'Site accepted', 'unknown', `the cluster could not be asked (${(err as Error).message})`)
  }
  if (conditions) {
    const ready = condition(conditions, 'Ready')
    add('site', 'Site ready', ready?.status === 'True' ? 'ok' : 'pending', ready?.status === 'True' ? 'the operator reports the site Ready' : said(ready))
    const synced = condition(conditions, 'RulesSynced')
    const loaded = condition(conditions, 'RulesLoaded')
    const rules = applied?.rules.length ?? 0
    add('rules', 'Gateway rules', synced?.status === 'True' && loaded?.status === 'True' ? 'ok' : 'pending',
      synced?.status === 'True' && loaded?.status === 'True' ? `${rules} rule(s) synced and loaded by the gateway` : `synced: ${said(synced)}; loaded: ${said(loaded)}`)
    const route = condition(conditions, 'RouteReady')
    if (route) add('route', 'Gateway route (HTTPRoute)', route.status === 'True' ? 'ok' : 'pending', route.status === 'True' ? 'accepted by the Gateway' : said(route))
    else add('route', 'Gateway route (HTTPRoute)', 'skipped', 'no HTTPRoute: the zone is served by its Ingress')
  }

  const host = site.address.host
  const addresses = await resolveHost(host).catch(() => [] as string[])
  add('dns', 'DNS', addresses.length > 0 ? 'ok' : 'fail', addresses.length > 0 ? `${host} resolves to ${addresses.join(', ')}` : `${host} does not resolve from jinbe`)

  const tls = await probeTransport().tls(host).catch((err: Error) => ({ authorized: false, validTo: null, error: err.message }))
  if (tls.authorized && tls.validTo) {
    const days = Math.floor((new Date(tls.validTo).getTime() - Date.now()) / 86_400_000)
    add('tls', 'HTTPS certificate', days < TLS_WARN_DAYS ? 'warn' : 'ok', `valid for ${host} until ${tls.validTo}${days < TLS_WARN_DAYS ? ` (${days} day(s) left)` : ''}`)
  } else if (tls.error === 'timeout' || /ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH/.test(tls.error ?? '')) {
    add('tls', 'HTTPS certificate', 'unknown', `could not connect to ${host}:443 from jinbe (${tls.error})`)
  } else {
    add('tls', 'HTTPS certificate', 'fail', `${host} presents no valid certificate (${tls.error ?? 'unknown'})`)
  }

  const protection = (await protectionLookup())(host)
  if (!protection) add('waf', 'WAF', 'unknown', 'the zone and Gateway could not be inspected')
  else add('waf', 'WAF', protection.state === 'waf' ? 'ok' : 'warn', protection.message)
  return checks
}

export interface VerifyReport {
  site: string
  host: string
  version: { saved: number; applied: number | null }
  checkedAt: string
  rollout: { ready: boolean; checks: RolloutCheck[] }
  probe: ProbeReport
  access: AccessMatrix
  waf: WafReport | null
  curl: ReturnType<typeof curlFor>[]
  summary: { ok: boolean; errors: string[]; warnings: string[] }
}

export async function verifySite(name: string, opts: { waf?: boolean } = {}, now = Date.now()): Promise<VerifyReport> {
  const record = await getRecord(name)
  const last = lastRun.get(name)
  if (last !== undefined && now - last < VERIFY_INTERVAL_MS) {
    const wait = Math.ceil((VERIFY_INTERVAL_MS - (now - last)) / 1000)
    throw Object.assign(siteError(429, 'verify_rate_limited', `${name} was verified less than ${VERIFY_INTERVAL_MS / 1000} s ago; retry in ${wait} s`), { retryAfterSec: wait })
  }
  lastRun.set(name, now)

  const live = record.applied ? (await sitesRepository.version(name, record.applied.version))?.site ?? null : null
  const site = live ?? record.site
  const host = site.address.host
  const targets = targetsOf(site)
  const checks = await rollout(record, site)
  const unpublished = (what: string) => ({ available: false, reason: `not published: no ${what}` })
  const probe: ProbeReport = live ? await probeRoutes(host, targets) : { ...unpublished('probe'), results: [], notProbed: targets.map((t) => t.route) }
  const access: AccessMatrix = live
    ? await accessMatrix(site, render(site, await loadPlatform()).roles, targets)
    : { ...unpublished('access matrix'), source: 'opa', subjects: [], rows: [], notChecked: targets.map((t) => t.route) }
  const waf = opts.waf && live ? await wafCheck(site) : null

  const errors = [
    ...checks.filter((c) => c.status === 'fail').map((c) => `${c.label}: ${c.message}`),
    ...probe.results.filter((r) => r.level === 'error').map((r) => `${r.method} ${r.url}: ${r.message}`),
    ...(waf?.blocked === false ? [`WAF: ${waf.message}`] : []),
  ]
  const warnings = [
    ...checks.filter((c) => c.status === 'warn' || c.status === 'pending' || c.status === 'unknown').map((c) => `${c.label}: ${c.message}`),
    ...probe.results.filter((r) => r.level === 'warn').map((r) => `${r.method} ${r.url}: ${r.message}`),
    ...(probe.available ? [] : [probe.reason ?? 'probe unavailable']),
    ...(probe.notProbed.length > 0 && probe.available ? [`${probe.notProbed.length} route(s) past the first ${targets.length - probe.notProbed.length} were not probed${probe.stoppedBy === 'budget' ? ' (time budget); use their curl commands' : ''}`] : []),
    ...(access.available ? [] : [access.reason ?? 'access matrix unavailable']),
    ...(waf && waf.blocked === null ? [waf.message] : []),
  ]
  const ready = checks.every((c) => c.status === 'ok' || c.status === 'skipped' || c.status === 'warn')
  return {
    site: name,
    host,
    version: { saved: record.version, applied: record.applied?.version ?? null },
    checkedAt: new Date(now).toISOString(),
    rollout: { ready, checks },
    probe,
    access,
    waf,
    curl: targets.map((t) => curlFor(host, t)),
    summary: { ok: ready && errors.length === 0, errors, warnings },
  }
}
