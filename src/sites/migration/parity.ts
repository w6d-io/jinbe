import type { OathkeeperRule, RouteRule } from '../../services/redis-rbac.repository.js'
import { gatekit, type MatchResult, type Probe } from '../gatekit.client.js'
import { examplePath } from '../patterns.js'
import { splitMatchUrl, type MigrationGroup } from './convert.js'

/**
 * Parity (site-ux §20.3 step 2): every probe of the corpus is matched by gatekit — the real
 * Oathkeeper matcher — against the legacy rule set and against the converted one. A probe whose
 * rule or verdict changed is a difference; one no opted-in change explains is a regression, and a
 * regression blocks the cut-over.
 *
 * Corpus: per legacy rule, its host root, its literal prefix, the prefix plus `x` and `/x`, and each
 * literal alternative of its first `<(a|b|…)>` group; plus every route-map example of the service of
 * the same name; × the rule's methods. (Matching is by method and URL only, so the design's
 * anonymous/session/token dimension does not change a match and is not multiplied in.)
 */

export interface ParityDiff { method: string; url: string; before: { rules: string[]; verdict: string }; after: { rules: string[]; verdict: string }; cause?: string }
export interface ParityReport { at: string; total: number; identical: number; differs: ParityDiff[]; regressions: ParityDiff[]; overlapsBefore: number; overlapsAfter: number }

const MAX_PROBES = 5000
const MAX_LISTED = 200
const CONCURRENCY = 8
const unescape = (s: string) => s.replace(/\\(.)/g, '$1')

export function probesOf(rule: OathkeeperRule): Probe[] {
  const split = splitMatchUrl(rule.match?.url ?? '')
  if (!split?.host) return []
  const lt = split.rest.indexOf('<')
  const literal = unescape(lt === -1 ? split.rest : split.rest.slice(0, lt))
  const paths = new Set(['/', literal, `${literal}x`, literal.endsWith('/') ? `${literal}x/y` : `${literal}/x`])
  const alt = lt === -1 ? null : /^<\(([A-Za-z0-9_\-./\\|]+)\)/.exec(split.rest.slice(lt))
  for (const word of alt ? alt[1].split('|').slice(0, 24) : []) {
    paths.add(`${literal}${unescape(word)}`)
    paths.add(`${literal}${unescape(word)}/x`)
  }
  return [...paths].flatMap((p) => rule.match.methods.map((method) => ({ method, url: `https://${split.host}${p}` })))
}

export function corpusOf(legacy: OathkeeperRule[], routeMaps: Record<string, RouteRule[]>, groups: MigrationGroup[]): Probe[] {
  const out = new Map<string, Probe>()
  const add = (p: Probe) => out.set(`${p.method} ${p.url}`, p)
  legacy.flatMap(probesOf).forEach(add)
  for (const g of groups) {
    for (const host of g.siteCr?.spec.hosts ?? []) {
      for (const row of routeMaps[g.proposedSite] ?? []) add({ method: row.method, url: `https://${host}${examplePath(row.path)}` })
    }
  }
  return [...out.values()].slice(0, MAX_PROBES)
}

export function compareProbe(probe: Probe, before: MatchResult, after: MatchResult, mapping: Map<string, string>, causes: Map<string, string>) {
  const b = [...before.matched].sort()
  const a = after.matched.map((id) => mapping.get(id) ?? id).sort()
  const same = before.verdict === after.verdict && b.join('\n') === a.join('\n')
  const cause = same ? undefined : [...b, ...a].map((id) => causes.get(id)).find(Boolean)
  return {
    same,
    regression: !same && !cause,
    diff: { method: probe.method, url: probe.url, before: { rules: b, verdict: before.verdict }, after: { rules: after.matched, verdict: after.verdict }, ...(cause ? { cause } : {}) } as ParityDiff,
  }
}

/**
 * `legacy`: the rules served today from the legacy source. `others`: rules served beside them either
 * way (applied sites). Dropped legacy rules are the only opted-in change that alters matching.
 */
export async function runParity(legacy: OathkeeperRule[], groups: MigrationGroup[], others: OathkeeperRule[], routeMaps: Record<string, RouteRule[]>, dropped: string[]): Promise<ParityReport> {
  const converted = new Set(groups.filter((g) => g.kind !== 'unassigned').flatMap((g) => g.legacyRuleIds))
  const before = [...legacy, ...others]
  const after = [...legacy.filter((r) => !converted.has(r.id) && !dropped.includes(r.id)), ...groups.flatMap((g) => g.renderedRules), ...others]
  const mapping = new Map(groups.flatMap((g) => Object.entries(g.ruleMap)))
  const causes = new Map(dropped.map((id) => [id, `decision:${id}`]))
  const probes = corpusOf(legacy, routeMaps, groups)

  const report: ParityReport = { at: new Date().toISOString(), total: probes.length, identical: 0, differs: [], regressions: [], overlapsBefore: 0, overlapsAfter: 0 }
  for (let i = 0; i < probes.length; i += CONCURRENCY) {
    const batch = probes.slice(i, i + CONCURRENCY)
    const results = await Promise.all(batch.map(async (p) => [p, await gatekit.match(before, p.method, p.url), await gatekit.match(after, p.method, p.url)] as const))
    for (const [probe, b, a] of results) {
      if (b.verdict === 'multiple') report.overlapsBefore++
      if (a.verdict === 'multiple') report.overlapsAfter++
      const c = compareProbe(probe, b, a, mapping, causes)
      if (c.same) report.identical++
      else {
        if (report.differs.length < MAX_LISTED) report.differs.push(c.diff)
        if (c.regression && report.regressions.length < MAX_LISTED) report.regressions.push(c.diff)
      }
    }
  }
  return report
}
