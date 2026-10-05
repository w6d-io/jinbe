import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { render } from './render.js'
import { sitesRepository, type SiteRecord } from './repository.js'
import { loadPlatform } from './platform.js'
import { assertNotSystem, contextChecks, errorsOf, gatekitChecks, liveRules, pinnedHostsOf, siteError } from './checks.js'
import { addressUrl, liveAddresses, sameAddress, swapChecks } from './address.js'
import { kubeSites } from './kube-sites.js'
import { publishPermissions, unpublishPermissions } from './publish.js'
import { findingsFor, getRecord, save } from './sites.service.js'
import { assertPublishable } from './findings.js'
import { auditSite, type Actor } from './audit.js'
import { setStage, saveApply, startApply, watchApply, withVersion } from './applies.js'
import { siteLoginStore } from './login-store.js'
import { liveSite, siteLoginOf } from './login.js'
import { holdsInJinbe } from '../authz/opa.js'
import type { Site } from './schemas.js'
import { assertNoApprovalNeeded } from './requests.js'
import { assertApplyAllowed } from './migration/migration.service.js'
import { deletionStore, ephemeralStore } from './lifecycle-store.js'

/**
 * Everything that reaches the gateway: apply, rollback, pause/resume, delete.
 *
 * Order is the safety property. Every check that can refuse runs first — render, platform context,
 * gatekit, and a Kubernetes round-trip — and when any of them cannot answer, the answer is 503 and
 * nothing is written. Then permissions are published (a new route fails closed until its
 * permission exists), THEN the Site CR is written. Delete runs the other way round: rules out first,
 * permissions after.
 *
 * Every apply gets a timeline (applies.ts) the caller follows by id; with four-eyes on, a high-risk
 * version is applied only through an approved request (requests.ts); before the migration's
 * cut-over, no new site is applied at all (migration/).
 */

export async function apply(name: string, version: number, actor: Actor, acknowledge: readonly string[] = []) {
  assertNotSystem(name)
  const record = await getRecord(name)
  if (version !== record.version) {
    throw siteError(409, 'version_mismatch', `Version ${record.version} is the saved one; apply that, or roll back to ${version}`)
  }
  await assertAcknowledged(record, acknowledge)
  await assertNoApprovalNeeded(record)
  return applyRecord(record, actor, 'applied', acknowledge.length > 0 ? { acknowledged: [...new Set(acknowledge)] } : {})
}

/**
 * The publish gate on security findings (findings.ts): refused (422 unconfirmed_findings) while one is
 * an error or a confirm finding is not acknowledged. Apply and the apply request pass through it; a
 * rollback does not — it puts back a version that was published already.
 */
export async function assertAcknowledged(record: SiteRecord, acknowledge: readonly string[]): Promise<void> {
  const platform = await loadPlatform()
  assertPublishable(await findingsFor(record.site, render(record.site, platform), platform), acknowledge)
}

export async function applyRecord(record: SiteRecord, actor: Actor, verb: string, details: Record<string, unknown> = {}) {
  const { site, version } = record
  await assertApplyAllowed()
  await assertMayWidenSignUp(record.site, actor)
  const records = await sitesRepository.list()
  const rendered = render(site, await loadPlatform())
  if (errorsOf(rendered.checks).length > 0) throw siteError(422, 'invalid_site', 'This version does not render', rendered.checks)

  const gk = await gatekitChecks(site, rendered, records)
  const ctx = await contextChecks(site, rendered, records)
  // A move: the version live now, and the moment the operator rewrites its Rules one by one.
  const before = record.applied ? (await sitesRepository.version(site.name, record.applied.version))?.site ?? null : null
  const swap = before ? await swapChecks({ site: before, rules: record.applied!.rules }, site, rendered, await liveRules(site.name, records)) : []
  const blocking = errorsOf([...ctx, ...gk, ...swap])
  if (blocking.length > 0) throw siteError(409, 'checks_failed', blocking.map((c) => c.message).join('; '), [...ctx, ...gk, ...swap])
  const live = await liveAddresses(records)

  const kube = kubeSites()
  await kube.ping()

  const timeline = await startApply(record, actor.email ?? 'unknown', record.applied ?? null)
  const failed = async (stage: 'permissions' | 'accepted', err: unknown) => {
    setStage(timeline, stage, 'failed', err instanceof Error ? err.message : 'error')
    Object.assign(timeline, { state: 'failed', endedAt: new Date().toISOString(), code: (err as { code?: string }).code ?? 'apply_failed' })
    await saveApply(timeline)
  }

  setStage(timeline, 'permissions', 'running')
  try {
    await publishPermissions(site.name, rendered, { description: site.description ?? site.displayName, pinnedHosts: pinnedHostsOf(records, site, live), actor })
    await siteLoginStore.set(site.name, siteLoginOf(site))
  } catch (err) {
    await failed('permissions', err)
    throw err
  }
  setStage(timeline, 'permissions', 'done')
  setStage(timeline, 'accepted', 'running')
  try {
    await kube.apply(withVersion(rendered.siteCr, version))
  } catch (err) {
    // Permissions are ahead of the rules: new routes stay refused until a retry writes the CR.
    const e = siteError(503, 'rules_pending', 'Permissions were published but the gateway rules were not written; nothing new is reachable yet. Retry apply.')
    ;(e as Error & { cause?: unknown }).cause = err
    await failed('accepted', e)
    throw e
  }
  timeline.generation = await kube.get(site.name).then((cr) => cr?.metadata.generation).catch(() => undefined)
  await saveApply(timeline)
  await sitesRepository.markApplied(site.name, { version, by: actor.email ?? 'unknown', rules: rendered.rules })
  auditSite('apply', site.name, actor, `${verb} version ${version}`, { version, rules: rendered.rules.map((r) => r.id), applyId: timeline.id, ...details }, 'applied')
  if (before && !sameAddress(before.address, site.address)) {
    auditSite('address_change', site.name, actor, `address ${addressUrl(before.address)} → ${addressUrl(site.address)} (version ${version})`, {
      version, fromVersion: record.applied!.version, applyId: timeline.id, address: { from: before.address, to: site.address },
    }, 'applied')
  }
  watchApply(site.name, timeline.id)
  return { applyId: timeline.id, version, rules: rendered.rules.map((r) => r.id), site: rendered.siteCr.metadata.name }
}

export async function rollback(name: string, toVersion: number, actor: Actor, note?: string) {
  assertNotSystem(name)
  const current = await getRecord(name)
  const target = await sitesRepository.version(name, toVersion)
  if (!target) throw siteError(404, 'not_found', `No version ${toVersion} of ${name}`)
  // A rollback is a new version (history stays append-only), carrying the current run state.
  const record = await save(name, { ...target.site, state: current.site.state }, {
    actor, ifMatch: current.etag, kind: 'rollback', note: note ?? `rollback to version ${toVersion}`,
  })
  return applyRecord(record, actor, `rolled back to ${toVersion} as`)
}

export async function setPaused(name: string, paused: boolean, actor: Actor) {
  assertNotSystem(name)
  const record = await getRecord(name)
  const state = paused ? 'paused' : 'active'
  if (record.applied) {
    const applied = await sitesRepository.version(name, record.applied.version)
    const rendered = render({ ...(applied?.site ?? record.site), state }, await loadPlatform())
    const kube = kubeSites()
    await kube.ping()
    await kube.apply(withVersion(rendered.siteCr, record.applied.version))
  }
  const updated = await sitesRepository.setState(name, state)
  auditSite(paused ? 'pause' : 'resume', name, actor, paused ? 'paused' : 'resumed')
  return { name, state: updated.site.state }
}

export async function remove(name: string, actor: Actor, opts: { approvedRequest?: string } = {}) {
  assertNotSystem(name)
  const record = await getRecord(name)
  const kube = kubeSites()
  await kube.ping()
  await kube.delete(name)
  if (record.applied) await unpublishPermissions(name, actor)
  await siteLoginStore.set(name, null)
  await sitesRepository.remove(name, actor.email ?? 'unknown')
  // Its expiry goes with it (a restored site is permanent), and so do requests to delete it.
  await ephemeralStore.clear(name)
  const cancelled = await deletionStore.cancelPending(name, actor.email ?? 'unknown', 'site deleted', opts.approvedRequest)
  auditSite('delete', name, actor, 'deleted', { version: record.version, ...(opts.approvedRequest ? { deletionRequest: opts.approvedRequest } : {}), ...(cancelled.length ? { cancelledRequests: cancelled } : {}) })
  return { name, deleted: true }
}

/** Bring a deleted site back as a saved, not applied, site (apply it again to serve it). */
export async function restore(name: string) {
  assertNotSystem(name)
  const record = await sitesRepository.restore(name)
  return { name, version: record.version, status: 'draft' as const, etag: record.etag }
}

export async function blastRadius(name: string) {
  const record = await getRecord(name)
  const groups = await redisRbacRepository.getGroups()
  const covering = Object.entries(groups).filter(([, def]) => name in def).map(([g]) => g)
  const orgRoles = Object.keys((await redisRbacRepository.getOrgRoles(name)) ?? {}).map((r) => `${name}:${r}`).sort()
  const orgMap = await redisRbacRepository.getOrgSites()
  const assignments = await orgRolesRepository.getAll()
  // Per entitled org: how many people hold one of this site's org roles there.
  const orgs = Object.entries(orgMap)
    .filter(([, svcs]) => svcs.includes(name))
    .map(([id]) => ({ id, grants: Object.values(assignments[id] ?? {}).filter((roles) => roles.some((r) => r.startsWith(`${name}:`))).length }))
  const routeMap = await redisRbacRepository.getRouteMap(name)
  return {
    groups: covering,
    // The site's org roles ("<site>:<role>"): deleted with it, and every assignment of them stops counting.
    orgRoles,
    orgs,
    rules: record.applied?.rules.length ?? 0,
    routes: routeMap?.rules.length ?? 0,
    // Not counted yet: people per group (Kratos), API keys and traffic (S-3).
    people: null,
    apiKeys: null,
    requests24h: null,
  }
}

/**
 * Opening a site to public sign-up, or widening it (open after domains, more domains, more roles), is
 * `sites.signup:write` on top of the publish: whoever drafts a site's sign-up (sites:write) is not who
 * exposes it. Closing or narrowing needs nothing more than the publish.
 */
export async function assertMayWidenSignUp(next: Site, actor: Actor): Promise<void> {
  const live = await liveSite(next.name)
  if (!signUpWidens(live?.signUp, next.signUp)) return
  if (actor.email && (await holdsInJinbe(actor.email, 'sites.signup:write'))) return
  throw siteError(403, 'sign_up_permission_missing', 'Opening or widening public sign-up on a site needs sites.signup:write: ask somebody who holds it to publish this version')
}

export function signUpWidens(before: Site['signUp'] | undefined, after: Site['signUp'] | undefined): boolean {
  const open = (s: Site['signUp'] | undefined) => !!s && s.mode !== 'closed' && s.roles.length > 0
  if (!open(after)) return false
  if (!open(before)) return true
  const b = before!, a = after!
  if (a.mode === 'open' && b.mode === 'domains') return true
  if (a.mode === 'domains' && a.domains.some((d) => !b.domains.includes(d))) return true
  return a.roles.some((r) => !b.roles.includes(r))
}
