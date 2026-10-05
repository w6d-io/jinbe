import { randomBytes } from 'node:crypto'
import { auditEventService } from '../../services/audit-event.service.js'
import type { AuditEventType } from '../../audit/v1/catalog.js'
import { kratosService } from '../../services/kratos.service.js'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { withRedisLock } from '../../services/redis-lock.js'
import { rbacService } from '../../services/rbac.service.js'
import { orgRolesRepository } from '../../services/org-roles.repository.js'
import { addToGroup, createOrganisation, groupsForSubjects, removeFromGroup } from '../../services/organisation-store.js'
import { joinOrganisation, organisationsOf } from '../../services/org-membership.service.js'
import { JINBE, qualified } from '../../policy/roles.js'
import type { KratosIdentity } from '../../schemas/admin.schema.js'
import { getSignInProtection } from '../../sign-in-protection/settings.js'
import { registrationVerdict } from '../../sign-in-protection/guard.js'
import { liveSite, liveSiteByHost } from '../login.js'
import { signUpGroupName, type Site } from '../schemas.js'
import { signUpStore } from './store.js'

/**
 * Public sign-up through one site (the intent's `signUp`).
 *
 *   1. registration: the Kratos guard asks `siteSignUpVerdict` with the flow's return_to; a site whose
 *      sign-up is open lets the address in even when the platform's own sign-up is closed, and the
 *      address is remembered (`pending`) for that site.
 *   2. the address is verified (the registration itself with a code, or the verification flow later):
 *      `onIdentityEvent` joins every pending site — the site's `<site>-users` group and, per
 *      `signUp.orgs`, an organisation.
 *   3. somebody who already has an account: `continueTo` (the "Continue to <site>" step).
 *
 * Joining never asks the holding rule or a step-up: nobody hands anything out, the site's own intent
 * (published by somebody who holds sites:apply, and sites.signup:write to open it) decides what a
 * sign-up gets, and the group can only carry that site's roles (render.ts).
 */

export const SIGN_UP_ACTOR = { id: null, email: 'jinbe (site sign-up)', type: 'system' } as const

export type JoinVia = 'sign-up' | 'continue' | 'invite'

export type JoinResult =
  | { joined: true; site: string; group: string; organization: { id: string; name: string; created: boolean } | null }
  | { joined: false; site: string; reason: JoinRefusal }

export type JoinRefusal = 'site_not_found' | 'sign_up_closed' | 'domain_not_allowed' | 'email_not_verified' | 'no_roles'

const emailOf = (identity: KratosIdentity): string => String((identity.traits as { email?: unknown })?.email ?? '').trim().toLowerCase()
const domainOf = (email: string): string => email.slice(email.lastIndexOf('@') + 1)

export function isVerified(identity: KratosIdentity, email = emailOf(identity)): boolean {
  return (identity.verifiable_addresses ?? []).some((a) => a.via === 'email' && a.value.trim().toLowerCase() === email && a.verified)
}

/** The live site a sign-in flow returns to (its return_to URL), or null. */
export async function siteForReturnTo(returnTo: string | null | undefined): Promise<Site | null> {
  if (!returnTo) return null
  let host: string
  try {
    host = new URL(returnTo).hostname.toLowerCase()
  } catch {
    return null
  }
  return liveSiteByHost(host)
}

export const signUpOpen = (site: Site | null): site is Site & { signUp: NonNullable<Site['signUp']> } =>
  !!site?.signUp && site.signUp.mode !== 'closed' && site.signUp.roles.length > 0 && site.state !== 'paused'

/**
 * Whether this address may sign up through this site: the site's mode and domains, and the
 * platform's deny list and disposable-provider block (a site does not lift those). null = may.
 */
export async function siteSignUpVerdict(site: Site & { signUp: NonNullable<Site['signUp']> }, email: string | null | undefined) {
  const platform = (await getSignInProtection()).registration
  return registrationVerdict(email, {
    ...platform,
    mode: site.signUp.mode === 'domains' ? 'allowlist' : 'open',
    allowEmails: [],
    allowDomains: site.signUp.mode === 'domains' ? site.signUp.domains : [],
  })
}

function audit(event: AuditEventType, verb: string, identity: KratosIdentity, details: Record<string, unknown>, site?: string): void {
  const email = emailOf(identity)
  Promise.resolve()
    .then(() => auditEventService.emit({
      category: 'access',
      kind: 'change',
      verb,
      target: `user:${email || identity.id}`,
      targetType: 'user',
      targetId: identity.id,
      ...(site ? { service: site } : {}),
      result: 'ok',
      actor: { id: SIGN_UP_ACTOR.id, email: SIGN_UP_ACTOR.email, ip: null, ua: null, sessionId: null },
      v1Event: event,
      details: { email, ...details },
      source: 'jinbe-api',
    }))
    .catch(() => {})
}

/** `Jane Doe` → `Jane's organization`; the company trait when given. */
export function organisationNameFor(identity: KratosIdentity): string {
  const traits = (identity.traits ?? {}) as { company?: unknown; name?: unknown; email?: unknown }
  const company = typeof traits.company === 'string' ? traits.company.trim() : ''
  if (company) return company.slice(0, 80)
  const name = typeof traits.name === 'string' ? traits.name.trim().split(/\s+/)[0] : ''
  const who = name || emailOf(identity).split('@')[0] || 'My'
  return `${who.slice(0, 60)}'s organization`
}

/** A tenant no other org has: the name's slug and a short random suffix. */
export function tenantFor(name: string): string {
  const slug = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50) || 'org'
  return `${slug}-${randomBytes(3).toString('hex')}`
}

/** Entitle an org to a site now (rbac:org_sites) and keep it across republishes (sign-up store). */
async function entitle(org: string, site: string): Promise<void> {
  await signUpStore.addOrgSite(org, site)
  await withRedisLock('org_sites', async () => {
    const current = (await redisRbacRepository.getOrgSites())[org] ?? []
    const next = [...new Set([JINBE, ...current, site])]
    if (next.length !== current.length) await redisRbacRepository.setOrgSites(org, next)
  })
}

async function personalOrganisation(identity: KratosIdentity, site: string): Promise<{ id: string; name: string; created: boolean }> {
  const name = organisationNameFor(identity)
  const created = await createOrganisation({ name, tenant: tenantFor(name), attributes: { createdBy: 'sign-up', site } })
  await entitle(created.id, site)
  await joinOrganisation(identity, created.id)
  await orgRolesRepository.setForMember(created.id, identity.id, [qualified(JINBE, 'owner')])
  audit('org.created', 'create', identity, { organizationId: created.id, name, via: 'sign-up', owner: identity.id }, site)
  return { id: created.id, name, created: true }
}

async function organisationFor(identity: KratosIdentity, site: Site & { signUp: NonNullable<Site['signUp']> }) {
  const mode = site.signUp.orgs
  if (mode === 'none' || mode === 'invite') return null
  // Already in an org this site serves (an earlier sign-up, an invite, an administrator): nothing to make.
  const orgSites = await redisRbacRepository.getOrgSites()
  const mine = await organisationsOf(identity)
  const served = mine.find((o) => (orgSites[o] ?? []).includes(site.name))
  if (served) return { id: served, name: '', created: false }
  if (mode === 'domain') {
    const claim = await signUpStore.domain(domainOf(emailOf(identity)))
    if (claim?.verified) {
      await entitle(claim.org, site.name)
      await joinOrganisation(identity, claim.org)
      audit('org.member.added', 'create', identity, { organizationId: claim.org, via: 'sign-up-domain', domain: claim.domain }, site.name)
      return { id: claim.org, name: '', created: false }
    }
  }
  return personalOrganisation(identity, site.name)
}

/**
 * Join one person to one site's sign-up. Idempotent: a second call finds the group and the org in
 * place. `invite`: somebody an org owner invited into an org made by this site's sign-up — no new org,
 * and the site's sign-up may be closed since (the org already belongs to the site).
 */
export async function joinSite(identityId: string, siteName: string, via: JoinVia): Promise<JoinResult> {
  return withRedisLock(`signup-join:${identityId}`, async () => {
    const site = await liveSite(siteName)
    if (!site?.signUp) return { joined: false, site: siteName, reason: site ? 'sign_up_closed' : 'site_not_found' }
    if (site.signUp.roles.length === 0) return { joined: false, site: siteName, reason: 'no_roles' }
    if (via !== 'invite' && !signUpOpen(site)) return { joined: false, site: siteName, reason: 'sign_up_closed' }
    const identity = await kratosService.getIdentity(identityId)
    const email = emailOf(identity)
    if (!isVerified(identity, email)) return { joined: false, site: siteName, reason: 'email_not_verified' }
    if (via !== 'invite' && (await siteSignUpVerdict(site as Site & { signUp: NonNullable<Site['signUp']> }, email))) {
      return { joined: false, site: siteName, reason: 'domain_not_allowed' }
    }
    const group = signUpGroupName(site.name)
    const groups = (await groupsForSubjects([identity.id])).get(identity.id) ?? []
    const newcomer = !groups.includes(group)
    if (newcomer) await addToGroup(identity.id, group, `sign-up:${site.name}`)
    const organization = via === 'invite' ? null : await organisationFor(identity, site as Site & { signUp: NonNullable<Site['signUp']> })
    await signUpStore.clearPending(email, site.name)
    await rbacService.notifyBindingsChanged('signup_joined')
    if (newcomer) audit('site.signup.joined', 'create', identity, { site: site.name, group, via, organizationId: organization?.id ?? null }, site.name)
    return { joined: true, site: site.name, group, organization }
  })
}

/**
 * A Kratos after-hook about this identity (registration, verification): join every site it signed up
 * through, once its address is verified; and somebody invited into an org a sign-up made joins that
 * site too. Never throws: the hook answers 200 whatever happens here.
 */
export async function onIdentityEvent(identityId: string | null, log?: { warn: (o: object, m: string) => void }): Promise<void> {
  if (!identityId) return
  try {
    const identity = await kratosService.getIdentity(identityId)
    const email = emailOf(identity)
    if (!email || !isVerified(identity, email)) return
    for (const p of await signUpStore.pending(email)) await joinSite(identityId, p.site, 'sign-up')
    const bySignUp = await signUpStore.orgSites()
    const sites = new Set((await organisationsOf(identity)).flatMap((o) => bySignUp[o] ?? []))
    for (const site of sites) await joinSite(identityId, site, 'invite')
  } catch (err) {
    log?.warn({ err, identityId }, 'Site sign-up join did not complete')
  }
}

/** The "Continue to <site>" step: a signed-in person joins a site whose sign-up is open. */
export async function continueTo(identityId: string, host: string): Promise<JoinResult> {
  const site = await liveSiteByHost(host.toLowerCase())
  if (!site) return { joined: false, site: host, reason: 'site_not_found' }
  return joinSite(identityId, site.name, 'continue')
}

/** Take one person out of a site's sign-up group (their org and account stay). */
export async function removeMember(siteName: string, identityId: string): Promise<boolean> {
  const group = signUpGroupName(siteName)
  const groups = (await groupsForSubjects([identityId])).get(identityId) ?? []
  if (!groups.includes(group)) return false
  await removeFromGroup(identityId, group)
  await rbacService.notifyBindingsChanged('signup_removed')
  return true
}
