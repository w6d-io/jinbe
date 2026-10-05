import { randomBytes } from 'node:crypto'
import { resolveTxt } from 'node:dns/promises'
import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { needs, open } from '../../policy/route-access.js'
import { kratosService } from '../../services/kratos.service.js'
import { membersOfGroup, organisationsById } from '../../services/organisation-store.js'
import { auditEventService } from '../../services/audit-event.service.js'
import { actorOf, handle, nameOf, parse } from '../http.js'
import { siteError } from '../checks.js'
import { signUpGroupName } from '../schemas.js'
import { continueTo, removeMember } from './service.js'
import { signUpStore, type DomainClaim } from './store.js'

/**
 * Sign-up routes:
 *   /sites/:name/sign-up/members        who joined a site's sign-up group; remove one, or everyone
 *   /me/sign-up/continue                the "Continue to <site>" step (a signed-in person joins)
 *   /organizations/:organizationId/domains   an org's email domains, proven by a DNS TXT record,
 *                                       which sign-up `orgs: domain` joins people into
 */

const TAGS = ['sites', 'sign-up']
const MEMBERS_MAX = 1000
/** The TXT record an org publishes to prove a domain: `_auth-verify.<domain>  "auth-verify=<token>"`. */
export const DOMAIN_RECORD_PREFIX = '_auth-verify'
const DOMAIN = z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/, 'a domain like example.com')
const identityParams = z.object({ name: z.string(), identityId: z.string().uuid() })
const continueBody = z.object({ host: z.string().trim().toLowerCase().min(1).max(253) }).strict()
const orgParams = z.object({ organizationId: z.string().uuid() })
const domainParams = orgParams.extend({ domain: DOMAIN })
const membersQuery = z.object({ limit: z.coerce.number().int().min(1).max(MEMBERS_MAX).default(200) })

function auditSignUp(verb: string, event: 'site.signup.member_removed' | 'org.domain.claimed' | 'org.domain.verified' | 'org.domain.removed', target: string, actor: ReturnType<typeof actorOf>, details: Record<string, unknown>) {
  Promise.resolve()
    .then(() => auditEventService.emit({
      category: 'access',
      kind: 'change',
      verb,
      target,
      result: 'ok',
      actor: { id: actor.id ?? null, email: actor.email ?? null, ip: actor.ip ?? null, ua: actor.ua ?? null, sessionId: actor.sessionId ?? null },
      requestId: actor.requestId ?? null,
      v1Event: event,
      details,
      source: 'jinbe-api',
    }))
    .catch(() => {})
}

/** Under /sites. */
export async function siteSignUpRoutes(fastify: FastifyInstance) {
  fastify.get('/:name/sign-up/members', {
    ...needs('users:read'),
    schema: { description: "Who joined this site's sign-up group (`<site>-users`): id, email, name, joined organizations. At most `limit` (200 by default, 1000 at most); `total` counts everyone", tags: TAGS },
  }, handle(async (request) => {
    const name = nameOf(request)
    const { limit } = parse(membersQuery, request.query)
    const ids = await membersOfGroup(signUpGroupName(name))
    const shown = ids.slice(0, limit)
    const people = await Promise.all(shown.map(async (id) => {
      try {
        const identity = await kratosService.getIdentityCached(id, { maxAgeMs: 60_000 })
        const traits = (identity.traits ?? {}) as { email?: string; name?: string }
        return { id, email: traits.email ?? null, name: traits.name ?? null, createdAt: identity.created_at ?? null, organizations: [identity.organization_id].filter(Boolean) as string[] }
      } catch {
        return { id, email: null, name: null, createdAt: null, organizations: [] as string[] }
      }
    }))
    const orgIds = [...new Set(people.flatMap((p) => p.organizations))]
    const names = new Map((await organisationsById(orgIds).catch(() => [])).map((o) => [o.id, o.name]))
    return {
      site: name,
      group: signUpGroupName(name),
      total: ids.length,
      members: people.map((p) => ({ ...p, organizations: p.organizations.map((id) => ({ id, name: names.get(id) ?? null })) })),
    }
  }))

  fastify.delete('/:name/sign-up/members/:identityId', {
    ...needs('sites.signup:revoke'),
    schema: { description: "Take one person out of this site's sign-up group. Their account and organizations stay; they lose what the group gave on this site", tags: TAGS },
  }, handle(async (request) => {
    const { name, identityId } = parse(identityParams, request.params)
    const removed = await removeMember(name, identityId)
    if (!removed) throw siteError(404, 'not_a_member', "This person is not in the site's sign-up group")
    auditSignUp('delete', 'site.signup.member_removed', `user:${identityId}`, actorOf(request), { site: name, identityId })
    return { removed: true }
  }))

  fastify.delete('/:name/sign-up/members', {
    ...needs('sites.signup:revoke', { stepUp: true }),
    schema: { description: "Take everybody out of this site's sign-up group (close sign-up first, or new people keep joining). Second factor within 15 minutes", tags: TAGS },
  }, handle(async (request) => {
    const name = nameOf(request)
    const ids = await membersOfGroup(signUpGroupName(name))
    let removed = 0
    for (const id of ids) if (await removeMember(name, id)) removed++
    auditSignUp('delete', 'site.signup.member_removed', `site:${name}`, actorOf(request), { site: name, everyone: true, removed })
    return { removed }
  }))
}

/** Under /me/sign-up. */
export async function signUpSelfRoutes(fastify: FastifyInstance) {
  fastify.post('/continue', {
    ...open('self'),
    schema: { description: "Continue to <site>: the signed-in person joins the site at `host` when its sign-up is open to them (verified address, allowed domain). Idempotent. `joined: false` says why not", tags: TAGS },
  }, handle(async (request) => {
    const id = request.userContext?.id
    if (!id) throw siteError(401, 'unauthenticated', 'Sign in first')
    return continueTo(id, parse(continueBody, request.body).host)
  }))
}

const view = (c: DomainClaim, withToken: boolean) => ({
  domain: c.domain,
  verified: c.verified,
  claimedAt: c.claimedAt,
  verifiedAt: c.verifiedAt ?? null,
  ...(withToken && !c.verified ? { record: { name: `${DOMAIN_RECORD_PREFIX}.${c.domain}`, type: 'TXT', value: `auth-verify=${c.token}` } } : {}),
})

/** Under /organizations/:organizationId. */
export async function orgDomainRoutes(fastify: FastifyInstance) {
  const ORG = { org: 'organizationId' }

  fastify.get('/domains', {
    ...needs('org.members:read', ORG),
    schema: { description: "This organization's email domains: verified ones bring people who sign up with that domain into it (sites whose sign-up joins by domain); an unverified one shows the TXT record to publish", tags: TAGS },
  }, handle(async (request) => {
    const { organizationId } = parse(orgParams, request.params)
    return { domains: (await signUpStore.domainsOf(organizationId)).map((c) => view(c, true)) }
  }))

  fastify.post('/domains', {
    ...needs('org.members:write', ORG),
    schema: { description: 'Claim an email domain for this organization. Returns the TXT record to publish; nothing is joined by domain until it is verified. A domain another organization has verified is refused', tags: TAGS },
  }, handle(async (request, reply) => {
    const { organizationId } = parse(orgParams, request.params)
    const { domain } = parse(z.object({ domain: DOMAIN }).strict(), request.body)
    const existing = await signUpStore.domain(domain)
    if (existing?.org === organizationId) return reply.status(200).send(view(existing, true))
    if (existing?.verified) throw siteError(409, 'domain_taken', 'Another organization has verified this domain')
    const claim: DomainClaim = { domain, org: organizationId, token: randomBytes(16).toString('hex'), verified: false, claimedAt: new Date().toISOString() }
    await signUpStore.putDomain(claim)
    auditSignUp('create', 'org.domain.claimed', `org:${organizationId}`, actorOf(request), { organizationId, domain })
    return reply.status(201).send(view(claim, true))
  }))

  fastify.post('/domains/:domain/verify', {
    ...needs('org.members:write', ORG),
    schema: { description: `Check the domain's TXT record (${DOMAIN_RECORD_PREFIX}.<domain> = auth-verify=<token>) and mark the domain verified when it is there`, tags: TAGS },
  }, handle(async (request) => {
    const { organizationId, domain } = parse(domainParams, request.params)
    const claim = await signUpStore.domain(domain)
    if (!claim || claim.org !== organizationId) throw siteError(404, 'not_claimed', 'This organization has not claimed that domain')
    if (claim.verified) return view(claim, false)
    let records: string[] = []
    try {
      records = (await resolveTxt(`${DOMAIN_RECORD_PREFIX}.${domain}`)).map((chunks) => chunks.join(''))
    } catch {
      records = []
    }
    if (!records.includes(`auth-verify=${claim.token}`)) {
      throw siteError(422, 'record_not_found', `No TXT record ${DOMAIN_RECORD_PREFIX}.${domain} with the expected value yet (DNS can take a few minutes)`)
    }
    const verified: DomainClaim = { ...claim, verified: true, verifiedAt: new Date().toISOString() }
    await signUpStore.putDomain(verified)
    auditSignUp('update', 'org.domain.verified', `org:${organizationId}`, actorOf(request), { organizationId, domain })
    return view(verified, false)
  }))

  fastify.delete('/domains/:domain', {
    ...needs('org.members:write', ORG),
    schema: { description: 'Release a domain: people who sign up with it no longer join this organization (those who did stay)', tags: TAGS },
  }, handle(async (request) => {
    const { organizationId, domain } = parse(domainParams, request.params)
    const claim = await signUpStore.domain(domain)
    if (!claim || claim.org !== organizationId) throw siteError(404, 'not_claimed', 'This organization has not claimed that domain')
    await signUpStore.removeDomain(domain)
    auditSignUp('delete', 'org.domain.removed', `org:${organizationId}`, actorOf(request), { organizationId, domain })
    return { removed: true }
  }))
}
