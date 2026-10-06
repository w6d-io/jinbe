import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { needs } from '../policy/route-access.js'
import { kratosService } from '../services/kratos.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { addToGroup, groupsForSubjects, membersOfGroup, removeFromGroup } from '../services/organisation-store.js'
import { getGroupSecondFactorFlags } from '../second-factor/settings.js'
import { actorOf, handle, nameOf, parse } from './http.js'
import { siteError } from './checks.js'
import { liveSite } from './login.js'
import { signUpGroupName, type Site } from './schemas.js'

/**
 * People in a site's own groups — `<site>-…`, the platform groups its intent binds to its roles (the
 * sign-up group included). Whoever builds the site (sites.members:write) decides who uses it, from
 * the site's page or the MCP.
 *
 * Why this skips the holding rule (services/rbac-escalation-guard.ts): such a group carries only this
 * site's roles, which its published intent defines; a site's permissions count only on its own routes,
 * never on jinbe's or another site's. A group that binds anything beyond this one site is refused here
 * (it is managed in Access → Groups, under the holding rule). Second-factor groups still refuse a
 * person without one, as everywhere else.
 */

const TAGS = ['sites', 'site-members']
const MAX_LISTED = 500
const groupName = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/)
const addBody = z.object({ group: groupName, email: z.string().trim().toLowerCase().email().max(254) }).strict()
const removeParams = z.object({ name: z.string(), group: groupName, identityId: z.string().uuid() })

/** The site's own groups in its published intent: `<site>-…` platform groups and the sign-up group. */
export function siteGroupsOf(site: Site): Record<string, string[]> {
  const prefix = `${site.name}-`
  const out: Record<string, string[]> = {}
  for (const [group, roles] of Object.entries(site.groups.platform)) if (group.startsWith(prefix)) out[group] = roles
  if (site.signUp && site.signUp.roles.length) out[signUpGroupName(site.name)] = site.signUp.roles
  return out
}

/** The published group, only when it binds this site and nothing else. */
async function ownedGroup(site: Site, group: string): Promise<string[]> {
  const roles = siteGroupsOf(site)[group]
  if (!roles) throw siteError(404, 'not_a_site_group', `'${group}' is not one of ${site.name}'s own groups (${site.name}-…, in its published version)`)
  const def = (await redisRbacRepository.getGroups())[group]
  if (!def) throw siteError(409, 'not_published', `'${group}' exists once the version that defines it is published`)
  const apps = Object.keys(def)
  if (apps.length !== 1 || apps[0] !== site.name) throw siteError(409, 'group_beyond_site', `'${group}' also gives access outside ${site.name}: manage it in Access → Groups`)
  return roles
}

async function publishedSite(name: string): Promise<Site> {
  const site = await liveSite(name)
  if (!site) throw siteError(404, 'not_published', `${name} has no published version yet`)
  return site
}

function audit(event: 'site.members.added' | 'site.members.removed', verb: string, site: string, group: string, who: { id: string; email: string | null }, actor: ReturnType<typeof actorOf>) {
  Promise.resolve()
    .then(() => auditEventService.emit({
      category: 'access',
      kind: 'change',
      verb,
      target: `user:${who.email ?? who.id}`,
      targetType: 'user',
      targetId: who.id,
      service: site,
      result: 'ok',
      actor: { id: actor.id ?? null, email: actor.email ?? null, ip: actor.ip ?? null, ua: actor.ua ?? null, sessionId: actor.sessionId ?? null, ...(actor.act ? { act: actor.act } : {}) },
      requestId: actor.requestId ?? null,
      v1Event: event,
      details: { site, group, email: who.email },
      source: 'jinbe-api',
    }))
    .catch(() => {})
}

/** Under /sites. */
export async function siteMemberRoutes(fastify: FastifyInstance) {
  fastify.get('/:name/members', {
    ...needs('sites.members:write', { alsoAccepts: ['users:read'] }),
    schema: { description: "The site's own groups (<site>-…, the sign-up group included), the roles each gives on this site, and who is in each (at most 500 listed per group; total counts everyone)", tags: TAGS },
  }, handle(async (request) => {
    const site = await publishedSite(nameOf(request))
    const groups = await Promise.all(Object.entries(siteGroupsOf(site)).map(async ([group, roles]) => {
      const ids = await membersOfGroup(group)
      const people = await Promise.all(ids.slice(0, MAX_LISTED).map(async (id) => {
        try {
          const identity = await kratosService.getIdentityCached(id, { maxAgeMs: 60_000 })
          const t = (identity.traits ?? {}) as { email?: string; name?: string }
          return { id, email: t.email ?? null, name: t.name ?? null }
        } catch {
          return { id, email: null, name: null }
        }
      }))
      return { group, roles, signUp: group === signUpGroupName(site.name), total: ids.length, members: people }
    }))
    return { site: site.name, groups }
  }))

  fastify.post('/:name/members', {
    ...needs('sites.members:write'),
    schema: { description: "Add somebody who has an account to one of the site's own groups: they get its roles on this site. A group that requires two-step sign-in refuses a person without a second factor", tags: TAGS },
  }, handle(async (request, reply) => {
    const site = await publishedSite(nameOf(request))
    const { group, email } = parse(addBody, request.body)
    await ownedGroup(site, group)
    const identity = await kratosService.findByEmail(email)
    if (!identity) throw siteError(404, 'no_account', `Nobody has an account with ${email}: they sign up (when the site allows it), or support invites them`)
    const flags = await getGroupSecondFactorFlags()
    if (flags.get(group)?.required && !(await kratosService.hasMFA(identity.id))) {
      throw siteError(422, 'mfa_required', `'${group}' requires two-step sign-in: ${email} must set up a second factor first`)
    }
    const current = (await groupsForSubjects([identity.id])).get(identity.id) ?? []
    if (current.includes(group)) return reply.status(200).send({ added: false, group, id: identity.id })
    await addToGroup(identity.id, group, `site:${site.name}`)
    await rbacService.notifyBindingsChanged('site_member_added')
    audit('site.members.added', 'create', site.name, group, { id: identity.id, email }, actorOf(request))
    return reply.status(201).send({ added: true, group, id: identity.id })
  }))

  fastify.delete('/:name/members/:group/:identityId', {
    ...needs('sites.members:write'),
    schema: { description: "Take somebody out of one of the site's own groups. Their account stays; they lose that group's roles on this site", tags: TAGS },
  }, handle(async (request) => {
    const { group, identityId } = parse(removeParams, request.params)
    const site = await publishedSite(nameOf(request))
    await ownedGroup(site, group)
    const current = (await groupsForSubjects([identityId])).get(identityId) ?? []
    if (!current.includes(group)) throw siteError(404, 'not_a_member', `This person is not in '${group}'`)
    await removeFromGroup(identityId, group)
    await rbacService.notifyBindingsChanged('site_member_removed')
    audit('site.members.removed', 'delete', site.name, group, { id: identityId, email: null }, actorOf(request))
    return { removed: true }
  }))
}
