import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { needs } from '../policy/route-access.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { badRequestResponseSchema } from '../schemas/response-schemas.js'
import { secondFactorStatus } from './status.js'
import {
  GROUP_NAME, MAX_GROUPS, getDefaultSecondFactorGroups, getGroupSecondFactorFlags, getSecondFactorGroups, getSecondFactorSetting,
  setGroupSecondFactor, setSecondFactorGroups,
} from './settings.js'
import { enforcing } from '../policy/declared-routes.js'
import { callerRights, demandPermissions } from '../middleware/require-permission.js'
import { allows } from '../services/user-permissions.js'
import { sitesRepository } from '../sites/repository.js'
import { groupSecondFactorJsonSchema, secondFactorMapJsonSchema } from '../schemas/second-factor.schema.js'
import {
  oauthGrantWindowHours, PERSONAL_KEY_MAX_AGE_DAYS, RULES, STEP_UP_MAX_AGE_MIN,
  groupSecondFactor, permissionRules, roleRules, siteSecondFactor, type GroupSecondFactor,
} from './requirements.js'

const groupsBody = {
  type: 'object',
  properties: {
    groups: { type: 'array', items: { type: 'string' } },
    defaultGroups: { type: 'array', items: { type: 'string' } },
  },
}

/**
 * GET /api/public/second-factor — the signed-in visitor's own 2FA status, for login-ui (status.ts).
 * No session gate (require-auth PUBLIC_ROUTES): it reads the visitor's own Kratos cookie itself and
 * answers about nobody else. Rate limited per IP.
 */
export async function secondFactorPublicRoutes(fastify: FastifyInstance) {
  fastify.get('/', {
    config: { access: 'public', rateLimit: { max: 120, timeWindow: '1 minute' } },
    schema: {
      description:
        'The signed-in visitor (own Kratos session cookie) must set up or prove a second factor before continuing? ' +
        '{secondFactorRequired, hasSecondFactor, methods, aal}; 401 without a session; 503 policy_unavailable | identity_unavailable.',
      tags: ['second-factor'],
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    reply.header('cache-control', 'private, no-store')
    try {
      return await secondFactorStatus(request.headers.cookie)
    } catch (err) {
      const e = err as { statusCode?: number; code?: string; message?: string }
      if (!e.statusCode) throw err
      return reply.status(e.statusCode).send({ error: e.code, message: e.message })
    }
  })
}

/**
 * The groups switched to "Members must use 2FA" (settings.ts), as one list — the settings screen's view
 * of the per-group switch.
 *   GET /api/admin/settings/second-factor — settings:read
 *   PUT /api/admin/settings/second-factor — groups.mfa:write (super admin alone, owner decision
 *       2026-09-30) + a recent second factor; listed groups on, every other group off.
 */
export async function secondFactorSettingsRoutes(fastify: FastifyInstance) {
  fastify.get('/second-factor', {
    ...needs('settings:read'),
    schema: {
      description: 'Groups whose members must set up a second factor at sign-in and hold aal2 on every permission-carrying route.',
      tags: ['second-factor'],
      response: { 200: groupsBody },
    },
  }, async () => ({ groups: await getSecondFactorGroups(), defaultGroups: await getDefaultSecondFactorGroups() }))

  fastify.put('/second-factor', {
    ...needs('groups.mfa:write'),
    schema: {
      description:
        'Replace the groups whose members must use two-step sign-in. Every name must be an existing group; an empty list ' +
        'turns every group off. Sets each group\'s "Members must use 2FA" switch (listed on, others off); published to OPA as data.second_factor. ' +
        'groups.mfa:write (super admin alone), with a second factor proven within 15 minutes.',
      tags: ['second-factor'],
      body: {
        type: 'object',
        required: ['groups'],
        additionalProperties: false,
        properties: { groups: { type: 'array', maxItems: MAX_GROUPS, items: { type: 'string', maxLength: 100 } } },
      },
      response: { 200: groupsBody, 400: badRequestResponseSchema },
    },
  }, async (request, reply) => {
    const { groups } = request.body as { groups: string[] }
    const malformed = groups.filter((g) => !GROUP_NAME.test(g))
    if (malformed.length) {
      return reply.status(400).send({ error: 'invalid_group', message: `Not a group name: ${malformed.join(', ')}` })
    }
    const known = await redisRbacRepository.getGroups()
    const unknown = groups.filter((g) => !(g in known))
    if (unknown.length) {
      return reply.status(400).send({ error: 'unknown_group', message: `No such group: ${unknown.join(', ')}` })
    }
    const before = await getSecondFactorGroups()
    const saved = await setSecondFactorGroups(groups)
    const a = auditActor(request)
    auditEventService.emit({
      category: 'rbac', kind: 'change', verb: 'update', target: 'second-factor-groups',
      result: 'applied', severity: 'high',
      actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { before, after: saved },
    }).catch(() => {})
    return { groups: saved, defaultGroups: await getDefaultSecondFactorGroups() }
  })
}

/** groups:read or sites:read: either one is enough to be shown the badges (each section asks its own). */
const readsGroupsOrSites = enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
  const rights = await callerRights(request, reply)
  if (!rights) return reply
  if (allows(rights.permissions, 'groups:read') || allows(rights.permissions, 'sites:read')) return
  await demandPermissions(request, reply, ['groups:read'])
  return reply
}, 'groups:read')

/** Each site as visitors meet it: its applied version, or the saved one (applied: false) before any apply. */
async function siteBars() {
  const records = await sitesRepository.list()
  return Promise.all(records.map(async (r) => {
    const applied = r.applied ? (await sitesRepository.version(r.site.name, r.applied.version))?.site ?? null : null
    return {
      name: r.site.name,
      displayName: r.site.displayName,
      host: r.site.address.host,
      applied: applied !== null,
      secondFactor: siteSecondFactor(applied ?? r.site),
    }
  }))
}

/**
 * GET /api/admin/rbac/second-factor-map — every rule that asks for a second factor and what it applies
 * to, in one read, for the console's badges and the MCP (requirements.ts). Describes; decides nothing.
 * Groups need groups:read and sites need sites:read (null otherwise); the rules, the catalogue's step-ups
 * and the roles are the same for every signed-in person. A section that cannot be read is null and
 * named in `unavailable`, never an empty list that would read as "nothing required".
 */
export async function secondFactorRbacRoutes(fastify: FastifyInstance) {
  fastify.get('/second-factor-map', {
    ...needs('groups:read'),
    preHandler: readsGroupsOrSites,
    schema: {
      description:
        'Every second-factor rule and what it applies to: sign-in groups (group_sign_in), groups that need enrolment before ' +
        'joining, permissions needing a recent second factor (step_up, with personal-key stand-in and four-eyes), staff roles, ' +
        "each site's two-step bar (site_login). groups:read or sites:read; groups need groups:read and sites sites:read.",
      tags: ['second-factor'],
      response: { 200: secondFactorMapJsonSchema },
    },
  }, async (request, reply) => {
    const rights = await callerRights(request, reply)
    if (!rights) return reply
    const unavailable: string[] = []
    const setting = await getSecondFactorSetting().catch(() => null)
    if (!setting) unavailable.push('signIn')

    let groups: Array<{ name: string; secondFactor: GroupSecondFactor }> | null = null
    if (allows(rights.permissions, 'groups:read')) {
      try {
        const flags = await getGroupSecondFactorFlags()
        groups = [...flags.keys()].sort().map((name) => ({ name, secondFactor: groupSecondFactor(flags.get(name)) }))
      } catch {
        unavailable.push('groups')
      }
    }

    let sites: Awaited<ReturnType<typeof siteBars>> | null = null
    if (allows(rights.permissions, 'sites:read')) {
      try {
        sites = await siteBars()
      } catch {
        unavailable.push('sites')
      }
    }

    const oauthHours = await oauthGrantWindowHours()
    reply.header('cache-control', 'private, no-store')
    return {
      rules: RULES,
      limits: { stepUpMaxAgeMin: STEP_UP_MAX_AGE_MIN, personalKeyMaxAgeDays: PERSONAL_KEY_MAX_AGE_DAYS, oauthGrantMaxAgeHours: oauthHours },
      signIn: setting ? { groups: setting.groups, explicit: setting.explicit } : null,
      groups,
      permissions: permissionRules(oauthHours),
      roles: roleRules(),
      sites,
      organizations: { rules: [], note: 'No organisation-level second-factor rule exists: the platform groups and each site decide.' },
      unavailable,
    }
  })

  /**
   * PUT /api/admin/rbac/groups/:name/second-factor {required} — one group's "Members must use 2FA"
   * switch. groups.mfa:write (super admin alone), with a recent second factor: it decides who may sign in without one and
   * who may join without one. Audited with the value before and after.
   */
  fastify.put('/groups/:name/second-factor', {
    ...needs('groups.mfa:write'),
    schema: {
      description:
        'Switch a group\'s "Members must use 2FA": on, its members need two-step sign-in (aal2) on every permission-carrying ' +
        'route and nobody joins it before enrolling a second factor. Published to OPA as data.second_factor. ' +
        'groups.mfa:write (super admin alone), with a second factor proven within 15 minutes.',
      tags: ['second-factor'],
      params: { type: 'object', required: ['name'], properties: { name: { type: 'string', maxLength: 64 } } },
      body: { type: 'object', required: ['required'], additionalProperties: false, properties: { required: { type: 'boolean' } } },
      response: {
        200: { type: 'object', properties: { name: { type: 'string' }, secondFactor: groupSecondFactorJsonSchema } },
        400: badRequestResponseSchema,
        404: badRequestResponseSchema,
        409: badRequestResponseSchema,
      },
    },
  }, async (request, reply) => {
    const { name } = request.params as { name: string }
    const { required } = request.body as { required: boolean }
    if (!GROUP_NAME.test(name)) return reply.status(400).send({ error: 'invalid_group', message: `Not a group name: ${name}` })
    const known = await redisRbacRepository.getGroups()
    if (!(name in known)) return reply.status(404).send({ error: 'unknown_group', message: `No such group: ${name}` })
    let set: Awaited<ReturnType<typeof setGroupSecondFactor>>
    try {
      set = await setGroupSecondFactor(name, required)
    } catch (err) {
      const e = err as { statusCode?: number; code?: string; message?: string }
      if (e.code === 'second_factor_locked') return reply.status(409).send({ error: e.code, message: e.message })
      throw err
    }
    const { before, after } = set
    const a = auditActor(request)
    auditEventService.emit({
      category: 'rbac', kind: 'change', verb: 'update', target: 'second-factor-groups',
      result: 'applied', severity: 'high',
      actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { group: name, before: before ? { required: before.required, explicit: before.explicit } : null, after: { required: after } },
    }).catch(() => {})
    return { name, secondFactor: groupSecondFactor((await getGroupSecondFactorFlags()).get(name)) }
  })
}
