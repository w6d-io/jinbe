import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * What a support desk may do to a user: fix their name and address, see and end their sessions, send
 * them a recovery mail or a sign-in link. Not create, delete, hand out groups, or touch roles, groups
 * or sites.
 */
export const SUPPORT_PERMISSIONS = [
  'users:read',
  'users:update',
  'users:update_email',
  'sessions:read',
  'sessions:revoke',
  'users:recovery',
  'users:send_login_link',
] as const

/**
 * Seeds role `support` in the jinbe service and group `support` = { jinbe: [support] }.
 *
 * Idempotent and additive: an existing role or group of that name is the operator's and is left
 * exactly as it is — a re-run never widens or narrows what somebody decided. The jinbe service must
 * exist; without it there is nothing to hold the role.
 */
export async function seedSupport(logger: BootstrapLogger): Promise<{ seeded: string[] }> {
  const seeded: string[] = []

  if (!(await redisRbacRepository.serviceExists('jinbe'))) {
    logger.warn('[seed-support] jinbe service absent — skipping the support role')
    return { seeded }
  }

  const roles = (await redisRbacRepository.getRoles('jinbe')) ?? {}
  if (!roles['support']) {
    roles['support'] = [...SUPPORT_PERMISSIONS]
    await redisRbacRepository.setRoles('jinbe', roles)
    seeded.push('role:jinbe.support')
  }

  if (!(await redisRbacRepository.getGroup('support'))) {
    await redisRbacRepository.setGroup('support', { jinbe: ['support'] })
    await redisRbacRepository.setGroupMetadata('support', {
      description: 'Support desk: edit a user\'s name and email, see and revoke sessions, send recovery and sign-in links.',
    })
    seeded.push('group:support')
  }

  if (seeded.length > 0) {
    await redisRbacRepository.invalidateBundleEtag()
    logger.info({ seeded, permissions: SUPPORT_PERMISSIONS }, '[seed-support] support role and group seeded')
  } else {
    logger.debug('[seed-support] support role and group already present — no work')
  }
  return { seeded }
}
