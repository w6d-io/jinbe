import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * Seed default RBAC configuration when Redis is empty.
 *
 * Idempotent: skipped entirely if any group already exists.
 *
 * Default groups:
 *   super_admins → global:[super_admin]   (matches `*` permission via OPA wildcard rule)
 *   admins       → jinbe:[admin]
 *   devs         → jinbe:[editor]
 *   viewers      → jinbe:[viewer]
 *   users        → {} (placeholder for newly registered users)
 */
export async function seedRbacDefaults(logger: BootstrapLogger): Promise<{ seeded: boolean }> {
  const groups = await redisRbacRepository.getGroups()
  if (Object.keys(groups).length > 0) {
    logger.info({ groupCount: Object.keys(groups).length }, 'Redis has groups — skipping RBAC seed')
    return { seeded: false }
  }

  logger.info('Redis empty — seeding default RBAC configuration')

  await redisRbacRepository.setGroup('super_admins', { global: ['super_admin'] })
  await redisRbacRepository.setGroup('admins', { jinbe: ['admin'] })
  await redisRbacRepository.setGroup('devs', { jinbe: ['editor'] })
  await redisRbacRepository.setGroup('viewers', { jinbe: ['viewer'] })
  await redisRbacRepository.setGroup('users', {})

  await redisRbacRepository.setRoles('global', { super_admin: ['*'] })
  await redisRbacRepository.setRoles('jinbe', {
    admin: ['*'],
    operator: [
      'clusters:list', 'clusters:read', 'clusters:create', 'clusters:update', 'clusters:delete',
      'databases:list', 'databases:read', 'databases:create', 'databases:update', 'databases:delete',
    ],
    editor: ['databases:list', 'databases:read', 'databases:create', 'databases:update', 'databases:delete'],
    viewer: ['databases:list', 'databases:read'],
  })

  await redisRbacRepository.addService('jinbe')
  await redisRbacRepository.addService('global')

  await redisRbacRepository.invalidateBundleEtag()
  logger.info('Default RBAC data seeded (groups, roles, services)')
  return { seeded: true }
}
