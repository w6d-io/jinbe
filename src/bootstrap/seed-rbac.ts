import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * Seed default RBAC configuration when Redis is empty.
 *
 * Idempotent: skipped entirely if any group already exists.
 *
 * Base groups (naming norm). The global admin tier (`platform-admins`), the
 * org-admin flag (`org_admins`) and the per-service `<svc>-viewer`/`<svc>-admin`
 * groups are seeded by seedDelegation so both fresh installs and schema upgrades
 * converge on the same set.
 *   super_admins → global:[super_admin]   (resolves to `*` via the OPA wildcard rule)
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
  await redisRbacRepository.setGroup('users', {})

  await redisRbacRepository.setRoles('global', { super_admin: ['*'], admin: ['*'] })
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
