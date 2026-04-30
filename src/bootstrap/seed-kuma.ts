import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * Seed the `kuma` RBAC service entry (admin UI logical name).
 *
 * Note on naming: in Kubernetes the service is `<release>-admin-ui` but in the
 * RBAC model the logical service name is `kuma`. This mismatch is intentional —
 * `kuma` is the dashboard product name and is what OPA policies reference.
 * The actual upstream URL is set via the Oathkeeper rule `kuma-app`.
 *
 * Idempotent: if the kuma service already exists, no work is done.
 *
 * Group propagation: when seeding for the first time, kuma roles are propagated
 * into existing groups. devs deliberately do NOT receive a kuma role.
 */
export async function seedKumaService(logger: BootstrapLogger): Promise<{ seeded: boolean; routeMapSeeded: boolean }> {
  let seeded = false
  let routeMapSeeded = false

  const kumaExists = await redisRbacRepository.serviceExists('kuma')
  if (!kumaExists) {
    await redisRbacRepository.addService('kuma')
    await redisRbacRepository.setRoles('kuma', {
      admin: ['*'],
      viewer: ['read'],
    })

    const groups = await redisRbacRepository.getGroups()
    if (groups['super_admins']) {
      groups['super_admins']['kuma'] = ['admin']
      await redisRbacRepository.setGroup('super_admins', groups['super_admins'])
    }
    if (groups['admins']) {
      groups['admins']['kuma'] = ['admin']
      await redisRbacRepository.setGroup('admins', groups['admins'])
    }
    if (groups['viewers']) {
      groups['viewers']['kuma'] = ['viewer']
      await redisRbacRepository.setGroup('viewers', groups['viewers'])
    }

    logger.info('Kuma service seeded in Redis')
    seeded = true
  }

  const kumaRouteMap = await redisRbacRepository.getRouteMap('kuma')
  if (!kumaRouteMap) {
    // Kuma is a pure frontend SPA — no own API backend.
    // All /api/... calls from kuma are proxied to jinbe and protected by
    // jinbe's route_map. Broad wildcards (/:any*) must NOT be here — they
    // would make all jinbe routes "public" via the kuma OPA bundle.
    await redisRbacRepository.setRouteMap('kuma', { rules: [] })
    logger.info('Kuma route_map seeded in Redis')
    routeMapSeeded = true
  }

  return { seeded, routeMapSeeded }
}
