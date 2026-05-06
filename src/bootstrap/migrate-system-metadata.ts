import { redisRbacRepository, type ResourceMetadata } from '../services/redis-rbac.repository.js'
import type { BootstrapLogger } from './types.js'

/**
 * RBAC-driven protection for system resources.
 *
 * Bootstrapped groups and services are tagged with `system: true` in the
 * Redis metadata hashes (`rbac:groups:meta`, `rbac:services:meta`). Routes
 * that mutate them then gate the operation on the actor holding the
 * `rbac:write_system` permission (or being a super_admin via global "*"),
 * instead of relying on a hardcoded list inside jinbe code.
 *
 * Idempotent: only sets metadata that is missing. Existing entries with a
 * different `description` or `createdAt` are left untouched. This lets
 * operators flip a non-system group to system (or vice-versa) by editing
 * Redis directly without bootstrap clobbering it on the next run.
 */
const SYSTEM_GROUP_DESCRIPTIONS: Record<string, string> = {
  super_admins: 'Holders of the global "*" wildcard — full platform admin.',
  admins:      'Per-service admin (jinbe.admin = "*"), no global wildcard.',
  devs:        'Editor role across services.',
  viewers:     'Read-only across services.',
  users:       'Default group for newly registered identities.',
}

const SYSTEM_SERVICE_DESCRIPTIONS: Record<string, string> = {
  jinbe: 'Jinbe API — RBAC management, audit, user lifecycle.',
  kuma:  'Kuma admin UI — RBAC management dashboard.',
}

export async function applySystemMetadataMigration(
  logger: BootstrapLogger,
): Promise<{ groupsMarked: number; servicesMarked: number }> {
  const now = new Date().toISOString()

  let groupsMarked = 0
  for (const [name, description] of Object.entries(SYSTEM_GROUP_DESCRIPTIONS)) {
    if (!(await redisRbacRepository.groupExists(name))) continue
    const existing = await redisRbacRepository.getGroupMetadata(name)
    if (existing?.system === true) continue // already tagged
    const meta: ResourceMetadata = {
      ...(existing ?? {}),
      system: true,
      description: existing?.description ?? description,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    }
    await redisRbacRepository.setGroupMetadata(name, meta)
    groupsMarked++
  }

  let servicesMarked = 0
  for (const [name, description] of Object.entries(SYSTEM_SERVICE_DESCRIPTIONS)) {
    if (!(await redisRbacRepository.serviceExists(name))) continue
    const existing = await redisRbacRepository.getServiceMetadata(name)
    if (existing?.system === true) continue
    const meta: ResourceMetadata = {
      ...(existing ?? {}),
      system: true,
      description: existing?.description ?? description,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    }
    await redisRbacRepository.setServiceMetadata(name, meta)
    servicesMarked++
  }

  if (groupsMarked > 0 || servicesMarked > 0) {
    logger.info(
      { groupsMarked, servicesMarked },
      'System metadata migration: tagged protected resources',
    )
  }

  return { groupsMarked, servicesMarked }
}
