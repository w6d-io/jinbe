import { kratosService, KratosApiError } from '../services/kratos.service.js'
import type { BootstrapAdmin, BootstrapLogger } from './types.js'

/**
 * Create the default admin Kratos identity if it doesn't already exist.
 *
 * Idempotent across all known states:
 * - Identity already present (listed by credentials_identifier) → skip.
 * - Identity creation succeeds → log and return.
 * - Identity creation returns 409 (race or filter inconsistency) → swallow.
 * - Other errors → propagate.
 *
 * The created identity is in the `super_admins` group via metadata_admin and is
 * marked verified so the user can log in immediately.
 */
export async function seedDefaultAdmin(
  admin: BootstrapAdmin,
  logger: BootstrapLogger,
): Promise<{ created: boolean }> {
  try {
    const { identities } = await kratosService.listIdentities(1, undefined, admin.email)
    if (identities.length > 0) {
      logger.debug({ email: admin.email, id: identities[0].id }, 'Admin identity already exists — skipping')
      return { created: false }
    }

    const identity = await kratosService.createIdentity({
      schema_id: 'default',
      state: 'active',
      traits: { email: admin.email, name: admin.name },
      credentials: { password: { config: { password: admin.password } } },
      metadata_admin: { groups: ['super_admins'] },
      verifiable_addresses: [
        { value: admin.email, verified: true, via: 'email', status: 'completed' },
      ],
    })

    logger.info({ email: admin.email, id: identity.id }, 'Default admin identity created')
    return { created: true }
  } catch (err) {
    if (err instanceof KratosApiError && err.statusCode === 409) {
      logger.info({ email: admin.email }, 'Admin identity already exists (Kratos 409) — skipping')
      return { created: false }
    }
    throw err
  }
}
