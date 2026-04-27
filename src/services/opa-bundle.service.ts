import { createGzip } from 'node:zlib'
import { pack } from 'tar-stream'
import { redisRbacRepository } from './redis-rbac.repository.js'
import { kratosService } from './kratos.service.js'

/**
 * OPA Bundle Service
 *
 * Builds and serves OPA bundles (tar.gz) containing:
 * - rbac.rego (policy)
 * - data.json (all RBAC data: bindings, groups, roles, route_maps)
 *
 * OPA replicas pull this bundle independently — solves HA data distribution.
 * Supports ETag for efficient polling (304 Not Modified).
 */
class OpaBundleService {
  private cachedBundle: Buffer | null = null
  private cachedEtag: string | null = null

  /**
   * Get the OPA bundle, building if needed
   * Returns null if etag matches (304)
   */
  async getBundle(ifNoneMatch?: string): Promise<{ buffer: Buffer; etag: string } | null> {
    const currentEtag = await redisRbacRepository.getBundleEtag()

    // ETag match — no changes
    if (ifNoneMatch && currentEtag && ifNoneMatch === currentEtag) {
      return null
    }

    // Return cached if etag hasn't changed
    if (this.cachedBundle && this.cachedEtag === currentEtag) {
      return { buffer: this.cachedBundle, etag: this.cachedEtag! }
    }

    // Build fresh bundle
    const bundle = await this.buildBundle()
    const etag = currentEtag || `${Date.now()}`

    this.cachedBundle = bundle
    this.cachedEtag = etag

    return { buffer: bundle, etag }
  }

  /**
   * Build the OPA bundle tar.gz
   */
  private async buildBundle(): Promise<Buffer> {
    // Fetch all data
    const [rego, rbacData, bindings] = await Promise.all([
      redisRbacRepository.getRego(),
      redisRbacRepository.getAllForBundle(),
      this.getBindings(),
    ])

    // Build data.json matching rbac.rego expectations
    const data = {
      bindings: {
        group_membership: bindings.group_membership,
        emails: bindings.emails,
        groups: rbacData.groups,
      },
      roles: rbacData.roles,
      route_map: rbacData.routeMaps,
    }

    const regoContent = rego || '# No policy loaded\npackage rbac\ndefault allow = false\n'
    const dataContent = JSON.stringify(data, null, 2)

    // Create tar.gz
    return this.createTarGz([
      { name: 'rbac.rego', content: regoContent },
      { name: 'data.json', content: dataContent },
    ])
  }

  /**
   * Get bindings from Kratos
   */
  private async getBindings(): Promise<{ group_membership: Record<string, string[]>; emails: Record<string, unknown> }> {
    try {
      const identitiesWithGroups = await kratosService.getAllIdentitiesWithGroups()
      const group_membership: Record<string, string[]> = {}
      for (const [email, groups] of identitiesWithGroups) {
        group_membership[email] = groups
      }
      return { group_membership, emails: {} }
    } catch (err) {
      console.error('[opa-bundle] Failed to fetch Kratos bindings:', err)
      return { group_membership: {}, emails: {} }
    }
  }

  /**
   * Create a tar.gz buffer from entries
   */
  private createTarGz(entries: Array<{ name: string; content: string }>): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const p = pack()
      const gzip = createGzip()
      const chunks: Buffer[] = []

      gzip.on('data', (chunk: Buffer) => chunks.push(chunk))
      gzip.on('end', () => resolve(Buffer.concat(chunks)))
      gzip.on('error', reject)

      p.pipe(gzip)

      for (const entry of entries) {
        const buf = Buffer.from(entry.content, 'utf-8')
        p.entry({ name: entry.name, size: buf.length }, buf)
      }

      p.finalize()
    })
  }
}

export const opaBundleService = new OpaBundleService()
