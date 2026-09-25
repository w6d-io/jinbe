import { getRedisClient } from '../services/redis-client.service.js'
import { withRedisLock } from '../services/redis-lock.js'
import type { OathkeeperRule } from '../services/redis-rbac.repository.js'
import type { Site } from './schemas.js'
import { sha256 } from './render.js'

/**
 * The Site intent store — the source of truth a Site CR is derived from (and re-created from on
 * restore).
 *
 *   rbac:sites                   → Hash: { name: JSON(SiteRecord) }        current saved version
 *   rbac:sites:versions:<name>   → List: JSON(SiteVersion), RPUSH only    append-only history
 *   rbac:sites:draft:<name>      → String: JSON(SiteDraft)                one server-side draft
 *   rbac:sites:deleted:<name>    → String: JSON(snapshot), EX 30 days     for restore
 *
 * Every save is a new version with its own etag; a save names the etag it was based on (If-Match),
 * so two editors cannot silently overwrite each other.
 */

export interface SiteRecord {
  site: Site
  version: number
  etag: string
  savedAt: string
  savedBy: string
  /** The version the gateway was last given, and the rules it rendered to (for overlap checks). */
  applied?: { version: number; at: string; by: string; rules: OathkeeperRule[] }
}

export interface SiteVersion {
  v: number
  at: string
  by: string
  note?: string
  kind: 'save' | 'rollback'
  etag: string
  site: Site
}

export interface SiteDraft {
  site: unknown
  baseVersion: number
  updatedBy: string
  updatedAt?: string
}

const SITES = 'rbac:sites'
const versionsKey = (name: string) => `rbac:sites:versions:${name}`
const draftKey = (name: string) => `rbac:sites:draft:${name}`
const deletedKey = (name: string) => `rbac:sites:deleted:${name}`
const DELETED_TTL_SECONDS = 30 * 24 * 3600

const status = (message: string, statusCode: number, code: string) => Object.assign(new Error(message), { statusCode, code })

export const etagOf = (site: Site, version: number) => sha256({ site, version }).slice(0, 16)

class SitesRepository {
  private get redis() {
    return getRedisClient()
  }

  async list(): Promise<SiteRecord[]> {
    const all = await this.redis.hgetall(SITES)
    return Object.values(all).map((raw) => JSON.parse(raw) as SiteRecord).sort((a, b) => a.site.name.localeCompare(b.site.name))
  }

  async get(name: string): Promise<SiteRecord | null> {
    const raw = await this.redis.hget(SITES, name)
    return raw ? (JSON.parse(raw) as SiteRecord) : null
  }

  /** Save a new version. `ifMatch` must name the current etag when the site exists (412 / 428 otherwise). */
  async save(site: Site, opts: { by: string; note?: string; ifMatch: string | undefined; kind?: SiteVersion['kind'] }): Promise<SiteRecord> {
    return withRedisLock(`sites:${site.name}`, async () => {
      const current = await this.get(site.name)
      const ifMatch = opts.ifMatch?.replace(/^W\//, '').replace(/"/g, '')
      if (current) {
        if (!ifMatch) throw status('This site exists: send If-Match with the etag you edited', 428, 'precondition_required')
        if (ifMatch !== current.etag && ifMatch !== '*') {
          throw status(`Someone saved version ${current.version} since you loaded this site`, 412, 'stale_etag')
        }
      } else if (ifMatch && ifMatch !== '*') {
        throw status('This site no longer exists', 412, 'stale_etag')
      }
      const version = (current?.version ?? 0) + 1
      const at = new Date().toISOString()
      const etag = etagOf(site, version)
      const record: SiteRecord = { site, version, etag, savedAt: at, savedBy: opts.by, ...(current?.applied ? { applied: current.applied } : {}) }
      const entry: SiteVersion = { v: version, at, by: opts.by, ...(opts.note ? { note: opts.note } : {}), kind: opts.kind ?? 'save', etag, site }
      await this.redis.rpush(versionsKey(site.name), JSON.stringify(entry))
      await this.redis.hset(SITES, site.name, JSON.stringify(record))
      return record
    })
  }

  async markApplied(name: string, applied: { version: number; by: string; rules: OathkeeperRule[] }): Promise<void> {
    await withRedisLock(`sites:${name}`, async () => {
      const current = await this.get(name)
      if (!current) throw status(`Site not found: ${name}`, 404, 'not_found')
      current.applied = { ...applied, at: new Date().toISOString() }
      await this.redis.hset(SITES, name, JSON.stringify(current))
    })
  }

  /** Replace the stored intent's run state without a new version (pause/resume). */
  async setState(name: string, state: Site['state']): Promise<SiteRecord> {
    return withRedisLock(`sites:${name}`, async () => {
      const current = await this.get(name)
      if (!current) throw status(`Site not found: ${name}`, 404, 'not_found')
      current.site = { ...current.site, state }
      await this.redis.hset(SITES, name, JSON.stringify(current))
      return current
    })
  }

  async versions(name: string): Promise<SiteVersion[]> {
    const raw = await this.redis.lrange(versionsKey(name), 0, -1)
    return raw.map((r) => JSON.parse(r) as SiteVersion)
  }

  async version(name: string, v: number): Promise<SiteVersion | null> {
    const raw = await this.redis.lrange(versionsKey(name), v - 1, v - 1)
    const entry = raw[0] ? (JSON.parse(raw[0]) as SiteVersion) : null
    return entry?.v === v ? entry : null
  }

  async getDraft(name: string): Promise<SiteDraft | null> {
    const raw = await this.redis.get(draftKey(name))
    return raw ? (JSON.parse(raw) as SiteDraft) : null
  }

  async putDraft(name: string, draft: SiteDraft): Promise<SiteDraft> {
    const stored = { ...draft, updatedAt: new Date().toISOString() }
    await this.redis.set(draftKey(name), JSON.stringify(stored))
    return stored
  }

  async deleteDraft(name: string): Promise<void> {
    await this.redis.del(draftKey(name))
  }

  /** Drop the site; its record and history are kept 30 days under rbac:sites:deleted:<name>. */
  async remove(name: string, by: string): Promise<void> {
    await withRedisLock(`sites:${name}`, async () => {
      const current = await this.get(name)
      if (!current) return
      const snapshot = { record: current, versions: await this.versions(name), deletedAt: new Date().toISOString(), deletedBy: by }
      await this.redis.set(deletedKey(name), JSON.stringify(snapshot), 'EX', DELETED_TTL_SECONDS)
      await this.redis.hdel(SITES, name)
      await this.redis.del(versionsKey(name))
      await this.redis.del(draftKey(name))
    })
  }
}

export const sitesRepository = new SitesRepository()
