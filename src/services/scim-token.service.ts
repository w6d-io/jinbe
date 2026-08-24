import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { getRedisClient } from './redis-client.service.js'

/**
 * SCIM bearer-token management (SCIM provisioning spec §3).
 *
 * One long-lived bearer token per IdP, stored HASHED in Redis:
 *   rbac:scim:tokens → Hash: { tokenId: JSON({ sha256, label, createdBy, createdAt, lastUsedAt }) }
 *
 * The plaintext token is shown exactly once at mint time (same invariant as
 * api-key.service: the secret is never stored). Token format
 * `scim_<tokenId>_<secret>` embeds the id so verification is a single HGET +
 * constant-time SHA-256 comparison; opaque tokens fall back to a full-hash
 * scan (still constant-time per entry).
 */

const SCIM_TOKENS_KEY = 'rbac:scim:tokens'
const TOKEN_RE = /^scim_([0-9a-f]{16})_[0-9a-f]{64}$/

export interface ScimTokenRecord {
  sha256: string
  label: string
  createdBy: string | null
  createdAt: string
  lastUsedAt: string | null
}

export interface ScimTokenPrincipal {
  tokenId: string
  label: string
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

/** Constant-time comparison of two hex digests (length-guarded). */
function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex')
  const bufB = Buffer.from(b, 'hex')
  if (bufA.length !== bufB.length || bufA.length === 0) return false
  return timingSafeEqual(bufA, bufB)
}

export class ScimTokenService {
  /**
   * Mint a new SCIM bearer token. Returns the plaintext token — the ONLY time
   * it is ever available. Only the SHA-256 hash is persisted.
   */
  async mint(opts: { label: string; createdBy?: string | null }): Promise<{
    tokenId: string
    token: string
    record: ScimTokenRecord
  }> {
    const tokenId = randomBytes(8).toString('hex')
    const secret = randomBytes(32).toString('hex')
    const token = `scim_${tokenId}_${secret}`
    const record: ScimTokenRecord = {
      sha256: sha256Hex(token),
      label: opts.label,
      createdBy: opts.createdBy ?? null,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    }
    await getRedisClient().hset(SCIM_TOKENS_KEY, tokenId, JSON.stringify(record))
    return { tokenId, token, record }
  }

  /**
   * Verify a presented bearer token. Returns the principal (tokenId + label)
   * on success, null otherwise — never throws for a bad token (fail-closed).
   */
  async verify(token: string): Promise<ScimTokenPrincipal | null> {
    if (!token) return null
    const presented = sha256Hex(token)
    const redis = getRedisClient()

    const match = TOKEN_RE.exec(token)
    if (match) {
      const tokenId = match[1]
      const raw = await redis.hget(SCIM_TOKENS_KEY, tokenId)
      if (!raw) return null
      const record = this.parseRecord(raw)
      if (!record || !safeEqualHex(presented, record.sha256)) return null
      this.touch(tokenId, record).catch(() => {})
      return { tokenId, label: record.label }
    }

    // Opaque token (no embedded id): compare against every stored hash.
    const all = await redis.hgetall(SCIM_TOKENS_KEY)
    let found: { tokenId: string; record: ScimTokenRecord } | null = null
    for (const [tokenId, raw] of Object.entries(all)) {
      const record = this.parseRecord(raw)
      if (record && safeEqualHex(presented, record.sha256)) {
        found = { tokenId, record }
      }
    }
    if (!found) return null
    this.touch(found.tokenId, found.record).catch(() => {})
    return { tokenId: found.tokenId, label: found.record.label }
  }

  /** List token metadata (never the hash — this feeds admin surfaces). */
  async list(): Promise<Array<Omit<ScimTokenRecord, 'sha256'> & { tokenId: string }>> {
    const all = await getRedisClient().hgetall(SCIM_TOKENS_KEY)
    const out: Array<Omit<ScimTokenRecord, 'sha256'> & { tokenId: string }> = []
    for (const [tokenId, raw] of Object.entries(all)) {
      const record = this.parseRecord(raw)
      if (!record) continue
      out.push({
        tokenId,
        label: record.label,
        createdBy: record.createdBy,
        createdAt: record.createdAt,
        lastUsedAt: record.lastUsedAt,
      })
    }
    return out
  }

  /** Revoke a token by id. Returns true when an entry was deleted. */
  async revoke(tokenId: string): Promise<boolean> {
    const deleted = await getRedisClient().hdel(SCIM_TOKENS_KEY, tokenId)
    return deleted > 0
  }

  /** Best-effort lastUsedAt bump — a failure must never break auth. */
  private async touch(tokenId: string, record: ScimTokenRecord): Promise<void> {
    await getRedisClient().hset(
      SCIM_TOKENS_KEY,
      tokenId,
      JSON.stringify({ ...record, lastUsedAt: new Date().toISOString() })
    )
  }

  private parseRecord(raw: string): ScimTokenRecord | null {
    try {
      const parsed = JSON.parse(raw) as ScimTokenRecord
      return typeof parsed?.sha256 === 'string' ? parsed : null
    } catch {
      return null
    }
  }
}

export const scimTokenService = new ScimTokenService()
