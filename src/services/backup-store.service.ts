import { S3Client, ListObjectsV2Command, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3'
import { env } from '../config/env.js'
import type { AuthBundle } from './rbac-bundle.service.js'

export interface BackupObject {
  key: string
  lastModified: string | null
  size: number
}

/**
 * Reads/writes RBAC-bundle backups in the same S3 bucket the chart's backup
 * CronJob writes to (`<prefix>/{timestamp}.json` + a rolling `<prefix>/latest.json`).
 * Credentials come from the default AWS chain (IRSA) — no static keys. All
 * methods no-op / throw cleanly when backup is not configured.
 */
class BackupStoreService {
  private _client: S3Client | null = null

  enabled(): boolean {
    return env.BACKUP_ENABLED && !!env.BACKUP_S3_BUCKET
  }

  /** Non-secret config for the Backup tab (status + setup guidance). */
  config(): { enabled: boolean; bucket: string | null; prefix: string; region: string } {
    return { enabled: this.enabled(), bucket: env.BACKUP_S3_BUCKET ?? null, prefix: this.prefix(), region: env.BACKUP_S3_REGION }
  }

  private client(): S3Client {
    if (!this._client) this._client = new S3Client({ region: env.BACKUP_S3_REGION })
    return this._client
  }

  private prefix(): string {
    return env.BACKUP_S3_PREFIX.replace(/\/+$/, '')
  }
  private latestKey(): string {
    return `${this.prefix()}/latest.json`
  }
  private disabledError(): Error {
    return Object.assign(new Error('Backup is not enabled'), { statusCode: 501, code: 'backup_disabled' })
  }

  /** Backup snapshots, newest-first. Excludes the rolling `latest.json`. */
  async listBackups(): Promise<BackupObject[]> {
    if (!this.enabled()) return []
    const out = await this.client().send(
      new ListObjectsV2Command({ Bucket: env.BACKUP_S3_BUCKET!, Prefix: `${this.prefix()}/` }),
    )
    const items = (out.Contents ?? [])
      .filter((o) => o.Key && o.Key.endsWith('.json') && o.Key !== this.latestKey())
      .map((o) => ({
        key: o.Key!,
        lastModified: o.LastModified ? o.LastModified.toISOString() : null,
        size: o.Size ?? 0,
      }))
    items.sort((a, b) => (b.lastModified ?? '').localeCompare(a.lastModified ?? ''))
    return items
  }

  async getBackup(key: string): Promise<AuthBundle> {
    if (!this.enabled()) throw this.disabledError()
    // Only read keys inside our own prefix — never an arbitrary bucket object.
    if (!key.startsWith(`${this.prefix()}/`) || key.includes('..')) {
      throw Object.assign(new Error('Invalid backup key'), { statusCode: 400, code: 'invalid_key' })
    }
    const out = await this.client().send(new GetObjectCommand({ Bucket: env.BACKUP_S3_BUCKET!, Key: key }))
    return JSON.parse(await out.Body!.transformToString()) as AuthBundle
  }

  /** The rolling `latest.json`, or null if no backup exists yet. */
  async getLatest(): Promise<AuthBundle | null> {
    if (!this.enabled()) return null
    try {
      const out = await this.client().send(new GetObjectCommand({ Bucket: env.BACKUP_S3_BUCKET!, Key: this.latestKey() }))
      return JSON.parse(await out.Body!.transformToString()) as AuthBundle
    } catch (e: any) {
      if (e?.name === 'NoSuchKey' || e?.$metadata?.httpStatusCode === 404) return null
      throw e
    }
  }

  /** Upload a bundle as a timestamped snapshot + refresh `latest.json`. */
  async putBackup(bundle: AuthBundle): Promise<{ key: string }> {
    if (!this.enabled()) throw this.disabledError()
    const ts = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z') // 20260723T020000Z
    const key = `${this.prefix()}/${ts}.json`
    const body = JSON.stringify(bundle)
    await this.client().send(new PutObjectCommand({ Bucket: env.BACKUP_S3_BUCKET!, Key: key, Body: body, ContentType: 'application/json' }))
    await this.client().send(new PutObjectCommand({ Bucket: env.BACKUP_S3_BUCKET!, Key: this.latestKey(), Body: body, ContentType: 'application/json' }))
    return { key }
  }
}

export const backupStore = new BackupStoreService()
