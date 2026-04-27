import Redis from 'ioredis'
import { env } from '../config/env.js'

/**
 * Redis Client Service
 *
 * Singleton wrapper around ioredis for RBAC data storage and audit streams.
 * Connection is lazy — created on first access.
 */
class RedisClientService {
  private client: Redis | null = null
  private connected = false

  /**
   * Get or create the Redis client
   */
  getClient(): Redis {
    if (!this.client) {
      this.client = new Redis(env.REDIS_URL, {
        password: env.REDIS_PASSWORD || undefined,
        db: env.REDIS_DB,
        maxRetriesPerRequest: 3,
        retryStrategy(times) {
          const delay = Math.min(times * 200, 5000)
          return delay
        },
        lazyConnect: false,
      })

      this.client.on('connect', () => {
        this.connected = true
        console.log('[redis] Connected')
      })

      this.client.on('error', (err) => {
        this.connected = false
        console.error('[redis] Error:', err.message)
      })

      this.client.on('close', () => {
        this.connected = false
      })
    }

    return this.client
  }

  /**
   * Check if Redis is reachable
   */
  async isHealthy(): Promise<boolean> {
    try {
      const client = this.getClient()
      const result = await client.ping()
      return result === 'PONG'
    } catch {
      return false
    }
  }

  /**
   * Graceful shutdown
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.quit()
      this.client = null
      this.connected = false
      console.log('[redis] Disconnected')
    }
  }

  /**
   * Connection status
   */
  get isConnected(): boolean {
    return this.connected
  }
}

export const redisClientService = new RedisClientService()
export const getRedisClient = () => redisClientService.getClient()
