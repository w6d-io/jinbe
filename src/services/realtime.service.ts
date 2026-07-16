import type Redis from 'ioredis'
import type { FastifyReply } from 'fastify'

/**
 * Real-time change fan-out to browser clients over Server-Sent Events.
 *
 * Why a SEPARATE Redis pub/sub channel (not the notifications outbox): the
 * outbox uses a consumer GROUP, so each event is delivered to exactly ONE
 * consumer — wrong for broadcast. SSE needs every jinbe replica to push to the
 * clients connected to IT, so we use pub/sub: any replica publishes a change,
 * every replica receives it and writes to its own connected clients.
 *
 * The payload is a minimal "something in category X changed" signal — never
 * data. Clients react by refetching through the normal auth'd endpoints, so
 * even if the stream were observed it carries no user data or secrets. The SSE
 * endpoint itself is gated by requireAdmin (Kratos session), same as the rest
 * of /admin.
 */
const CHANNEL = 'rbac:realtime'
const HEARTBEAT_MS = 25_000

export interface RealtimeEvent {
  type: string
  at: string
}

class RealtimeService {
  private pub: Redis | null = null
  private sub: Redis | null = null
  private clients = new Set<FastifyReply>()
  private heartbeat: ReturnType<typeof setInterval> | null = null

  /** Wire the pub/sub connections + heartbeat. Idempotent (dev hot-reload). */
  init(redis: Redis): void {
    if (this.sub) return
    this.pub = redis
    // A subscriber connection can't issue normal commands, so duplicate.
    this.sub = redis.duplicate()
    this.sub.on('message', (_channel, message) => this.broadcast(message))
    this.sub.subscribe(CHANNEL).catch((err) => {
      console.error('[realtime] subscribe failed:', err)
    })
    this.heartbeat = setInterval(() => this.ping(), HEARTBEAT_MS)
    // Don't keep the event loop alive just for the heartbeat.
    this.heartbeat.unref?.()
    console.log('[realtime] SSE fan-out ready')
  }

  stop(): void {
    if (this.heartbeat) clearInterval(this.heartbeat)
    this.heartbeat = null
    this.sub?.disconnect()
    this.sub = null
    for (const reply of this.clients) {
      try { reply.raw.end() } catch { /* ignore */ }
    }
    this.clients.clear()
  }

  /**
   * Publish a change signal to every replica's SSE clients. Best-effort and
   * non-blocking — a pub/sub failure must never break the mutation that
   * triggered it.
   */
  publish(type: string): void {
    if (!this.pub) return
    const payload: RealtimeEvent = { type, at: new Date().toISOString() }
    this.pub.publish(CHANNEL, JSON.stringify(payload)).catch(() => {})
  }

  /** Register a hijacked SSE response; caller removes it on request close. */
  addClient(reply: FastifyReply): void {
    this.clients.add(reply)
  }

  removeClient(reply: FastifyReply): void {
    this.clients.delete(reply)
  }

  get clientCount(): number {
    return this.clients.size
  }

  private broadcast(message: string): void {
    for (const reply of this.clients) {
      try {
        reply.raw.write(`event: change\ndata: ${message}\n\n`)
      } catch {
        this.clients.delete(reply)
      }
    }
  }

  private ping(): void {
    for (const reply of this.clients) {
      try {
        reply.raw.write(`: ping\n\n`)
      } catch {
        this.clients.delete(reply)
      }
    }
  }
}

export const realtimeService = new RealtimeService()
