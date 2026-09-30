import type { FastifyBaseLogger } from 'fastify'
import { DRY_RUN } from '../../authz/dry-run.js'
import type { UserContext } from '../../middleware/identity-extractor.js'
import type { RouteChain } from '../../policy/route-guards.js'

/**
 * Runs a route's real guards, in Fastify's order, against a request jinbe builds for the subject —
 * and stops at the first answer, as Fastify does. The guards are the ones the route runs
 * (policy/route-guards.ts), unchanged; the request carries DRY_RUN so the refusal audit and the
 * delegated write budget are skipped, and a capturing reply keeps what they would have sent.
 *
 * Of the onRequest hooks only the ones that JUDGE a request run: the session 2FA gate and the two
 * machine credentials. Request ids, the identity extraction and the session check are replaced by the
 * subject the explainer was asked about. The idempotency hook replays responses, it decides nothing.
 */

const JUDGING_ON_REQUEST = new Set(['requireSecondFactor', 'requireOpalClient', 'scimAuth'])
const NOT_A_GUARD = new Set(['idempotencyPreHandler'])

export interface GuardRun {
  guard: string
  phase: 'onRequest' | 'preHandler'
  verdict: 'pass' | 'refuse' | 'error'
  status?: number
  body?: unknown
  error?: string
}

export interface ChainVerdict {
  /** The status the caller would get; 200 when every guard passes (the handler may still refuse). */
  status: number
  body?: unknown
  /** The guard that answered, or `handler` when none did. */
  decidedBy: string
  guards: GuardRun[]
}

export interface DryRequestInput {
  method: string
  path: string
  pattern: string
  params: Record<string, string>
  config: Record<string, unknown>
  userContext: UserContext
  body?: unknown
  id?: string
  ip?: string
}

const silent: FastifyBaseLogger = new Proxy({} as FastifyBaseLogger, {
  get: (_t, key) => (key === 'child' ? () => silent : key === 'level' ? 'silent' : () => {}),
})

/** The request the guards see: the subject's identity on the asked route, flagged DRY_RUN. */
export function dryRequest(input: DryRequestInput): Record<string | symbol, unknown> {
  return {
    [DRY_RUN]: true,
    id: input.id ?? 'explain',
    ip: input.ip ?? '127.0.0.1',
    method: input.method,
    url: input.path,
    params: input.params,
    query: {},
    headers: {},
    body: input.body,
    routeOptions: { url: input.pattern, method: input.method, config: input.config },
    userContext: input.userContext,
    log: silent,
  }
}

function captureReply() {
  const headers: Record<string, unknown> = {}
  const reply = {
    statusCode: 200,
    sent: false,
    body: undefined as unknown,
    status(code: number) {
      reply.statusCode = code
      return reply
    },
    code(code: number) {
      reply.statusCode = code
      return reply
    },
    header(key: string, value: unknown) {
      headers[key.toLowerCase()] = value
      return reply
    },
    headers(values: Record<string, unknown>) {
      for (const [k, v] of Object.entries(values)) headers[k.toLowerCase()] = v
      return reply
    },
    getHeader: (key: string) => headers[key.toLowerCase()],
    send(body?: unknown) {
      reply.body = body
      reply.sent = true
      return reply
    },
    log: silent,
  }
  return reply
}

type AnyHook = (...args: unknown[]) => unknown

async function runOne(hook: AnyHook, request: unknown, reply: ReturnType<typeof captureReply>): Promise<void> {
  // A callback-style hook (request, reply, done) is awaited through its `done`.
  if (hook.length >= 3) {
    await new Promise<void>((resolve, reject) => {
      const out = hook(request, reply, (err?: unknown) => (err ? reject(err) : resolve()))
      if (out && typeof (out as Promise<unknown>).then === 'function') (out as Promise<unknown>).then(() => resolve(), reject)
    })
    return
  }
  await hook(request, reply)
}

/** Runs the chain until a guard answers; every guard reached is listed with its verdict. */
export async function dryRunChain(chain: RouteChain, request: Record<string | symbol, unknown>): Promise<ChainVerdict> {
  const guards: GuardRun[] = []
  const phases: Array<['onRequest' | 'preHandler', AnyHook[]]> = [
    ['onRequest', (chain.onRequest as AnyHook[]).filter((h) => JUDGING_ON_REQUEST.has(h.name))],
    ['preHandler', (chain.preHandler as AnyHook[]).filter((h) => !NOT_A_GUARD.has(h.name))],
  ]
  for (const [phase, hooks] of phases) {
    for (const hook of hooks) {
      const guard = hook.name || 'anonymous'
      const reply = captureReply()
      try {
        await runOne(hook, request, reply)
      } catch (err) {
        const status = Number((err as { statusCode?: unknown }).statusCode) || 500
        guards.push({ guard, phase, verdict: 'error', status, error: (err as Error).message })
        return { status, decidedBy: guard, guards }
      }
      if (reply.sent) {
        guards.push({ guard, phase, verdict: reply.statusCode < 400 ? 'pass' : 'refuse', status: reply.statusCode, body: reply.body })
        return { status: reply.statusCode, body: reply.body, decidedBy: guard, guards }
      }
      guards.push({ guard, phase, verdict: 'pass' })
    }
  }
  return { status: 200, decidedBy: 'handler', guards }
}
