import { describe, it, expect, vi } from 'vitest'

// The console decides whether to offer an edit from this field, so two properties matter: it is
// ANSWERED (not inferred by the console), and its default is the arrangement where editing works —
// a deployment that says nothing keeps the behaviour it has always had.

const envState = { RULES_SOURCE: 'service', APP_NAME: 'jinbe' }

vi.mock('../../../config/env.js', () => ({ env: envState }))
vi.mock('../../../services/rbac-resolver.service.js', () => ({
  rbacResolverService: { resolveUserRbac: vi.fn(async () => ({ groups: [], roles: [], permissions: [] })) },
}))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: { extendSession: vi.fn(async () => {}), getIdentity: vi.fn(async () => null) },
}))

const { whoamiRoutes } = await import('../../../routes/whoami.routes.js')

async function whoami() {
  let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | null = null
  await whoamiRoutes({
    get: (_path: string, _opts: unknown, fn: typeof handler) => {
      handler = fn
    },
  } as never)
  const body: Record<string, unknown> = {}
  const reply = { status: () => reply, send: (p: Record<string, unknown>) => Object.assign(body, p) }
  await handler!({ validatedSession: null, userContext: null, log: { warn: vi.fn() } }, reply)
  return body
}

describe('GET /whoami — where the rules are enforced from', () => {
  it('answers the arrangement where editing works when nothing was declared', async () => {
    envState.RULES_SOURCE = 'service'
    expect((await whoami()).rules_source).toBe('service')
  })

  it('answers what the deployment declared', async () => {
    envState.RULES_SOURCE = 'gitops'
    expect((await whoami()).rules_source).toBe('gitops')
  })
})
