import { describe, it, expect, vi, beforeEach } from 'vitest'

// The flag said where rules come from and gated nothing: it was reported to the console, which greys
// its editors — and the console was the only caller that honoured it.

const { state } = vi.hoisted(() => ({ state: { RULES_SOURCE: 'gitops' } }))
vi.mock('../../../config/env.js', () => ({ env: state }))

const { refuseWhenSourcedFromGit } = await import('../../../middleware/refuse-when-sourced-from-git.js')

function reply() {
  const captured: { status?: number; body?: unknown } = {}
  const r = {
    status(code: number) {
      captured.status = code
      return r
    },
    async send(body: unknown) {
      captured.body = body
    },
    captured,
  }
  return r
}

const request = () =>
  ({ url: '/api/admin/rbac/groups', method: 'POST', log: { info: vi.fn() }, userContext: { email: 'a@x.io' } }) as never

describe('a write to something the repository owns', () => {
  beforeEach(() => {
    state.RULES_SOURCE = 'gitops'
  })

  it('is refused when the rules come from Git', async () => {
    const r = reply()
    await refuseWhenSourcedFromGit(request(), r as never)

    expect(r.captured.status).toBe(409)
    expect(r.captured.body).toMatchObject({ error: 'Conflict', rulesSource: 'gitops' })
  })

  it('names where the change belongs instead of only refusing', async () => {
    const r = reply()
    await refuseWhenSourcedFromGit(request(), r as never)

    expect((r.captured.body as { message: string }).message).toMatch(/repository/i)
  })

  // 409, not 403: nobody holds this one — not the super admin either — because the authority moved.
  // A 403 sends somebody looking for a permission to grant themselves.
  it('does not report it as a missing permission', async () => {
    const r = reply()
    await refuseWhenSourcedFromGit(request(), r as never)

    expect(r.captured.status).not.toBe(403)
  })

  it('lets the write through where this service IS the source', async () => {
    state.RULES_SOURCE = 'service'
    const r = reply()
    await refuseWhenSourcedFromGit(request(), r as never)

    expect(r.captured.status).toBeUndefined()
    expect(r.captured.body).toBeUndefined()
  })
})
