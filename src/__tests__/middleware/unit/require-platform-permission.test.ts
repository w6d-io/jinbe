import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// The gate for the surfaces that are not about one organisation: listing every organisation, reading
// the trail, handing out a group. Asked of OPA — what the caller holds in jinbe — never of a model
// read beside it.

vi.mock('../../../authz/opa.js', () => ({ holdsInJinbe: vi.fn() }))
vi.mock('../../../audit/deny.js', () => ({ denyAudit: vi.fn() }))

import { requirePlatformPermission } from '../../../middleware/require-platform-permission.js'
import { holdsInJinbe } from '../../../authz/opa.js'
import { denyAudit } from '../../../audit/deny.js'

function request(subject?: string): FastifyRequest {
  return {
    userContext: subject ? { id: subject, email: `${subject}@example.com` } : undefined,
    log: { warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
  } as unknown as FastifyRequest
}

function reply(): FastifyReply & { _statusCode?: number; _body?: unknown } {
  const r = {
    _statusCode: undefined as number | undefined,
    _body: undefined as unknown,
    status: vi.fn().mockImplementation(function (this: typeof r, c: number) { this._statusCode = c; return this }),
    send: vi.fn().mockImplementation(function (this: typeof r, b: unknown) { this._body = b; return this }),
  }
  return r as unknown as FastifyReply & { _statusCode?: number; _body?: unknown }
}

describe('requirePlatformPermission', () => {
  beforeEach(() => vi.clearAllMocks())

  it('lets the caller through when OPA says they hold it', async () => {
    vi.mocked(holdsInJinbe).mockResolvedValue(true)
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-a'), r)

    expect(r.send).not.toHaveBeenCalled()
    // The address the RBAC bindings are keyed on, and the permission it was asked about.
    expect(holdsInJinbe).toHaveBeenCalledWith('subject-a@example.com', 'admin.organisation:read')
  })

  it('refuses with 403 and names the permission', async () => {
    vi.mocked(holdsInJinbe).mockResolvedValue(false)
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-b'), r)

    expect(r._statusCode).toBe(403)
    expect(r._body).toMatchObject({ message: expect.stringContaining('admin.organisation:read') })
    expect(denyAudit).toHaveBeenCalledWith(expect.anything(), 'missing_permission:admin.organisation:read')
  })

  it('answers 503 when OPA cannot be asked, never 403', async () => {
    // "Does not hold it" and "I could not tell" are opposite facts. A 403 here reads as a missing
    // right, and somebody would go and ask for a permission they already have.
    vi.mocked(holdsInJinbe).mockRejectedValue(new Error('OPA is unreachable'))
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-c'), r)

    expect(r._statusCode).toBe(503)
  })

  it('refuses before reading anything when there is no identity', async () => {
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request(undefined), r)

    expect(r._statusCode).toBe(401)
    expect(holdsInJinbe).not.toHaveBeenCalled()
  })

  it('refuses the sentinel identity an unauthenticated context carries', async () => {
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('unknown'), r)

    expect(r._statusCode).toBe(401)
    expect(holdsInJinbe).not.toHaveBeenCalled()
  })
})
