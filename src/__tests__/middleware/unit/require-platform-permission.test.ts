import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// The gate for the surfaces that are not about one organisation: listing every organisation, reading
// the trail, handing out a group. What it replaces asked whether the caller was in a group NAMED
// like an admin group, resolved from Kratos metadata through a cache — so what an administrator
// could see was decided by something nobody enforces, keyed on an address.

vi.mock('../../../services/authorization-model.service.js', () => ({
  holdsPlatformPermission: vi.fn(),
  AuthorizationModelUnavailableError: class extends Error {},
}))

import { requirePlatformPermission } from '../../../middleware/require-platform-permission.js'
import { holdsPlatformPermission } from '../../../services/authorization-model.service.js'

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

  it('lets the caller through when the model says they hold it', async () => {
    vi.mocked(holdsPlatformPermission).mockResolvedValue(true)
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-a'), r)

    expect(r.send).not.toHaveBeenCalled()
    // The IDENTITY, and the permission it was asked about — never an address.
    expect(holdsPlatformPermission).toHaveBeenCalledWith('subject-a', 'admin.organisation:read')
  })

  it('refuses with 403 and names the permission', async () => {
    vi.mocked(holdsPlatformPermission).mockResolvedValue(false)
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-b'), r)

    expect(r._statusCode).toBe(403)
    expect(r._body).toMatchObject({ message: expect.stringContaining('admin.organisation:read') })
  })

  it('answers 503 when the model cannot be read, never 403', async () => {
    // "Does not hold it" and "I could not tell" are opposite facts. A 403 here reads as a missing
    // right, and somebody would go and ask for a permission they already have.
    vi.mocked(holdsPlatformPermission).mockRejectedValue(new Error('configmaps is forbidden'))
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('subject-c'), r)

    expect(r._statusCode).toBe(503)
  })

  it('refuses before reading anything when there is no identity', async () => {
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request(undefined), r)

    expect(r._statusCode).toBe(401)
    expect(holdsPlatformPermission).not.toHaveBeenCalled()
  })

  it('refuses the sentinel identity an unauthenticated context carries', async () => {
    const r = reply()

    await requirePlatformPermission('admin.organisation:read')(request('unknown'), r)

    expect(r._statusCode).toBe(401)
    expect(holdsPlatformPermission).not.toHaveBeenCalled()
  })
})
