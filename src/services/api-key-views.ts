import type { FastifyRequest } from 'fastify'
import { rights } from '../authz/opa.js'
import { allows } from './user-permissions.js'
import { kratosService } from './kratos.service.js'
import { lastUsedOf } from './api-key-last-used.js'
import type { ApiKeyView } from '../schemas/api-key.schema.js'

/**
 * What a key list/get adds to the stored views, read at answer time:
 *   - `last_used_at` (services/api-key-last-used.ts), null when never seen or unreadable;
 *   - `created_by_email`: the creator's address through the shared identity cache — only when the
 *     creator is the caller, or the caller may look people up (`users:read`, as the audit actor
 *     names do). Otherwise null: managing an org's keys does not disclose who a platform admin is.
 * Neither ever fails the request: anything unreadable stays null.
 */

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

async function maySeeUsers(request: FastifyRequest, email: string): Promise<boolean> {
  try {
    const held = request.rbacInfo?.email === email ? request.rbacInfo : await rights(email)
    return allows(held.permissions, 'users:read')
  } catch {
    return false
  }
}

type DecoratedView = Pick<ApiKeyView, 'client_id' | 'created_by' | 'last_used_at' | 'created_by_email'>

async function creatorEmails(request: FastifyRequest, views: readonly DecoratedView[]): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const me = request.userContext
  if (me?.id && me.email && me.email !== 'unknown') out.set(me.id, me.email)
  const others = [...new Set(views.map((v) => v.created_by).filter((id): id is string => !!id && id !== me?.id && ID.test(id)))]
  if (others.length === 0 || !me?.email || !(await maySeeUsers(request, me.email))) return out
  try {
    const found = await kratosService.getIdentitiesByIds(others)
    for (const id of others) {
      const email = (found.get(id)?.traits as Record<string, unknown> | undefined)?.email
      if (typeof email === 'string' && email) out.set(id, email)
    }
  } catch (err) {
    request.log.warn({ err: (err as Error).message }, '[api-keys] creator addresses could not be read')
  }
  return out
}

export async function decorateKeyViews<T extends DecoratedView>(request: FastifyRequest, views: T[]): Promise<T[]> {
  if (views.length === 0) return views
  const [used, emails] = await Promise.all([lastUsedOf(views.map((v) => v.client_id)), creatorEmails(request, views)])
  return views.map((v) => ({
    ...v,
    last_used_at: used.get(v.client_id) ?? null,
    created_by_email: (v.created_by && emails.get(v.created_by)) || null,
  }))
}
