import { createHash } from 'node:crypto'
import { KratosSessionService, kratosSessionService } from '../services/kratos-session.service.js'
import { queryOpa } from '../services/opa-client.js'
import type { Site } from './schemas.js'
import { twoFactorOn } from './render.js'
import { sitesRepository } from './repository.js'
import { siteLoginStore, type SiteLogin, type StoredLogo } from './login-store.js'
import { assertNotSystem, siteError } from './checks.js'
import type { Actor } from './audit.js'

/**
 * Per-site login (site-ux §11): the 2FA bar the policy enforces, the branding login-ui shows, the
 * logo, and the "why was I refused" answer login-ui's /access page needs.
 *
 * Everything public here describes the APPLIED version — what visitors meet — never a saved draft.
 */

export const LOGO_MAX_BYTES = 256 * 1024
export const LOGO_TYPES = ['image/png', 'image/webp'] as const

/** data.site_login[<site>], or null when the site asks for no second factor. */
export function siteLoginOf(site: Pick<Site, 'login'>): SiteLogin | null {
  if (!twoFactorOn(site)) return null
  const tf = site.login!.twoFactor
  return { min_aal: 'aal2', scope: tf.scope, routes: tf.routes ?? [], clients: tf.clients }
}

/** The applied intent of an applied site, or null. */
export async function liveSite(name: string): Promise<Site | null> {
  const record = await sitesRepository.get(name)
  if (!record?.applied) return null
  return (await sitesRepository.version(name, record.applied.version))?.site ?? null
}

async function liveSiteByHost(host: string): Promise<Site | null> {
  const wanted = host.toLowerCase()
  const record = (await sitesRepository.list()).find((r) => r.applied && r.site.address.host === wanted)
  return record ? liveSite(record.site.name) : null
}

export interface PublicSiteLogin {
  name: string
  displayName: string
  logoUrl: string | null
  accent: string | null
  welcome: string | null
  helpUrl: string | null
  minAal: 'aal1' | 'aal2'
  scope: 'none' | 'writes' | 'all' | 'routes'
  /** Where login-ui sends the visitor after sign-in; null = Kratos' default return URL. */
  defaultReturnUrl: string | null
}

async function publicView(site: Site | null): Promise<PublicSiteLogin> {
  if (!site) throw siteError(404, 'not_found', 'No site here')
  const b = site.login?.branding
  const logo = await siteLoginStore.getLogo(site.name)
  return {
    name: site.name,
    displayName: b?.name ?? site.displayName,
    logoUrl: logo ? `/api/public/sites/${site.name}/logo` : null,
    accent: b?.accent ?? null,
    welcome: b?.welcome ?? null,
    helpUrl: b?.helpUrl ?? null,
    minAal: siteLoginOf(site) ? 'aal2' : 'aal1',
    scope: site.login?.twoFactor.scope ?? 'none',
    defaultReturnUrl: site.login?.defaultReturnUrl ?? null,
  }
}

export const publicLoginByHost = async (host: string) => publicView(await liveSiteByHost(host))
export const publicLoginByName = async (name: string) => publicView(await liveSite(name))

// ── logo ──────────────────────────────────────────────────────

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const MAX_SIDE = 2048

/** PNG: signature, IHDR first with sane dimensions, chunks well-formed up to IEND at the very end. */
function isPng(b: Buffer): boolean {
  if (b.length < 8 + 25 + 12 || !b.subarray(0, 8).equals(PNG_SIGNATURE)) return false
  let at = 8
  let first = true
  while (at + 12 <= b.length) {
    const len = b.readUInt32BE(at)
    const type = b.toString('latin1', at + 4, at + 8)
    if (!/^[A-Za-z]{4}$/.test(type) || at + 12 + len > b.length) return false
    if (first) {
      if (type !== 'IHDR' || len !== 13) return false
      const w = b.readUInt32BE(at + 8)
      const h = b.readUInt32BE(at + 12)
      if (w < 1 || h < 1 || w > MAX_SIDE || h > MAX_SIDE) return false
      first = false
    }
    at += 12 + len
    if (type === 'IEND') return at === b.length
  }
  return false
}

/** WebP: RIFF container whose size matches the file, WEBP form, a VP8/VP8L/VP8X first chunk. */
function isWebp(b: Buffer): boolean {
  if (b.length < 20) return false
  if (b.toString('latin1', 0, 4) !== 'RIFF' || b.toString('latin1', 8, 12) !== 'WEBP') return false
  if (b.readUInt32LE(4) !== b.length - 8) return false
  return ['VP8 ', 'VP8L', 'VP8X'].includes(b.toString('latin1', 12, 16))
}

/**
 * Store a logo after checking its bytes are what its type says (no SVG: it can carry script).
 * Not re-encoded — the bytes are validated structurally and always served with their own type,
 * `nosniff` and a CSP that runs nothing.
 */
export async function putLogo(name: string, type: string, body: Buffer, actor: Actor): Promise<{ logoUrl: string; bytes: number; etag: string }> {
  assertNotSystem(name)
  if (!(await sitesRepository.get(name))) throw siteError(404, 'not_found', `Site not found: ${name}`)
  if (!(LOGO_TYPES as readonly string[]).includes(type)) throw siteError(415, 'logo_type', 'A logo must be a PNG or WebP image')
  if (body.length > LOGO_MAX_BYTES) throw siteError(413, 'logo_too_large', 'A logo must be at most 256 KB')
  const ok = type === 'image/png' ? isPng(body) : isWebp(body)
  if (!ok) throw siteError(422, 'logo_invalid', `The file is not a valid ${type === 'image/png' ? 'PNG' : 'WebP'} image`)
  const etag = createHash('sha256').update(body).digest('hex').slice(0, 16)
  const logo: StoredLogo = { type: type as StoredLogo['type'], data: body.toString('base64'), etag, at: new Date().toISOString(), by: actor.email ?? 'unknown' }
  await siteLoginStore.setLogo(name, logo)
  return { logoUrl: `/api/public/sites/${name}/logo`, bytes: body.length, etag }
}

export async function deleteLogo(name: string): Promise<void> {
  assertNotSystem(name)
  await siteLoginStore.deleteLogo(name)
}

export async function getLogo(name: string): Promise<StoredLogo> {
  const logo = await siteLoginStore.getLogo(name)
  if (!logo) throw siteError(404, 'not_found', 'No logo')
  return logo
}

// ── access reason (login-ui /access) ─────────────────────────

export type AccessReason = 'needs_2fa' | 'forbidden' | 'ok' | 'not_found'
const REASONS: readonly string[] = ['needs_2fa', 'forbidden', 'ok', 'not_found']

/**
 * Why the visitor holding this Kratos session was refused `GET <url>` on this site, as the policy
 * sees it now. The caller is the visitor themself (their own cookie): the answer is one word and the
 * site's 2FA bar, nothing about permissions or groups. An unknown answer is `forbidden`, never `ok`.
 */
export async function accessReason(name: string, rawUrl: unknown, cookieHeader: string | undefined): Promise<{ reason: AccessReason; minAal: 'aal1' | 'aal2' }> {
  const cookie = KratosSessionService.extractSessionCookie(cookieHeader)
  if (!cookie) throw siteError(401, 'unauthenticated', 'Sign in first')
  const { session } = await kratosSessionService.validateSession(cookie)
  if (!session) throw siteError(401, 'unauthenticated', 'Sign in first')

  const site = await liveSite(name)
  if (!site) throw siteError(404, 'not_found', 'No site here')
  let url: URL
  try {
    url = new URL(String(rawUrl ?? ''))
  } catch {
    throw siteError(400, 'invalid_url', 'url must be an absolute URL on the site')
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.hostname.toLowerCase() !== site.address.host) {
    throw siteError(400, 'invalid_url', 'url must be on the site host')
  }

  const decision = await queryOpa<{ reason?: unknown }>('rbac/decision', {
    email: session.email,
    object: url.pathname,
    action: 'GET',
    app: site.name,
    aal: session.aal,
    client: false,
  })
  const reason = typeof decision?.reason === 'string' && REASONS.includes(decision.reason) ? (decision.reason as AccessReason) : 'forbidden'
  return { reason, minAal: siteLoginOf(site) ? 'aal2' : 'aal1' }
}
