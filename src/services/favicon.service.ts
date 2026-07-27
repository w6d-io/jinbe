import { getRedisClient } from './redis-client.service.js'
import { redisRbacRepository } from './redis-rbac.repository.js'

/**
 * Favicon Service
 *
 * Fetches, caches and serves the favicon of a service's own PUBLIC website.
 *
 * OPSEC: the icon is fetched DIRECTLY from the service's own public host,
 * server-side and in-cluster from jinbe — NEVER via a third-party favicon
 * service (Google/DuckDuckGo/etc.), which would leak the (potentially internal)
 * hostname off-platform. jinbe fetches; the browser never calls out.
 *
 * The public host is derived from the service's Oathkeeper access rule
 * `match.url`. The bytes + content-type are cached in Redis for 7 days; a
 * negative sentinel is cached for 1 day so unreachable / icon-less services
 * don't trigger an outbound fetch on every request. Nothing here ever throws to
 * the caller — a favicon is decorative, so every failure resolves to `null`.
 *
 * Cache key schema:
 *   favicon:<service>  → String: JSON({ ct, b64 })  (positive, 7d TTL)
 *                        or the literal "none"       (negative,  1d TTL)
 */

// ─────────────────────────────────────────────────────────────
// Tunables
// ─────────────────────────────────────────────────────────────

const CACHE_PREFIX = 'favicon:'
const NONE_SENTINEL = 'none'
const POSITIVE_TTL_SECONDS = 7 * 24 * 60 * 60 // 7 days — icons rarely change
const NEGATIVE_TTL_SECONDS = 24 * 60 * 60     // 1 day  — re-probe unreachable services sooner
const FETCH_TIMEOUT_MS = 3_000                // per-request wall-clock bound
const MAX_BYTES = 100 * 1024                  // 100KB hard cap on any fetched body
const MAX_HTML_SCAN = 200_000                 // only scan the first ~200KB of HTML for <link>
const USER_AGENT = 'jinbe-favicon-fetcher'

export interface FaviconResult {
  contentType: string
  data: Buffer
}

class FaviconService {
  private cacheKey(service: string): string {
    return `${CACHE_PREFIX}${service}`
  }

  // ═══════════════════════════════════════════════════════════
  // Public API
  // ═══════════════════════════════════════════════════════════

  /**
   * Resolve a service's favicon, cache-first. Returns the cached image on a
   * positive hit, `null` on a negative hit, and on a miss fetches from the
   * service's own public host (caching either the bytes or a negative sentinel).
   * Never throws.
   */
  async getFavicon(service: string): Promise<FaviconResult | null> {
    try {
      const cached = await this.readCache(service)
      if (cached !== undefined) return cached // hit: positive result OR negative (null)

      const origin = await this.resolveOrigin(service)
      if (!origin) {
        // No usable public host → nothing to fetch. Cache "none" so we don't
        // re-derive on every request.
        await this.cacheNegative(service)
        return null
      }

      const result = await this.fetchFavicon(origin)
      if (result) {
        await this.cachePositive(service, result)
        return result
      }
      await this.cacheNegative(service)
      return null
    } catch {
      // Defensive: a favicon is decorative — swallow everything.
      return null
    }
  }

  // ═══════════════════════════════════════════════════════════
  // Host derivation (from the service's Oathkeeper access rule)
  // ═══════════════════════════════════════════════════════════

  /**
   * Derive the service's public origin (`https://<host>[:port]`) from its
   * Oathkeeper access rule `match.url`. Prefers the service's MAIN rule
   * (`id === service`) which carries the canonical public URL, falling back to a
   * sibling sub-rule (`<service>-health`, …) that shares the same host.
   * Returns `null` when no rule yields a concrete, literal host.
   */
  async resolveOrigin(service: string): Promise<string | null> {
    const rules = await redisRbacRepository.getAccessRules()
    const main = rules.find(r => r.id === service)
    const sibling = rules.find(r => r.id.startsWith(`${service}-`))
    for (const rule of [main, sibling]) {
      const origin = this.parseOrigin(rule?.match?.url)
      if (origin) return origin
    }
    return null
  }

  /**
   * Parse a concrete origin out of an Oathkeeper `match.url`. These come in two
   * shapes: a plain URL (`https://host/api/svc/<**>`) or a regex wrapped in
   * angle brackets with a regex scheme (`<https?://host/.*>`). A wildcard /
   * templated host (`<.*>.example.com`) has no single host → `null`, treated as
   * "no favicon". Always resolves to https (public hosts serve icons over TLS).
   */
  private parseOrigin(matchUrl: string | undefined): string | null {
    if (!matchUrl || typeof matchUrl !== 'string') return null
    let s = matchUrl.trim()
    if (s.startsWith('<')) s = s.slice(1) // strip a leading regex-group bracket
    // scheme: http | https | https?  → then ://  → authority up to :/<>?# or ws
    const m = /^https?\??:\/\/([^/<>?#\s:]+)(?::(\d+))?/i.exec(s)
    if (!m) return null
    const hostname = m[1]
    const port = m[2]
    // Reject anything still carrying regex/template metacharacters or an
    // otherwise malformed hostname — we can only fetch a literal host.
    if (!/^[a-z0-9.-]+$/i.test(hostname)) return null
    if (
      hostname.includes('..') ||
      hostname.startsWith('.') ||
      hostname.endsWith('.') ||
      hostname.startsWith('-')
    ) return null
    return port ? `https://${hostname}:${port}` : `https://${hostname}`
  }

  // ═══════════════════════════════════════════════════════════
  // Fetch (HTML discovery → declared icons → /favicon.ico)
  // ═══════════════════════════════════════════════════════════

  private async fetchFavicon(origin: string): Promise<FaviconResult | null> {
    const hostAuthority = new URL(origin).host

    // 1) Discover declared icons from the site's HTML (best quality).
    const candidates = new Set<string>()
    const html = await this.fetchHtml(origin)
    if (html) {
      for (const href of this.extractIconHrefs(html)) {
        try {
          const abs = new URL(href, `${origin}/`)
          // Defense-in-depth: only follow an icon on the service's OWN host, and
          // only over http(s). Never chase an off-host href (avoids SSRF and
          // keeps us strictly on the service's public host).
          if (
            (abs.protocol === 'https:' || abs.protocol === 'http:') &&
            abs.host === hostAuthority
          ) {
            candidates.add(abs.toString())
          }
        } catch {
          // malformed / data: href — skip
        }
      }
    }

    // 2) Always try the conventional /favicon.ico as a last resort.
    candidates.add(`${origin}/favicon.ico`)

    for (const url of candidates) {
      const img = await this.fetchImage(url)
      if (img) return img
    }
    return null
  }

  private async fetchHtml(origin: string): Promise<string | null> {
    const res = await this.fetchBounded(`${origin}/`, ct =>
      ct === 'text/html' || ct === 'application/xhtml+xml'
    )
    return res ? res.body.toString('utf8') : null
  }

  private async fetchImage(url: string): Promise<FaviconResult | null> {
    const res = await this.fetchBounded(url, ct => ct.startsWith('image/'))
    return res ? { contentType: res.contentType, data: res.body } : null
  }

  /**
   * Bounded fetch: enforces a ~3s timeout, a 100KB size cap (streamed, so a
   * lying/absent Content-Length can't blow memory) and a content-type
   * allow-list. Returns `null` on any non-2xx, disallowed type, over-size body
   * or error — never throws.
   */
  private async fetchBounded(
    url: string,
    accept: (contentType: string) => boolean,
  ): Promise<{ contentType: string; body: Buffer } | null> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
      })
      if (!res.ok) return null

      const contentType = (res.headers.get('content-type') || '')
        .split(';')[0]
        .trim()
        .toLowerCase()
      if (!accept(contentType)) return null

      // Early reject on an honest Content-Length.
      const declared = Number(res.headers.get('content-length'))
      if (Number.isFinite(declared) && declared > MAX_BYTES) return null

      const body = await this.readBounded(res)
      if (!body || body.byteLength === 0) return null
      return { contentType, body }
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Read a response body into a Buffer, aborting the moment it exceeds
   * MAX_BYTES (defends against a server that lies about / omits Content-Length).
   */
  private async readBounded(res: Response): Promise<Buffer | null> {
    const reader = res.body?.getReader?.()
    if (!reader) {
      const buf = Buffer.from(await res.arrayBuffer())
      return buf.byteLength > MAX_BYTES ? null : buf
    }
    const chunks: Buffer[] = []
    let total = 0
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (value) {
        total += value.byteLength
        if (total > MAX_BYTES) {
          await reader.cancel().catch(() => {})
          return null
        }
        chunks.push(Buffer.from(value))
      }
    }
    return Buffer.concat(chunks)
  }

  /**
   * Extract candidate icon hrefs from a page's <head>, standard `icon` /
   * `shortcut icon` first, then `apple-touch-icon(-precomposed)`. Order-stable
   * and de-duplicated. Plain string parsing (no HTML-parser dependency).
   */
  private extractIconHrefs(html: string): string[] {
    const head = html.slice(0, MAX_HTML_SCAN)
    const found: Array<{ href: string; priority: number }> = []
    const linkRe = /<link\b[^>]*>/gi
    let tagMatch: RegExpExecArray | null
    while ((tagMatch = linkRe.exec(head)) !== null) {
      const tag = tagMatch[0]
      const relVal = this.attr(tag, 'rel')?.toLowerCase()
      if (!relVal) continue
      const tokens = relVal.split(/\s+/)
      const isStd = tokens.includes('icon') // covers "icon" and "shortcut icon"
      const isApple =
        tokens.includes('apple-touch-icon') ||
        tokens.includes('apple-touch-icon-precomposed')
      if (!isStd && !isApple) continue
      const href = this.attr(tag, 'href')?.trim()
      if (!href) continue
      found.push({ href, priority: isStd ? 0 : 1 })
    }
    found.sort((a, b) => a.priority - b.priority)
    const seen = new Set<string>()
    const out: string[] = []
    for (const { href } of found) {
      if (!seen.has(href)) {
        seen.add(href)
        out.push(href)
      }
    }
    return out
  }

  /** Read a (possibly unquoted) HTML attribute value from a single tag. */
  private attr(tag: string, name: string): string | undefined {
    const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i')
    const m = re.exec(tag)
    if (!m) return undefined
    return m[2] ?? m[3] ?? m[4]
  }

  // ═══════════════════════════════════════════════════════════
  // Cache (Redis, string-encoded so it round-trips through ioredis)
  // ═══════════════════════════════════════════════════════════

  /**
   * @returns `undefined` on a cache MISS, `null` on a negative HIT, or the
   *          decoded image on a positive HIT.
   */
  private async readCache(service: string): Promise<FaviconResult | null | undefined> {
    try {
      const raw = await getRedisClient().get(this.cacheKey(service))
      if (raw === null) return undefined
      if (raw === NONE_SENTINEL) return null
      const env = JSON.parse(raw) as { ct?: string; b64?: string }
      if (!env.ct || !env.b64) return undefined // corrupt → treat as miss
      return { contentType: env.ct, data: Buffer.from(env.b64, 'base64') }
    } catch {
      return undefined
    }
  }

  private async cachePositive(service: string, result: FaviconResult): Promise<void> {
    try {
      const envelope = JSON.stringify({
        ct: result.contentType,
        b64: result.data.toString('base64'),
      })
      await getRedisClient().set(this.cacheKey(service), envelope, 'EX', POSITIVE_TTL_SECONDS)
    } catch {
      // best-effort cache — never let a write failure lose the result
    }
  }

  private async cacheNegative(service: string): Promise<void> {
    try {
      await getRedisClient().set(this.cacheKey(service), NONE_SENTINEL, 'EX', NEGATIVE_TTL_SECONDS)
    } catch {
      // best-effort
    }
  }
}

export const faviconService = new FaviconService()
