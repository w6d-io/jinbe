import { createHmac } from 'crypto'
import { isIPv4, isIPv6 } from 'net'
import { env } from '../../config/env.js'

/**
 * Pseudonyms for audit/v1 (CONTROL AU-5, GDPR minimisation).
 *
 * Kratos ids are already pseudonymous: erasing the identity erases what they point to. What has no
 * id — an IP, a session id, an identifier somebody typed — is replaced by a keyed HMAC, so two events
 * about the same value can still be correlated by whoever holds the key, and nobody else. Rotating
 * AUDIT_HMAC_KEY cuts that correlation from then on.
 */

export function hmac(value: string | null | undefined): string | undefined {
  const key = env.AUDIT_HMAC_KEY
  if (!value || !key) return undefined
  return `hmac-sha256:${createHmac('sha256', key).update(value).digest('hex').slice(0, 32)}`
}

/** An IPv4 address to its /24, an IPv6 address to its /48. Anything else: nothing. */
export function ipNet(ip: string | null | undefined): string | undefined {
  if (!ip) return undefined
  const v4 = ip.startsWith('::ffff:') && isIPv4(ip.slice(7)) ? ip.slice(7) : ip
  if (isIPv4(v4)) return `${v4.split('.').slice(0, 3).join('.')}.0/24`
  if (!isIPv6(ip)) return undefined
  const [head, tail = ''] = ip.split('::')
  const left = head ? head.split(':') : []
  const right = tail ? tail.split(':') : []
  const groups = ip.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left
  return `${groups.slice(0, 3).map((g) => g.replace(/^0+(?=.)/, '').toLowerCase()).join(':')}::/48`
}

/** The browser family, which is what an investigation asks; the full string fingerprints. */
export function uaFamily(ua: string | null | undefined): string | undefined {
  if (!ua) return undefined
  if (ua.includes('Firefox')) return 'Firefox'
  if (ua.includes('Edg')) return 'Edge'
  if (ua.includes('Chrome')) return 'Chrome'
  if (ua.includes('Safari')) return 'Safari'
  if (ua.includes('curl')) return 'curl'
  if (ua.includes('kube-probe')) return 'kube-probe'
  return 'other'
}

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g

/** Replaces every address in a free string (a summary, a reason, a target label). */
export function scrubEmails(text: string): string {
  return text.replace(EMAIL, (m) => `[email ${hmac(m.toLowerCase()) ?? 'redacted'}]`).replace(/@/g, '[at]')
}
