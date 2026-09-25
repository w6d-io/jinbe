import { randomBytes } from 'crypto'

/**
 * RFC 9562 UUIDv7: 48 bits of Unix milliseconds, then random. Sorts by creation time, so an
 * event_id is also a rough cursor and index-friendly in any store the archive lands in.
 */
export function uuidv7(now: number = Date.now()): string {
  const b = randomBytes(16)
  let ms = BigInt(now)
  for (let i = 5; i >= 0; i--) {
    b[i] = Number(ms & 0xffn)
    ms >>= 8n
  }
  b[6] = (b[6] & 0x0f) | 0x70
  b[8] = (b[8] & 0x3f) | 0x80
  const h = b.toString('hex')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}
