import { createHash } from 'node:crypto'
import { createGzip } from 'node:zlib'
import { pack } from 'tar-stream'
import { allGroupMemberships } from './organisation-store.js'

/**
 * Which groups each person is in, packaged the way a policy engine takes data.
 *
 * A bundle rather than a push: every engine replica fetches it for itself, so nothing has to know
 * how many there are, and a replica that starts late catches up on its own. And it keeps the last
 * one it activated — so this service can be down while decisions carry on at full speed.
 *
 * ROOTS ARE THE LOAD-BEARING PART. Declaring `ory/membership` means this bundle owns that subtree and
 * nothing else: the route tables and roles delivered by another mechanism are untouched by it. Without
 * roots, a bundle replaces everything the engine holds — which is how a small change to one dataset
 * silently deletes the rest.
 *
 * There is no "empty is fine" path: reading the store either answers or raises. An unreachable store
 * must never be served as "nobody belongs to anything", because the engine would activate it and
 * remove everybody's access in one poll.
 */
export interface Membership {
  /** The bundle itself, gzipped tar. */
  body: Buffer
  /** Content hash — the engine's bundle revision, and this response's ETag. */
  revision: string
}

const ROOT = 'ory/membership'

let cached: Membership | null = null

/**
 * Build it, or answer the cached one when nothing changed.
 *
 * Keyed on the content rather than on a clock: two builds of an unchanged directory produce the same
 * revision, so the engine's poll costs a 304 and the revision it reports stays meaningful.
 */
export async function membershipBundle(): Promise<Membership> {
  const held = await allGroupMemberships()
  const data = Object.fromEntries([...held.entries()].sort(([a], [b]) => a.localeCompare(b)))
  const payload = JSON.stringify({ ory: { membership: data } }, null, 2)
  const revision = createHash('sha256').update(payload).digest('hex').slice(0, 16)

  if (cached?.revision === revision) return cached

  const manifest = JSON.stringify({ revision, roots: [ROOT] }, null, 2)
  cached = { body: await archive([
    { name: '.manifest', content: manifest },
    { name: 'data.json', content: payload },
  ]), revision }
  return cached
}

/** Emptied between tests; nothing else may call it. */
export function forgetMembershipBundle(): void {
  cached = null
}

function archive(entries: readonly { name: string; content: string }[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const tar = pack()
    const gzip = createGzip()
    const chunks: Buffer[] = []

    gzip.on('data', (chunk: Buffer) => chunks.push(chunk))
    gzip.on('end', () => resolve(Buffer.concat(chunks)))
    gzip.on('error', reject)
    tar.on('error', reject)
    tar.pipe(gzip)

    for (const entry of entries) {
      const buffer = Buffer.from(entry.content, 'utf-8')
      tar.entry({ name: entry.name, size: buffer.length }, buffer)
    }
    tar.finalize()
  })
}
