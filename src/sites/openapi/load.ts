import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { Worker } from 'node:worker_threads'
import { LIMITS, specError } from './limits.js'
import type { ParsedSpec } from './extract.js'
import type { SpecFormat } from './parse.js'

/**
 * Parse an uploaded spec off the event loop, bounded: a worker thread with a capped heap
 * (LIMITS.heapMb) and a wall clock (LIMITS.parseMs from the moment it is handed the spec) after
 * which it is terminated. A YAML bomb, a pathological nesting or a huge document therefore costs at
 * most one short-lived worker, never the API process. At most MAX_PARALLEL parses run at once.
 */

const MAX_PARALLEL = 2
let running = 0

// Built: dist/sites/openapi/worker.js. From source (vitest, tsx dev) the worker is worker.ts, loaded
// through tsx registered inside the worker itself (`--import tsx` in execArgv is not applied to workers).
const fromSource = import.meta.url.endsWith('.ts')
const WORKER = fromSource ? sourceWorker() : new URL('./worker.js', import.meta.url)

function sourceWorker(): URL {
  const tsx = pathToFileURL(createRequire(import.meta.url).resolve('tsx/esm/api')).href
  const entry = new URL('./worker.ts', import.meta.url).href
  const code = `import { register } from ${JSON.stringify(tsx)}; register(); await import(${JSON.stringify(entry)})`
  return new URL(`data:text/javascript,${encodeURIComponent(code)}`)
}

/** The pin between preview and commit: the SHA-256 of the spec's exact bytes. */
export const specSha256 = (content: string) => createHash('sha256').update(content, 'utf8').digest('hex')

export async function loadSpec(content: string, format: SpecFormat = 'auto', opts: { parseMs?: number } = {}): Promise<ParsedSpec> {
  if (Buffer.byteLength(content, 'utf8') > LIMITS.bytes) throw specError('spec_too_large', `larger than ${LIMITS.bytes / 1024 / 1024} MiB`)
  if (running >= MAX_PARALLEL) throw Object.assign(specError('import_busy', 'other imports are being read; try again in a moment'), { statusCode: 429 })
  running++
  try {
    return await inWorker(content, format, opts.parseMs ?? LIMITS.parseMs)
  } finally {
    running--
  }
}

function inWorker(content: string, format: SpecFormat, parseMs: number): Promise<ParsedSpec> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER, {
      resourceLimits: { maxOldGenerationSizeMb: LIMITS.heapMb, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
    })
    let settled = false
    let clock: NodeJS.Timeout | undefined
    const finish = (settle: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(boot)
      clearTimeout(clock)
      void worker.terminate()
      settle()
    }
    const boot = setTimeout(() => finish(() => reject(specError('parser_unavailable', 'the spec parser did not start'))), LIMITS.bootMs)
    worker.on('message', (msg: { ready?: true; ok?: boolean; spec?: ParsedSpec; code?: string; message?: string }) => {
      if (msg.ready) {
        clearTimeout(boot)
        clock = setTimeout(() => finish(() => reject(specError('parse_timeout', `the spec took longer than ${parseMs} ms to read`))), parseMs)
        worker.postMessage({ content, format })
        return
      }
      finish(() => (msg.ok && msg.spec ? resolve(msg.spec) : reject(specError(msg.code ?? 'unreadable_spec', msg.message ?? 'the spec could not be read'))))
    })
    worker.on('error', (err: Error & { code?: string }) => {
      const oom = err.code === 'ERR_WORKER_OUT_OF_MEMORY'
      finish(() => reject(specError(oom ? 'spec_too_complex' : 'unreadable_spec', oom ? `reading the spec needs more than ${LIMITS.heapMb} MiB` : 'the spec could not be read')))
    })
    worker.on('exit', () => finish(() => reject(specError('spec_too_complex', 'the spec parser stopped before answering'))))
  })
}
