import { parentPort } from 'node:worker_threads'
import { SpecError } from './limits.js'
import { parseSpecSync, type SpecFormat } from './parse.js'

/**
 * The parse worker (load.ts): says it is ready once its modules are loaded, parses the one spec it
 * is then sent, answers, and is terminated. Its heap is capped by the parent's resourceLimits and
 * its wall clock by the parent's timer.
 */

parentPort?.once('message', (msg: { content: string; format: SpecFormat }) => {
  try {
    parentPort?.postMessage({ ok: true, spec: parseSpecSync(msg.content, msg.format) })
  } catch (e) {
    const known = e instanceof SpecError
    parentPort?.postMessage({ ok: false, code: known ? e.code : 'unreadable_spec', message: known ? e.message : 'the spec could not be read' })
  }
})
parentPort?.postMessage({ ready: true })
