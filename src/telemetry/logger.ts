import pino, { type DestinationStream, type Logger, type LoggerOptions } from 'pino'
import { randomUUID } from 'crypto'
import type { IncomingMessage } from 'http'
import { env } from '../config/index.js'
import { redactQueryToken } from '../middleware/require-opal-client.js'
import { logBase, traceFields } from './log-correlation.js'

/**
 * The one logger every line of this process goes through: application lines, the request line and
 * the audit line. One JSON object per line, so Loki can parse it without a multiline stage.
 *
 * `log_type` separates the three streams (`app` by default, `request` from the request logger,
 * `audit` from the audit emitter). It rides in the mixin, so a line that names its own type wins
 * and no line carries the key twice — pino would serialise a duplicate, and a JSON parser keeps
 * whichever it reads last.
 */

// Every place a credential has been seen to travel through a log call: the request/response objects
// Fastify serialises, a bare headers object, and an HTTP client's error config (axios keeps the
// outgoing headers there, capitalised).
const SECRET_HEADERS = ['.cookie', '.authorization', '["x-session-token"]', '["set-cookie"]']
const CLIENT_HEADERS = ['.Authorization', '.Cookie', '["X-Session-Token"]']

// Emails are personal data and the logs are readable by more people than the directory is. The
// subject id says who, without saying it to everyone.
const EMAIL_KEYS = ['email', 'userEmail', 'actorEmail', 'targetEmail']

export const REDACT_PATHS = [
  'req.url',
  ...SECRET_HEADERS.flatMap((h) => [`headers${h}`, `*.headers${h}`]),
  ...CLIENT_HEADERS.flatMap((h) => [`err.config.headers${h}`, `error.config.headers${h}`, `*.config.headers${h}`]),
  '*.token', '*.password', '*.client_secret',
  ...EMAIL_KEYS.flatMap((k) => [k, `*.${k}`]),
]

const REDACTED = '[redacted]'

/** A URL keeps its path and loses only its token; everything else on the list is dropped whole. */
function censor(value: unknown, path: string[]): unknown {
  return path.length === 2 && path[0] === 'req' && path[1] === 'url' ? redactQueryToken(value) : REDACTED
}

export function loggerOptions(level: string = env.LOG_LEVEL || 'info'): LoggerOptions {
  return {
    level,
    redact: { paths: REDACT_PATHS, censor },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: { level: (label) => ({ level: label }) },
    // `service` / `env` / `version` come from the SAME variables the trace SDK reads, so a line
    // cannot be filed under a service the traces do not know.
    base: { service: 'jinbe', environment: env.NODE_ENV, ...logBase() },
    // Evaluated per line: the active span is a property of the moment, not of the logger.
    mixin: () => ({ log_type: 'app', ...traceFields() }),
  }
}

export function createLogger(opts: { level?: string; destination?: DestinationStream } = {}): Logger {
  const options = loggerOptions(opts.level)
  if (opts.destination) return pino(options, opts.destination)
  if (env.NODE_ENV === 'development') {
    return pino({
      ...options,
      transport: { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss Z', ignore: 'pid,hostname' } },
    })
  }
  // Synchronous stdout: an audit line must be written before the call that produced it returns.
  return pino(options, pino.destination({ dest: 1, sync: true }))
}

// Ingress-nginx's `$req_id` is 32 hex characters; other callers send UUIDs. Anything outside this
// alphabet could close the JSON string it is written into, so it is replaced rather than escaped.
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/

/** The caller's `x-request-id` when it is a plausible id, else a fresh one. */
export function genReqId(req: IncomingMessage): string {
  const header = req.headers['x-request-id']
  const value = Array.isArray(header) ? header[0] : header
  return value && REQUEST_ID.test(value) ? value : randomUUID()
}

/** Fastify options that go with the logger: the id, its log key, and our own request line. */
export const fastifyLoggingOptions = {
  genReqId,
  requestIdLogLabel: 'request_id',
  // Fastify's two lines per request ("incoming request" / "request completed") are replaced by one
  // line from middleware/request-logger.ts, which knows the route pattern and the subject.
  disableRequestLogging: true,
}

let root: Logger | undefined

/** The process logger, created on first use so tests that never log never open stdout. */
export function rootLogger(): Logger {
  root ??= createLogger()
  return root
}
