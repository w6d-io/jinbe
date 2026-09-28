import { describe, it, expect, afterEach } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { Writable } from 'node:stream'
import Fastify from 'fastify'
import { createLogger, captureProcessWarnings, fastifyLoggingOptions } from '../../telemetry/logger.js'

// OBS-1.1: one JSON line per event. A console.* call or a raw stdout/stderr write in the service is a
// plain-text line Loki cannot parse (control check S13). Everything goes through telemetry/logger.ts.

const SRC = join(__dirname, '..', '..')

/** Where a raw write is the right thing, and why. A new entry needs a reason as good as these. */
const ALLOWED: Record<string, string> = {
  'cli/': 'operator CLIs: their output is for a terminal, not for Loki',
  'scripts/': 'build-time scripts, never part of the running service',
  'config/env.ts': 'invalid-env line, written as JSON by hand: the logger is configured from env',
  'telemetry/register.ts': 'preloaded before the app, writes its JSON lines by hand in the logger shape',
  'audit/v1/emitter.ts': 'the audit sink failed: a JSON line to stderr that does not depend on that sink',
}

const RAW = /\bconsole\s*\.\s*(log|info|warn|error|debug|trace|dir|table)\b|\bprocess\s*\.\s*(stdout|stderr)\s*\.\s*write\b/

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sources(path)
    return /\.ts$/.test(name) && !/\.(test|spec)\.ts$/.test(name) ? [path] : []
  })
}

/** Line comments and block comments removed, so prose about "the console" is not a finding. */
function code(text: string): string[] {
  return text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).split('\n').map((l) => l.replace(/(^|[^:'"`])\/\/.*$/, '$1'))
}

describe('no plain-text logging in src (OBS-1.1)', () => {
  it('has no console.* or raw stdout/stderr write outside the allow-list', () => {
    const found: string[] = []
    for (const file of sources(SRC)) {
      const rel = relative(SRC, file).split('\\').join('/')
      if (Object.keys(ALLOWED).some((prefix) => rel === prefix || rel.startsWith(prefix))) continue
      code(readFileSync(file, 'utf8')).forEach((line, i) => {
        if (RAW.test(line)) found.push(`src/${rel}:${i + 1}: ${line.trim()}`)
      })
    }
    expect(found, 'use componentLogger(...) from telemetry/logger.ts instead').toEqual([])
  })

  it('every allow-list entry still exists (a stale entry would silently widen the next one)', () => {
    for (const prefix of Object.keys(ALLOWED)) {
      expect(() => statSync(join(SRC, prefix)), prefix).not.toThrow()
    }
  })
})

describe('process warnings (OBS-1.1)', () => {
  const saved = process.listeners('warning')
  afterEach(() => {
    process.removeAllListeners('warning')
    for (const l of saved) process.on('warning', l)
  })

  it('writes a deprecation as one JSON line at warn with its code, and nothing else', async () => {
    const lines: string[] = []
    const stream = new Writable({ write(chunk, _e, cb) { lines.push(...chunk.toString().split('\n').filter(Boolean)); cb() } })
    captureProcessWarnings(createLogger({ level: 'info', destination: stream }).child({ component: 'process' }))
    expect(process.listenerCount('warning')).toBe(1)

    process.emitWarning('requestIdLogLabel option is deprecated.', { type: 'DeprecationWarning', code: 'FSTDEP024' })
    await new Promise((r) => setImmediate(r))

    expect(lines).toHaveLength(1)
    expect(JSON.parse(lines[0])).toMatchObject({
      level: 'warn', component: 'process', msg: 'requestIdLogLabel option is deprecated.',
      warning: { name: 'DeprecationWarning', code: 'FSTDEP024' },
    })
  })

  it('the server options raise no Fastify deprecation (FSTDEP023/024)', async () => {
    const seen: string[] = []
    process.removeAllListeners('warning')
    process.on('warning', (w) => seen.push((w as Error & { code?: string }).code ?? w.name))
    const fastify = Fastify({ loggerInstance: createLogger({ level: 'silent' }), ...fastifyLoggingOptions })
    await fastify.ready()
    await new Promise((r) => setImmediate(r))
    await fastify.close()
    expect(seen.filter((c) => c.startsWith('FSTDEP'))).toEqual([])
  })
})
