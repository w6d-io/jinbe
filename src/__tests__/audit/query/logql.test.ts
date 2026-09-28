import { describe, it, expect } from 'vitest'
import { quote, auditQuery, auditSelector, opsLogsQuery, regexAlternation, type AuditStream } from '../../../audit/query/logql.js'

// AUD-9 / AU-12: the client never sends LogQL, and nothing it sends can change the shape of the
// query jinbe builds. Every value lands inside one double-quoted literal, and reading that literal
// back gives exactly what was sent — so a hostile string can only ever be searched FOR.

/** Go strconv.Unquote for the escapes quote() produces — what Loki does with the literal. */
function unquote(lit: string): string {
  expect(lit.startsWith('"') && lit.endsWith('"')).toBe(true)
  let out = ''
  for (let i = 1; i < lit.length - 1; i++) {
    const c = lit[i]
    if (c === '"') throw new Error(`unescaped quote at ${i} in ${lit}`)
    if (c.charCodeAt(0) < 0x20) throw new Error('raw control character inside a literal')
    if (c !== '\\') { out += c; continue }
    const n = lit[++i]
    if (n === 'n') out += '\n'
    else if (n === 'r') out += '\r'
    else if (n === 't') out += '\t'
    else if (n === '\\' || n === '"') out += n
    else if (n === 'u') { out += String.fromCharCode(parseInt(lit.slice(i + 1, i + 5), 16)); i += 4 }
    else throw new Error(`unknown escape \\${n}`)
  }
  return out
}

/** Splits a query into its skeleton (everything outside string literals) and its literals. */
function tokens(query: string): { skeleton: string; literals: string[] } {
  let skeleton = ''
  const literals: string[] = []
  for (let i = 0; i < query.length; i++) {
    if (query[i] !== '"') { skeleton += query[i]; continue }
    let j = i + 1
    while (j < query.length && query[j] !== '"') j += query[j] === '\\' ? 2 : 1
    literals.push(query.slice(i, j + 1))
    skeleton += '"_"'
    i = j
  }
  return { skeleton, literals }
}

// Deterministic PRNG: a failing seed can be replayed.
function rng(seed: number) {
  return () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff }
}
const HOSTILE = ['"', '\\', '`', '}', '{', '|', '=', '~', '!', '\n', '\r', '\t', '\u0000', '\u001f', ' ', 'a', 'Z', '0', '.', '*', '(', ')', '$', '^', '[', ']', 'é', '日', ' ', '#', ',', 'or', 'and', '|=', '!~', '} |= "', '`org_id`']
function hostile(next: () => number, max = 64): string {
  let s = ''
  const len = 1 + Math.floor(next() * 20)
  while (s.length < len) s += HOSTILE[Math.floor(next() * HOSTILE.length)]
  return s.slice(0, max)
}

describe('quote()', () => {
  it('round-trips any string through Loki\'s unquoting (property, 2000 hostile strings)', () => {
    const next = rng(42)
    for (let i = 0; i < 2000; i++) {
      const s = hostile(next)
      expect(unquote(quote(s))).toBe(s)
    }
  })

  it('escapes the classic probes', () => {
    expect(quote('"} |= "')).toBe('"\\"} |= \\""')
    expect(quote('a\\"b')).toBe('"a\\\\\\"b"')
    expect(quote('x\ny')).toBe('"x\\ny"')
  })
})

const LABEL: AuditStream = { mode: 'label', container: 'jinbe' }
const JSON_: AuditStream = { mode: 'json', container: 'jinbe' }

describe('auditSelector() / LOKI_AUDIT_SELECTOR', () => {
  it('label: selects the log_type stream label, pinned to the namespace', () => {
    expect(auditSelector('auth', LABEL)).toBe('{log_type="audit", namespace="auth"}')
    expect(auditSelector(undefined, LABEL)).toBe('{log_type="audit"}')
  })

  it('json: jinbe\'s container, pinned to the namespace, narrowed on the raw line', () => {
    expect(auditSelector('auth', JSON_)).toBe('{namespace="auth", container="jinbe"} |= "\\"log_type\\":\\"audit\\""')
    expect(auditSelector(undefined, JSON_)).toBe('{container="jinbe"} |= "\\"log_type\\":\\"audit\\""')
    expect(unquote(tokens(auditSelector('auth', JSON_)).literals[2])).toBe('"log_type":"audit"')
  })

  it('json: the parsed log_type decides, right after | json and before every other filter', () => {
    const q = auditQuery({ orgs: ['org-1'], q: 'hello' }, 'auth', JSON_)
    expect(q).toBe('{namespace="auth", container="jinbe"} |= "\\"log_type\\":\\"audit\\"" |= "hello" | json | log_type="audit" | org_id="org-1"')
  })

  it('json: a hostile container name is still one literal', () => {
    const q = auditSelector('auth', { mode: 'json', container: '"} |= "x' })
    expect(tokens(q).skeleton).toBe(tokens(auditSelector('auth', JSON_)).skeleton)
  })

  it('the default comes from the environment and is json until the collector promotes the label', () => {
    expect(auditQuery({}, 'auth')).toBe(auditQuery({}, 'auth', JSON_))
  })
})

describe.each([['label', LABEL], ['json', JSON_]] as const)('auditQuery() — %s mode', (_mode, stream) => {
  const benign = auditQuery({ orgs: ['org-1'], actor: 'a', target: 't', site: 's', events: ['org.grants.changed'], category: 'authz', result: 'denied', severity: 'high', traceId: 'abc', q: 'hello' }, undefined, stream)
  const selector = auditSelector(undefined, stream)
  // The literals the mode itself writes (selector, `log_type="audit"`), never a caller value.
  const fixed = new Set([...tokens(selector).literals, '"audit"'])

  it('always selects the audit stream, and only through the selector', () => {
    expect(benign.startsWith(selector)).toBe(true)
    expect(auditQuery({}, undefined, stream).startsWith(selector)).toBe(true)
  })

  it('filters org, actor, target, site, event, category, result, severity, trace and free text', () => {
    expect(benign).toContain('|= "hello"')
    expect(benign).toContain('| json')
    for (const f of ['org_id="org-1"', 'actor_id="a"', 'target_id="t"', 'site="s"', 'event="org.grants.changed"', 'category="authz"', 'result="denied"', 'severity="high"', 'trace_id="abc"']) {
      expect(benign).toContain(f)
    }
  })

  it('a hostile value in ANY field leaves the query\'s structure untouched (property)', () => {
    const shape = tokens(benign).skeleton
    const next = rng(7)
    for (let i = 0; i < 1000; i++) {
      const v = hostile(next)
      // A value ending in `.*` is a prefix by design (and allow-listed upstream); keep it exact here.
      const ev = v.endsWith('.*') ? `${v}x` : v
      const q = auditQuery({ orgs: [v], actor: v, target: v, site: v, events: [ev], category: v, result: v, severity: v, traceId: v, q: v }, undefined, stream)
      const t = tokens(q)
      expect(t.skeleton).toBe(shape)
      for (const lit of t.literals) expect(() => unquote(lit)).not.toThrow()
      expect(unquote(t.literals.find((l) => !fixed.has(l))!)).toBe(v)
    }
  })

  it('a hostile namespace stays inside its literal', () => {
    expect(tokens(auditQuery({}, '"} |= "x', stream)).skeleton).toBe(tokens(auditQuery({}, 'auth', stream)).skeleton)
  })

  it('an event prefix becomes an escaped regex, never a raw one', () => {
    const q = auditQuery({ events: ['org.grants.*'] }, undefined, stream)
    expect(q).toContain('event=~"org\\\\.grants\\\\..*"')
  })

  it('several orgs (an org admin of two) become one anchored alternation of escaped values', () => {
    const q = auditQuery({ orgs: ['a.b', 'c|d'] }, undefined, stream)
    expect(q).toContain(`org_id=~${regexAlternation(['a.b', 'c|d'])}`)
    expect(unquote(regexAlternation(['a.b', 'c|d']))).toBe('a\\.b|c\\|d')
  })

  it('an empty org list scopes to nothing rather than to everything', () => {
    expect(() => auditQuery({ orgs: [] }, undefined, stream)).toThrow()
  })

  it('subject matches the user as actor OR target', () => {
    expect(auditQuery({ subject: 'u-1' }, undefined, stream)).toContain('| actor_id="u-1" or target_id="u-1"')
  })
})

describe('opsLogsQuery()', () => {
  it('label: pins the namespace and excludes the audit stream by its label', () => {
    const q = opsLogsQuery({ namespace: 'auth' }, LABEL)
    expect(q).toBe('{namespace="auth", log_type!="audit"}')
  })

  it('json: pins the namespace and excludes audit lines on the raw line, whatever their spacing', () => {
    const q = opsLogsQuery({ namespace: 'auth', container: 'jinbe' }, JSON_)
    expect(q).toBe('{namespace="auth", container="jinbe"} !~ "\\"log_type\\"\\\\s*:\\\\s*\\"audit\\""')
    // RE2 and JS agree on this pattern: test it as Loki would run it.
    const re = new RegExp(unquote(tokens(q).literals[2]))
    expect(re.test('{"level":30,"log_type":"audit","event":"x"}')).toBe(true)
    expect(re.test('{"log_type" : "audit"}')).toBe(true)
    expect(re.test('{"log_type":"app","msg":"saw \\"log_type\\":\\"audit\\""}')).toBe(false)
    expect(re.test('{"log_type":"request"}')).toBe(false)
  })

  it.each([['label', LABEL], ['json', JSON_]] as const)('%s: escapes the namespace and the ids too', (_mode, stream) => {
    const q = opsLogsQuery({ namespace: 'a"b', requestId: 'x"} |= "', container: 'jinbe' }, stream)
    const t = tokens(q)
    expect(t.skeleton).toBe(tokens(opsLogsQuery({ namespace: 'n', requestId: 'r', container: 'c' }, stream)).skeleton)
  })

  it('the default comes from the environment (json)', () => {
    expect(opsLogsQuery({ namespace: 'auth' })).toBe(opsLogsQuery({ namespace: 'auth' }, JSON_))
  })
})
