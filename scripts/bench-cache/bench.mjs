// Before/after latency per route against three jinbe builds sharing one seeded Kratos (500
// identities) and Redis: develop (13001), this branch (13002), this branch with CACHE_ENABLED=false
// (13003). Kratos and OPA sit behind counting proxies, so each row also reports upstream calls per
// request. Servers are measured one after another, never concurrently.
const SERVERS = { develop: 13001, cache: 13002, 'cache-off': 13003 }
const N = Number(process.env.N ?? 40)
const OPAL = { authorization: 'Bearer bench-opal-client-token-0123456789abcdef0123' }
const ROUTES = [
  ['users list (page 250)', '/api/admin/users?page_size=250'],
  ['users search', '/api/admin/users/search?q=bench&limit=50'],
  ['rbac users', '/api/admin/rbac/users'],
  ['stats', '/api/admin/stats'],
  ['me/organizations', '/api/me/organizations'],
  ['access review', '/api/admin/access-review'],
  ['whoami', '/api/whoami'],
  ['service roles', '/api/admin/rbac/services/jinbe/roles'],
  ['sites list', '/api/admin/sites'],
  ['OPAL bindings feed', '/api/admin/rbac/bindings', OPAL],
]
const count = async (port) => Number(await (await fetch(`http://localhost:${port}/__count`)).text())
const q = (a, p) => a[Math.min(a.length - 1, Math.floor(a.length * p))]

const MODE = process.env.MODE ?? 'warm'
const results = {}
if (MODE === 'spaced') {
  // A console used at human pace: every route once per round, rounds 6s apart — past develop's 5s
  // in-process TTLs, so each read there pays its upstream again; the shared cache serves stale and
  // refreshes behind.
  const ROUNDS = Number(process.env.ROUNDS ?? 6)
  const t = {}
  const calls = {}
  for (let round = 0; round < ROUNDS; round++) {
    for (const [name, port] of Object.entries(SERVERS)) {
      for (const [label, path, headers] of ROUTES) {
        await count(14435); await count(18182)
        const s = performance.now()
        const r = await fetch(`http://localhost:${port}${path}`, { headers })
        await r.arrayBuffer()
        const ms = performance.now() - s
        const k = await count(14435), o = await count(18182)
        if (round === 0) continue // first round primes every server
        ;((t[label] ??= {})[name] ??= []).push(ms)
        const c = ((calls[label] ??= {})[name] ??= { kratos: 0, opa: 0, status: r.status })
        c.kratos += k / (ROUNDS - 1); c.opa += o / (ROUNDS - 1)
      }
    }
    await new Promise((r) => setTimeout(r, 6_000))
  }
  for (const [label, byServer] of Object.entries(t)) {
    for (const [name, a] of Object.entries(byServer)) {
      a.sort((x, y) => x - y)
      ;(results[label] ??= {})[name] = { status: calls[label][name].status, p50: q(a, 0.5), p95: q(a, 0.95), kratos: calls[label][name].kratos, opa: calls[label][name].opa }
    }
  }
} else for (const [name, port] of Object.entries(SERVERS)) {
  for (const [label, path, headers] of ROUTES) {
    const url = `http://localhost:${port}${path}`
    let status = 0
    for (let i = 0; i < 3; i++) status = (await fetch(url, { headers })).status
    await count(14435); await count(18182)
    const t = []
    for (let i = 0; i < N; i++) {
      const s = performance.now()
      const r = await fetch(url, { headers })
      await r.arrayBuffer()
      t.push(performance.now() - s)
    }
    const kratos = (await count(14435)) / N
    const opa = (await count(18182)) / N
    t.sort((a, b) => a - b)
    ;(results[label] ??= {})[name] = { status, p50: q(t, 0.5), p95: q(t, 0.95), kratos, opa }
  }
  // A console opening: 49 guarded reads at once, 15 times (wall time per burst).
  const bursts = []
  for (let i = 0; i < 15; i++) {
    const s = performance.now()
    await Promise.all(Array.from({ length: 49 }, () => fetch(`http://localhost:${port}/api/admin/rbac/services/jinbe/roles`).then((r) => r.arrayBuffer())))
    bursts.push(performance.now() - s)
  }
  bursts.sort((a, b) => a - b)
  ;(results['49 concurrent service reads (burst wall)'] ??= {})[name] = { status: 200, p50: q(bursts, 0.5), p95: q(bursts, 0.95), kratos: 0, opa: 0 }
}

const f = (n) => (Number.isNaN(n) ? '-' : n < 10 ? n.toFixed(2) : n.toFixed(1))
console.log(MODE === 'spaced' ? `MODE=spaced: one request per route per round, rounds 6s apart (first round discarded). ms; kratos/opa = upstream calls per request.` : `N=${N} sequential requests per route, warm (after 3 warm-ups). ms; kratos/opa = upstream calls per request.`)
console.log('| route | status | develop p50 / p95 | cache p50 / p95 | cache-off p50 / p95 | speedup p50 | kratos calls dev→cache | opa calls dev→cache |')
console.log('|---|---|---|---|---|---|---|---|')
for (const [label, r] of Object.entries(results)) {
  const d = r.develop, c = r.cache, o = r['cache-off']
  console.log(`| ${label} | ${d.status}/${c.status}/${o.status} | ${f(d.p50)} / ${f(d.p95)} | ${f(c.p50)} / ${f(c.p95)} | ${f(o.p50)} / ${f(o.p95)} | ${(d.p50 / c.p50).toFixed(1)}x | ${f(d.kratos)} → ${f(c.kratos)} | ${f(d.opa)} → ${f(c.opa)} |`)
}
