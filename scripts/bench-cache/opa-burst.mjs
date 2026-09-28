// A console opening fires ~49 guarded requests at once; each guard asks OPA what the caller holds.
// Cold burst of 49 concurrent rights() calls for one caller, against the local OPA (via the counting
// proxy), repeated after the 5s TTL: develop's authz/opa.js vs this branch's.
const dist = process.argv[2]
const { rights, clearAuthzCache } = await import(`${dist}/authz/opa.js`)
const out = []
for (let i = 0; i < 10; i++) {
  clearAuthzCache()
  await fetch('http://localhost:18182/__count')
  const s = performance.now()
  await Promise.all(Array.from({ length: 49 }, () => rights('dev@localhost.dev').catch(() => null)))
  const ms = performance.now() - s
  const calls = Number(await (await fetch('http://localhost:18182/__count')).text())
  out.push({ ms, calls })
}
out.sort((a, b) => a.ms - b.ms)
console.log(JSON.stringify({ p50ms: out[5].ms.toFixed(1), p95ms: out[9].ms.toFixed(1), opaCallsPerBurst: out[5].calls }))
process.exit(0)
