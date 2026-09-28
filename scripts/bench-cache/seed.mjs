const N = Number(process.argv[2] ?? 500)
const groups = ['users', 'devs', 'ops', 'support', 'viewers']
const jobs = []
for (let i = 0; i < N; i++) {
  const body = {
    schema_id: 'default', state: i % 17 === 0 ? 'inactive' : 'active',
    traits: { email: `user${String(i).padStart(4, '0')}@bench.test`, name: `Bench User ${i}` },
    metadata_admin: { groups: ['users', groups[i % groups.length]], organizations: [`org-${i % 10}`] },
  }
  if (i === 0) body.traits.email = 'dev@localhost.dev'
  jobs.push(body)
}
let ok = 0
for (let i = 0; i < jobs.length; i += 25) {
  const r = await Promise.all(jobs.slice(i, i + 25).map((b) => fetch('http://localhost:14434/admin/identities', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })))
  for (const x of r) { if (x.ok) ok++; else if (ok === 0) console.error(x.status, await x.text()) }
}
console.log('seeded', ok)
