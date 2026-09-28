#!/usr/bin/env node
// Proves the protected identity traits (src/sign-in-protection/protected-traits.ts) against a running
// Kratos whose registration after.<method> and settings after.profile hooks point at jinbe's
// POST /api/webhooks/kratos/guard with the charts Jsonnet (registration: `traits`; settings:
// `traits` + `stored_traits`).
//
// API flows only — what a script does, never login-ui — so no form can help:
//   KRATOS_URL=http://localhost:4733 KRATOS_ADMIN_URL=http://localhost:4734 node scripts/kratos-protected-traits-e2e.mjs
// PASSWORD=1 when Kratos takes password sign-ups (they are then tried too); the email-code sign-up
// always runs (codes read from the courier queue on the admin API). The registration policy and bot
// check must be off.

const KRATOS = (process.env.KRATOS_URL || 'http://localhost:4733').replace(/\/+$/, '')
const ADMIN = (process.env.KRATOS_ADMIN_URL || 'http://localhost:4734').replace(/\/+$/, '')
const PROTECTED_ID = 4000915
const VICTIM = '7d0b6a4e-5f1c-4a8e-9b61-2f4d3c1e0a99'

let failed = 0
const ok = (name, cond, detail) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `\n      ${detail}`}`)
  if (!cond) failed++
}
const messageIds = (body) => [...(body?.ui?.messages ?? []), ...(body?.ui?.nodes ?? []).flatMap((n) => n.messages ?? [])].map((m) => m.id)
const json = async (url, init = {}) => {
  const res = await fetch(url, { ...init, headers: { accept: 'application/json', 'content-type': 'application/json', ...(init.headers || {}) } })
  return { status: res.status, body: await res.json().catch(() => ({})) }
}
const post = (url, body, headers) => json(url, { method: 'POST', body: JSON.stringify(body), headers })
const email = (tag) => `traits-${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@example.org`
const identityOf = async (address) => (await json(`${ADMIN}/admin/identities?credentials_identifier=${encodeURIComponent(address)}`)).body[0]

async function registerPassword(traits) {
  const flow = (await json(`${KRATOS}/self-service/registration/api`)).body
  return post(`${KRATOS}/self-service/registration?flow=${flow.id}`, { method: 'password', password: `Traits-e2e-${Math.random().toString(36).slice(2)}-Pw!`, traits })
}

async function registerCode(traits) {
  const flow = (await json(`${KRATOS}/self-service/registration/api`)).body
  const sent = await post(`${KRATOS}/self-service/registration?flow=${flow.id}`, { method: 'code', traits })
  await new Promise((r) => setTimeout(r, 500))
  const mails = (await json(`${ADMIN}/admin/courier/messages`)).body.filter((m) => m.recipient === traits.email)
  const code = mails.at(-1)?.body.match(/\b(\d{6})\b/)?.[1]
  if (!code) return { status: sent.status, body: sent.body, noCode: true }
  return post(`${KRATOS}/self-service/registration?flow=${flow.id}`, { method: 'code', code, traits })
}

async function saveProfile(token, traits) {
  const headers = { 'x-session-token': token }
  const flow = (await json(`${KRATOS}/self-service/settings/api`, { headers })).body
  return post(`${KRATOS}/self-service/settings?flow=${flow.id}`, { method: 'profile', traits }, headers)
}

const hasPassword = process.env.PASSWORD === '1'
console.log(`Kratos ${KRATOS}: sign-up by ${hasPassword ? 'password (and email code)' : 'email code'}`)

// ── Sign-up ─────────────────────────────────────────────────────────────────
const register = hasPassword ? registerPassword : registerCode
{
  const a = email('reg-person')
  const r = await register({ email: a, person_uuid: VICTIM })
  ok('sign-up with someone else\'s person_uuid is refused with the protected-trait message', r.status === 400 && messageIds(r.body).includes(PROTECTED_ID), `${r.status} ${JSON.stringify(messageIds(r.body))}`)
  ok('… and no identity was written', !(await identityOf(a)), 'identity exists')
}
{
  const a = email('reg-code')
  const r = await registerCode({ email: a, applicant_uuid: VICTIM })
  ok('email-code sign-up with an applicant_uuid is refused at the code step', r.status === 400 && messageIds(r.body).includes(PROTECTED_ID), `${r.status} ${JSON.stringify(messageIds(r.body))}`)
  ok('… and no identity was written', !(await identityOf(a)), 'identity exists')
}
{
  const a = email('reg-empty')
  const r = await register({ email: a, name: 'Ada', person_uuid: '' })
  const id = await identityOf(a)
  ok('an empty protected field (older form) signs up, and the empty value is not stored', r.status === 200 && id && !('person_uuid' in id.traits), `${r.status} ${JSON.stringify(id?.traits)}`)
}

// ── Profile ─────────────────────────────────────────────────────────────────
const a = email('profile')
const signedUp = hasPassword ? await registerPassword({ email: a, name: 'Ada' }) : await registerCode({ email: a, name: 'Ada' })
const token = signedUp.body.session_token
ok('clean sign-up gets a session', signedUp.status === 200 && !!token, `${signedUp.status} ${JSON.stringify(signedUp.body.error ?? messageIds(signedUp.body))}`)
if (token) {
  const id = await identityOf(a)
  // What an administrator (or jinbe) does: the admin API, no hook.
  const put = await json(`${ADMIN}/admin/identities/${id.id}`, { method: 'PUT', body: JSON.stringify({ schema_id: id.schema_id, state: id.state, traits: { ...id.traits, person_uuid: 'assigned-by-admin' } }) })
  ok('an administrator sets person_uuid through the admin API', put.status === 200, `${put.status}`)

  const changed = await saveProfile(token, { email: a, name: 'Ada', person_uuid: VICTIM })
  ok('profile save changing person_uuid is refused', changed.status === 400 && messageIds(changed.body).includes(PROTECTED_ID), `${changed.status} ${JSON.stringify(messageIds(changed.body))}`)
  ok('… stored value unchanged', (await identityOf(a)).traits.person_uuid === 'assigned-by-admin', JSON.stringify((await identityOf(a)).traits))

  const added = await saveProfile(token, { email: a, name: 'Ada', applicant_uuid: VICTIM })
  ok('profile save setting an applicant_uuid that was never set is refused', added.status === 400 && messageIds(added.body).includes(PROTECTED_ID), `${added.status}`)

  const dropped = await saveProfile(token, { email: a, name: 'Ada Lovelace' })
  const after = (await identityOf(a)).traits
  ok('profile save leaving person_uuid out saves the name and keeps person_uuid', dropped.status === 200 && after.name === 'Ada Lovelace' && after.person_uuid === 'assigned-by-admin', `${dropped.status} ${JSON.stringify(after)}`)

  const same = await saveProfile(token, { email: a, name: 'Ada L.', person_uuid: 'assigned-by-admin' })
  ok('profile save sending person_uuid back unchanged goes through', same.status === 200 && (await identityOf(a)).traits.name === 'Ada L.', `${same.status}`)
}

console.log(failed ? `\n${failed} failed` : '\nall passed')
process.exit(failed ? 1 : 0)
