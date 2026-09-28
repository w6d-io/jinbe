#!/usr/bin/env node
// Proves the sign-in guard against a running Kratos whose registration/login `after` hooks point at
// jinbe's POST /api/webhooks/kratos/guard (charts: selfservice.flows.*.after, see src/sign-in-protection).
//
// It talks to Kratos' API flows directly — what a scanner does (GET /self-service/registration/api,
// then POST the form) — never through login-ui, so nothing browser-side can help.
//
//   KRATOS_URL=https://auth.example.com node scripts/kratos-guard-e2e.mjs
//     probe only: expects the bot check to be ON for registration and a token-less sign-up refused
//
//   KRATOS_URL=http://localhost:4633 GUARD_SET='docker exec -i guard-redis redis-cli -x HSET rbac:config sign_in_protection' \
//   node scripts/kratos-guard-e2e.mjs
//     full matrix: GUARD_SET receives the settings JSON on stdin and the script waits out jinbe's 5 s cache
//
// Token: CAPTCHA_TOKEN (default Cloudflare's dummy token). EXPECT_TOKEN=pass (jinbe runs Turnstile's
// always-pass test secret) or EXPECT_TOKEN=fail (the always-fail secret: every token must be refused).
import { execSync } from 'node:child_process'

const KRATOS = (process.env.KRATOS_URL || 'http://localhost:4633').replace(/\/+$/, '')
const SET = process.env.GUARD_SET || ''
const TOKEN = process.env.CAPTCHA_TOKEN || 'XXXX.DUMMY.TOKEN.XXXX'
const TOKEN_PASSES = (process.env.EXPECT_TOKEN || 'pass') !== 'fail'
const CACHE_MS = Number(process.env.GUARD_CACHE_MS || 5500)

let failed = 0
const ok = (name, cond, detail) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : `\n      ${detail}`}`)
  if (!cond) failed++
}

const settings = (p = {}) => ({
  captcha: { flows: { registration: false, login: false, recovery: false, verification: false, ...(p.flows || {}) }, failMode: p.failMode || 'closed' },
  registration: { mode: 'open', allowEmails: [], allowDomains: [], denyDomains: [], blockDisposable: false, ...(p.registration || {}) },
})

async function apply(p) {
  execSync(SET, { input: JSON.stringify(settings(p)), stdio: ['pipe', 'ignore', 'inherit'] })
  await new Promise((r) => setTimeout(r, CACHE_MS))
}

/** Every message Kratos put on the flow (form-level and per node) — [{id, text}]. */
function messagesOf(body) {
  const ui = body?.ui ?? {}
  return [...(ui.messages ?? []), ...(ui.nodes ?? []).flatMap((n) => n.messages ?? [])].map((m) => ({ id: m.id, text: m.text }))
}

async function register(email, token) {
  const init = await fetch(`${KRATOS}/self-service/registration/api`, { headers: { accept: 'application/json' } })
  const flow = await init.json()
  const body = { method: 'password', password: `Guard-e2e-${Math.random().toString(36).slice(2)}-Pw!`, traits: { email } }
  if (token !== undefined) body.transient_payload = { captcha_token: token }
  const res = await fetch(`${KRATOS}/self-service/registration?flow=${flow.id}`, {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  return { status: res.status, json, messages: messagesOf(json), password: body.password }
}

async function login(identifier, password, token) {
  const init = await fetch(`${KRATOS}/self-service/login/api`, { headers: { accept: 'application/json' } })
  const flow = await init.json()
  const body = { method: 'password', identifier, password }
  if (token !== undefined) body.transient_payload = { captcha_token: token }
  const res = await fetch(`${KRATOS}/self-service/login?flow=${flow.id}`, {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  return { status: res.status, json, messages: messagesOf(json) }
}

const hasId = (r, id) => r.messages.some((m) => m.id === id)
const show = (r) => `HTTP ${r.status} ${JSON.stringify(r.messages)}`
const unique = (local, domain = 'example.org') => `${local}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}@${domain}`

// 1. The scanner's call: registration API flow, no token.
if (SET) await apply({ flows: { registration: true } })
const scanner = await register(unique('scanner'))
ok('registration API flow without a bot-check token is refused (400, 4000901)', scanner.status === 400 && hasId(scanner, 4000901), show(scanner))
ok('… and no session was issued', !scanner.json.session_token && !scanner.json.session, JSON.stringify(scanner.json).slice(0, 200))

if (SET) {
  const good = await register(unique('human'), TOKEN)
  if (TOKEN_PASSES) ok('registration with a passing token: account created, session issued', good.status === 200 && !!good.json.session_token, show(good))
  else ok('registration with a token the provider rejects: refused (4000902)', good.status === 400 && hasId(good, 4000902), show(good))

  await apply({ registration: { mode: 'closed' } })
  const closed = await register(unique('closed'))
  ok('closed: refused with the closed message (4000911)', closed.status === 400 && hasId(closed, 4000911), show(closed))

  await apply({ registration: { mode: 'allowlist', allowDomains: ['corp.example'], allowEmails: ['guest@example.net'] } })
  const outsider = await register(unique('outsider'))
  ok('allowlist: an unlisted address is refused (4000912)', outsider.status === 400 && hasId(outsider, 4000912), show(outsider))
  const insider = await register(unique('insider', 'corp.example'))
  ok('allowlist: an address of an allowed domain signs up', insider.status === 200, show(insider))

  await apply({ registration: { blockDisposable: true } })
  const burner = await register(unique('burner', 'mailinator.com'))
  ok('disposable inbox refused when the switch is on (4000913)', burner.status === 400 && hasId(burner, 4000913), show(burner))

  // Login: an account made with no protection on, then the bot check turned on for sign-in.
  await apply({})
  const email = unique('login')
  const made = await register(email)
  await apply({ flows: { login: true } })
  const noTok = await login(email, made.password)
  ok('login with the right password but no token: refused before the session (4000901)', noTok.status === 400 && hasId(noTok, 4000901) && !noTok.json.session_token, show(noTok))
  const wrong = await login(email, 'not-the-password')
  ok('login with a wrong password: Kratos answers first ("credentials invalid", 4000006) — the known oracle', wrong.status === 400 && hasId(wrong, 4000006), show(wrong))
  const withTok = await login(email, made.password, TOKEN)
  if (TOKEN_PASSES) ok('login with the right password and a passing token: session issued', withTok.status === 200 && !!withTok.json.session_token, show(withTok))
  else ok('login with a token the provider rejects: refused (4000902)', withTok.status === 400 && hasId(withTok, 4000902), show(withTok))

  await apply({})
  const open = await register(unique('open'))
  ok('everything off again: open sign-up works', open.status === 200, show(open))
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
