import { z } from 'zod'
import dotenv from 'dotenv'
import { checkAdminPasswordHardening, describeAdminPasswordWeakness } from './admin-password.js'

// Load environment variables
dotenv.config()

// FQDN regex: at least one dot, alphanumeric + hyphens, no scheme/path/port.
// Catches mistakes like "http://app.example.com" and "app.example.com:8080".
const fqdnSchema = z
  .string()
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i, {
    message: 'must be a bare FQDN (no scheme, no port, no path)',
  })

// Environment schema with validation
export const envSchema = z.object({
  // Server
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('production'),
  PORT: z.string().transform(Number).pipe(z.number().positive()).default('3000'),
  HOST: z.string().default('0.0.0.0'),
  BASE_URL: z.string().url().optional(),

  // The key the address-change audit hashes are keyed with when AUDIT_HMAC_KEY is unset
  // (services/email-change.service.ts).
  ENCRYPTION_KEY: z.string().min(32, 'ENCRYPTION_KEY must be at least 32 characters'),

  // CORS
  CORS_ORIGIN: z.string().default('*'),
  CORS_CREDENTIALS: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // Set 'true' in production when oathkeeper handles CORS — prevents
  // duplicate Access-Control-Allow-Origin headers (oathkeeper emits its
  // own, jinbe layering its own causes browser rejection).
  DISABLE_CORS: z.string().default('false'),

  // Rate Limiting
  RATE_LIMIT_MAX: z.string().transform(Number).pipe(z.number().positive()).default('100'),
  RATE_LIMIT_TIME_WINDOW: z.string().transform(Number).pipe(z.number().positive()).default('60000'),

  // Client address (utils/client-ip.ts): Fastify trusts this many hops, the socket peer first, and
  // request.ip is the X-Forwarded-For entry after them — never the client-written leftmost one. The
  // default, 1, is Envoy (or nginx) -> Oathkeeper -> jinbe: Oathkeeper forwards the header as it got
  // it and appends nothing, Envoy appends the client. 0 = the socket peer, the header ignored.
  TRUSTED_PROXY_HOPS: z.coerce.number().int().min(0).max(10).default(1),
  // 'true' only where every external request reaches jinbe through Envoy, which overwrites
  // x-envoy-external-address: the header is then preferred to the hop count. Anywhere a client can
  // reach Oathkeeper without Envoy (an nginx ingress) the header is the client's to write.
  TRUST_ENVOY_EXTERNAL_ADDRESS: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // Metrics — Prometheus is served on its own port (0 turns it off), never on the app port the
  // gateway fronts. With a token set, a scrape must present it as a bearer.
  METRICS_PORT: z.coerce.number().int().min(0).max(65535).default(9464),
  METRICS_HOST: z.string().default('0.0.0.0'),
  METRICS_TOKEN: z.string().min(16).optional(),

  // API Documentation
  ENABLE_SWAGGER: z
    .string()
    .transform((val) => val === 'true')
    .default('true'),

  // Optional
  COMMIT_SHA: z.string().optional(),
  RELEASE_NAME: z.string().optional(),
  APP_VERSION: z.string().optional(),

  // Development only - bypass authentication (NEVER use in production!)
  DEV_BYPASS_AUTH: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // Fake user email for dev bypass
  DEV_USER_EMAIL: z.string().email().optional(),
  // The staff role the dev bypass acts as (policy/roles.ts), so local development can exercise the
  // real matrix: DEV_ROLE=support. Defaults to super_admin (`*`), what the bypass always granted.
  DEV_ROLE: z.enum(['developer', 'support', 'ops', 'security', 'super_admin']).default('super_admin'),

  // Kratos APIs
  // ─── Authentication methods ───
  // Each way of proving who is calling is a switch, so a deployment takes the ones it wants and
  // nothing else. Both default to what this service did before they existed: the Kratos session
  // cookie on, the bearer off.
  //
  // A deployment whose console holds an OIDC token has no cookie to send, and one that turns the
  // cookie off stops accepting session-based callers entirely — which is the point: an
  // authentication method left on is an authentication method that can be used.
  AUTH_COOKIE_ENABLED: z
    .string()
    .transform((v) => v === 'true')
    .default('true'),
  AUTH_BEARER_ENABLED: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),

  // ─── OIDC bearer ───
  // Where a bearer token is verified against. No default: a wrong or missing issuer must fail the
  // verification rather than quietly accept a token from somewhere else.
  OIDC_ISSUER: z.string().url().optional(),
  OIDC_JWKS_URL: z.string().url().optional(),
  // The audience this service answers to. A token minted for another audience is not for us, and
  // accepting it would let any holder of any token of that issuer in.
  OIDC_AUDIENCE: z.string().optional(),

  // ─── Where organisations come from ───
  // `local` reads them from this service's own model, administered through the console. `claim`
  // reads them from the verified token, so whoever issues it decides and this service asks nobody
  // — which is how a deployment plugs its own directory in without this code knowing it exists.
  // local     — inferred from group memberships by the policy, as this service has always done
  // directory  — records this service owns, in ORGANISATION_DATABASE_URL
  // claim      — whatever the verified token asserts; this service consults nothing
  // Whether this service is still a rule source. `service` — the engines fetch the rules from here
  // at runtime, so the console's editors change what is enforced. `gitops` — the edge is fed from
  // Rule resources and the policy engine from labelled ConfigMaps, both synced from a repository,
  // and a write here would land in a store nothing reads. Reported to the console so it can stop
  // offering an edit that cannot take effect; it changes nothing this service does.
  RULES_SOURCE: z.enum(['service', 'gitops']).default('service'),
  // `local` is gone: it asked an engine for a path the model no longer has, so as the DEFAULT it
  // scoped every caller to nothing unless a deployment overrode it.
  ORGANISATION_SOURCE: z.enum(['directory', 'claim']).default('directory'),

  // Which store holds the `directory` records.
  // kratos   — memberships on the Kratos identity (organization_id + metadata_admin), the registry
  //            (name, tenant, settings, entitlements) in Redis. One source of truth, nothing extra
  //            to run. The default when no database URL is set.
  // postgres — the relational store in ORGANISATION_DATABASE_URL (the default when it is set).
  ORGANISATION_STORE: z.enum(['kratos', 'postgres']).optional(),

  // Where organisations live in the `postgres` store. Absent with ORGANISATION_STORE=postgres, the
  // organisation routes answer 503 not_configured rather than that nobody belongs anywhere.
  ORGANISATION_DATABASE_URL: z.string().optional(),
  // The authority that signed the database's certificate, as PEM. A certificate authority is
  // public by nature, so it belongs in configuration rather than in a secret store. Without it a
  // private authority cannot be verified, and the choice is then between refusing the connection
  // and trusting whatever answers — this makes the third option available.
  ORGANISATION_DATABASE_CA: z.string().optional(),
  ORGANISATION_DATABASE_POOL_MAX: z.coerce.number().int().positive().default(5),
  ORGANISATION_DATABASE_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
  // The claim the organisations are read from in `claim` mode. Named rather than fixed: a claim
  // name is a deployment's vocabulary, not this service's.
  ORGANISATION_CLAIM: z.string().default('orgs'),

  KRATOS_PUBLIC_URL: z.string().url().default('http://kratos-public:80'),
  KRATOS_ADMIN_URL: z.string().url().default('http://kratos-admin:80'),
  // Sent as `Authorization: Bearer <token>` on every Kratos admin call, for an admin API behind the
  // chart's token-checking sidecar (kratos.adminAuth). Empty = no header. Never logged.
  KRATOS_ADMIN_TOKEN: z.string().optional(),
  // Per-request timeout (ms) for Kratos Admin directory calls. Bounds the
  // OPAL /bindings directory walk so a HUNG Kratos aborts and the route can
  // fail closed instead of hanging the datasource fetch.
  KRATOS_REQUEST_TIMEOUT_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().positive())
    .default('10000'),

  // Path to the kratos.yml the Kratos process watches (shared mount).
  // Enables the /api/admin/auth/methods toggles — jinbe patches
  // selfservice.methods there and Kratos hot-reloads. Unset → feature off (501).
  KRATOS_CONFIG_PATH: z.string().optional(),

  // Shared secret authenticating the Kratos after-hook webhook
  // (POST /api/webhooks/kratos). Kratos sends it as an api_key header; jinbe
  // constant-time compares it and rejects (401, emitting nothing) on mismatch.
  // Vault-injected in production; when unset the webhook rejects every call.
  KRATOS_WEBHOOK_SECRET: z.string().optional(),

  // ─── Sign-in protection: the bot check (sign-in-protection/captcha.ts) ───
  // Which flows ask for it is a platform setting edited in the console; WHO checks the answer is
  // configured here. The secret is Vault-injected and never leaves this process: no API returns it,
  // the console only learns whether it is set. Provider or site key or secret missing → "not
  // configured", and a flow that asks for the check follows CAPTCHA fail mode (closed by default).
  CAPTCHA_PROVIDER: z.enum(['turnstile', 'hcaptcha', 'recaptcha']).default('turnstile'),
  CAPTCHA_SITE_KEY: z.string().min(1).optional(),
  CAPTCHA_SECRET_KEY: z.string().min(1).optional(),
  // One siteverify call; beyond it the provider counts as unavailable.
  CAPTCHA_VERIFY_TIMEOUT_MS: z.coerce.number().int().positive().max(10000).default(3000),
  // Hostnames the widget may have been solved on (login-ui's), comma-separated. Empty: not checked.
  CAPTCHA_EXPECTED_HOSTNAMES: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)),
  // reCAPTCHA v3 only: the lowest score that passes.
  CAPTCHA_RECAPTCHA_MIN_SCORE: z.coerce.number().min(0).max(1).default(0.5),
  // The providers' published test keys pass (or fail) every visitor. Refused in production unless
  // this says a sandbox wants them.
  CAPTCHA_ALLOW_TEST_KEYS: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),

  // ─── Sign-in gate (sign-in-protection/gate.ts) ───
  // Kratos sends a code the moment an address is submitted, before any hook can stop it. With the
  // gate on, the bootstrap rules send POST /self-service/{login,registration,recovery,verification}
  // through jinbe, which checks the bot-check token and the code-sending rate limits before Kratos
  // sees the submit. Off: the rules go straight to Kratos, as before (the endpoint exists either way).
  SIGN_IN_GATE_ENABLED: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),
  // Code-sending submits allowed per address and per client IP, within one window.
  SIGN_IN_GATE_CODES_PER_ADDRESS: z.coerce.number().int().positive().default(5),
  SIGN_IN_GATE_CODES_PER_IP: z.coerce.number().int().positive().default(20),
  SIGN_IN_GATE_WINDOW_S: z.coerce.number().int().positive().default(900),
  // How long a token the gate verified stays good for the Kratos guard hook of the same flow (the
  // provider answers a second siteverify of one token with timeout-or-duplicate).
  SIGN_IN_GATE_VERIFIED_TTL_S: z.coerce.number().int().positive().max(3600).default(300),

  // ─── Protected identity traits (sign-in-protection/protected-traits.ts) ───
  // Kratos traits only an administrator (or jinbe, through the admin API) may set, comma-separated.
  // The gateway forwards them as trusted headers (x-person-uuid, x-applicant-uuid), so a sign-up
  // carrying one is refused and a profile save cannot change one — enforced by the Kratos guard
  // web_hook, whatever the form shows. login-ui reads the list from the public settings and never
  // renders these fields. Empty: nothing protected.
  PROTECTED_TRAITS: z
    .string()
    .default('person_uuid,applicant_uuid')
    .transform((v) => [...new Set(v.split(',').map((s) => s.trim()).filter(Boolean))])
    .refine((l) => l.every((n) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(n)), 'PROTECTED_TRAITS: trait names only (letters, digits, _)')
    .refine((l) => !l.includes('email'), 'PROTECTED_TRAITS: email is the sign-up identifier and cannot be protected'),

  // Hydra Admin API (private — never expose publicly). Used to manage
  // OAuth2 clients that back per-organization M2M API keys.
  HYDRA_ADMIN_URL: z.string().url().default('http://auth-hydra-admin:4445'),
  // As KRATOS_ADMIN_TOKEN, for the Hydra admin API (hydra.adminAuth). Empty = no header.
  HYDRA_ADMIN_TOKEN: z.string().optional(),
  // Hydra's public port: jinbe mints a personal key's short-lived token there (client_credentials),
  // for POST /api/mcp/personal-keys/exchange.
  HYDRA_PUBLIC_URL: z.string().url().default('http://auth-hydra-public:4444'),
  // A CEILING on API-key scopes (comma-separated permissions). The scopes a key may be given are the
  // permissions of the routes on the sites its organization runs that the creator holds there
  // (services/api-key-scopes.ts); when this is set, only those it covers (equal or a dotted
  // ancestor) are offered. Empty = no ceiling. Never widens the catalog, and '*' is never a scope.
  API_KEY_ALLOWED_SCOPES: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),

  // ── Delegated user tokens (MCP prerequisite) ─────────────────────────────
  // Off by default. On: an OPAQUE Hydra access token sent as `Authorization: Bearer`, together with
  // the calling service's projected ServiceAccount token in `X-Actor-Token`, authenticates the USER
  // the token was issued to — narrowed to its scopes and its one organization. Needs
  // K8S_SA_AUTH_ENABLED=true, since the actor is verified by TokenReview. The same flag turns on the
  // personal-key API (/api/me/api-keys) and the org policy that may forbid personal keys.
  DELEGATED_TOKENS_ENABLED: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // The audience a delegated token MUST carry (e.g. https://mcp.<env>.example.com). Empty while
  // enabled refuses every delegated token: a token for another resource is never one for this one.
  DELEGATED_TOKEN_AUDIENCE: z.string().default(''),
  // The actors (`namespace:serviceaccount`) allowed to present a delegated token. Empty refuses all.
  DELEGATED_ACTOR_SUBJECTS: z
    .string()
    .default('auth:auth-mcp')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  // The public address of this deployment's MCP server (auth-mcp's /mcp, e.g.
  // https://mcp.<env>.example.com/mcp). The address people are shown when the administrator has not
  // saved one (rbac:config mcp serverUrl). Empty: none.
  MCP_PUBLIC_URL: z.string().default(''),
  // auth-mcp inside the cluster (e.g. http://auth-mcp:3100). With MCP_PUBLIC_URL, bootstrap routes the
  // MCP host through Oathkeeper to it (rule `mcp`, tokens checked by auth-mcp itself).
  MCP_UPSTREAM_URL: z.string().default(''),
  // The OAuth authorization server MCP clients sign in with: Hydra's issuer, BYTE-FOR-BYTE as Hydra
  // publishes it (urls.self.issuer, trailing slash included) — auth-mcp's PRM names the same string.
  // Set: jinbe serves RFC 8414 metadata and the locked-down client registration on that host
  // (src/oauth/), and bootstrap routes both through Oathkeeper (rule `mcp-oauth-as`). Empty: neither.
  MCP_OAUTH_ISSUER: z.string().default(''),
  // Client registration brake: `<n>/h/ip` (per IPv4 /24 or IPv6 /48) and `<m>/d` (everyone).
  MCP_OAUTH_DCR_RATE: z.string().default('10/h/ip,200/d'),
  // Calls a minute one replica answers on the login/consent provider (/api/public/oauth2/*), over all
  // visitors: the backstop behind the per-visitor limit (oauth/provider-limit.ts).
  MCP_OAUTH_PROVIDER_CEILING: z.coerce.number().int().positive().default(3000),
  // How long an introspection answer is reused (ms), capped by the token's own exp. Bounds how long a
  // revoked token still works here.
  DELEGATED_TOKEN_CACHE_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().nonnegative().max(60_000))
    .default('30000'),

  // ── Kubernetes ServiceAccount authentication (in-cluster M2M) ────────────
  // When enabled, a caller may authenticate with a PROJECTED ServiceAccount
  // token (`Authorization: Bearer <jwt>`) instead of a Kratos session cookie.
  // The token is verified by the cluster's own API server (TokenReview — jinbe
  // never validates the signature itself), and the resulting
  // `system:serviceaccount:<ns>:<sa>` is mapped to the SYNTHETIC SUBJECT
  // `<sa>.<ns>@K8S_SA_EMAIL_DOMAIN`. Authorization is unchanged: that subject
  // must exist as a Kratos identity for OPA to resolve any permission, so a
  // valid token alone grants nothing.
  K8S_SA_AUTH_ENABLED: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // Audience the caller's projected token MUST carry, and that jinbe asks the
  // API server to validate. NEVER set this to the API server's own audience
  // (e.g. https://kubernetes.default.svc): every pod's default token would
  // then be a jinbe credential, and a token sent to jinbe could be replayed
  // against the API server. A token whose TokenReview returns no audience is
  // rejected for exactly that reason.
  K8S_SA_TOKEN_AUDIENCE: z.string().min(1).default('jinbe'),
  // Email domain of the synthetic subject. MUST be a domain reserved for
  // machines — it shares the identity namespace with human logins, so a
  // routable domain would let a human identity impersonate a ServiceAccount.
  K8S_SA_EMAIL_DOMAIN: z.string().min(1).default('serviceaccount.cluster.local'),
  // Defense-in-depth allowlist of `namespace:serviceaccount` entries
  // (`namespace:*` allows a whole namespace). Empty = no subject filter; the
  // Kratos identity + OPA-resolved permissions remain the authoritative gate.
  K8S_SA_ALLOWED_SUBJECTS: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  // TokenReview result cache TTL (ms), further capped by the token's own exp.
  // Bounds the per-request API-server round-trip without outliving the token.
  K8S_SA_CACHE_TTL_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().nonnegative())
    .default('60000'),


  // Application name for OPAL fine-grained authorization
  APP_NAME: z.string().min(1, 'APP_NAME is required for OPAL authorization').default('jinbe'),

  // opal-server, told to refetch the datasource manifest after every RBAC change (POST /data/config).
  // Unset: no push, and nothing logged about OPAL.
  OPAL_SERVER_URL: z.string().url().optional(),
  // Bearer for that push, when opal-server runs with OPAL_AUTH_MASTER_TOKEN (a datasource JWT).
  OPAL_SERVER_TOKEN: z.string().min(1).optional(),
  // Each manifest entry's periodic_update_interval: the OPAL client refetches it this often even if a
  // push is lost. 0 leaves it out (fetched on connect and on push only).
  // Break-glass (bootstrap/break-glass.ts): sha256 (hex) of the offline-held code. Unset = no
  // break-glass path at all. Vault-injected; rotate after every use.
  JINBE_BREAK_GLASS_CODE_SHA256: z.string().regex(/^[0-9a-fA-F]{64}$/).optional(),
  // Where --apply writes its mandatory pre-apply store snapshot (and S3 too when backup is on).
  JINBE_SNAPSHOT_DIR: z.string().default('/tmp/jinbe-snapshots'),
  // Declares JINBE_SNAPSHOT_DIR a persistent volume. --apply refuses unless a snapshot copy outlives
  // the pod: the S3 backup, or this dir declared durable AND mounted (bootstrap/snapshot.ts).
  JINBE_SNAPSHOT_DIR_DURABLE: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),
  // The planHash an upgrade's bootstrap may apply on its own (the reviewed `--plan`). Unset: an
  // install written by the previous model refuses to start the new one until --apply is run.
  JINBE_RBAC_APPLY_EXPECT: z.string().optional(),
  OPAL_DATA_REFRESH_SECONDS: z.string().transform(Number).pipe(z.number().nonnegative()).default('60'),
  // Internal URL that opal-server uses to fetch data from this jinbe instance.
  // Set to the in-cluster service URL in production.
  JINBE_INTERNAL_URL: z.string().url().default('http://jinbe:8080'),
  // Shared with the OPAL client (its OPAL_CLIENT_TOKEN). Unset: the OPAL data routes refuse everyone.
  OPAL_CLIENT_TOKEN: z.string().min(32).optional(),
  // OPA (the opal-client sidecar) and its bearer token (the client's OPAL_POLICY_STORE_AUTH_TOKEN),
  // for the admin access check. Either unset: POST /api/admin/rbac/access-check answers 503.
  OPA_URL: z.string().url().optional(),
  OPA_TOKEN: z.string().min(1).optional(),


  // Redis (RBAC data store + audit streams)
  REDIS_URL: z.string().default('redis://redis:6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).pipe(z.number().min(0)).default('0'),
  REDIS_AUDIT_STREAM: z.string().default('auth:audit:events'),
  // Shared read cache (src/cache): Redis-backed stale-while-revalidate over the heavy upstream reads
  // (Kratos directory walk, identity by id, second-factor state, org member lists) plus the
  // in-process OPA answer cache. CACHE_ENABLED=false is the kill switch: every read goes upstream
  // and nothing is cached, OPA answers included. CACHE_DISABLED_NAMESPACES turns off single
  // namespaces (e.g. `kratos.directory,opa`).
  CACHE_ENABLED: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  CACHE_DISABLED_NAMESPACES: z
    .string()
    .default('')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  // `redis` (default) shares entries across replicas; `memory` keeps them per process (tests, and a
  // deployment without Redis).
  CACHE_STORE: z.enum(['redis', 'memory']).default('redis'),
  // How long the Kratos directory walk is served without a refresh. Mutations made through jinbe and
  // Kratos self-service flows (webhook) invalidate it at once; this bounds changes made behind jinbe.
  CACHE_DIRECTORY_FRESH_MS: z.string().transform(Number).pipe(z.number().int().positive()).default('15000'),
  // How long a Kratos session validation (/sessions/whoami) is reused for READS (GET/HEAD/OPTIONS) on
  // the replica that made it. Writes always validate afresh. 0 turns it off (as does the
  // `kratos.session` namespace in CACHE_DISABLED_NAMESPACES, or CACHE_ENABLED=false). Trade-off: a
  // session revoked outside jinbe (Kratos logout, "revoke other sessions") can still READ for up to
  // this long; revocations made through jinbe drop it on every replica at once.
  SESSION_CACHE_TTL_MS: z.string().transform(Number).pipe(z.number().int().nonnegative().max(10_000)).default('5000'),
  // Cap on the global audit stream (approximate, ~ trimming). Per-entity
  // fan-out keys carry their own tighter cap. Retention is bounded by this
  // number — there is no tamper-evident/WORM store in this pass.
  REDIS_AUDIT_MAXLEN: z.string().transform(Number).pipe(z.number().int().positive()).default('100000'),
  // Where audit events go. `legacy` — the Redis stream above only. `dual` — that stream AND the
  // audit/v1 line (stdout, `log_type:"audit"`) plus its outbox. `v1` — the v1 line and outbox only;
  // the Redis-stream readers (the Home's change tile, the access review's trail) then stop
  // receiving new rows.
  AUDIT_SINK: z.enum(['legacy', 'dual', 'v1']).default('dual'),
  // Key for the HMACs that stand in for an IP, a session id or an unknown identifier in audit/v1.
  // Unset: those fields are left out (the truncated network is still written).
  AUDIT_HMAC_KEY: z.string().min(32).optional(),
  // Durable copy of every v1 event until the archive confirms it.
  AUDIT_OUTBOX_STREAM: z.string().default('auth:audit:outbox'),
  // 'true' once an archiver (AUD-7: drain the outbox → Object-Lock bucket → ack) runs for this
  // deployment. Then the outbox is never trimmed and the Home alarms on archive lag. Off (no archiver
  // exists yet): nothing ever drains the outbox, so it is capped at AUDIT_OUTBOX_MAX_LEN (approximate
  // MAXLEN, oldest dropped) and the Home shows the archive as not deployed.
  AUDIT_ARCHIVE_ENABLED: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),
  AUDIT_OUTBOX_MAX_LEN: z.string().transform(Number).pipe(z.number().int().positive()).default('100000'),

  // The log backend read by /api/audit/* (in-cluster, no auth). Unset: the audit reads answer 503
  // audit_store_unavailable.
  LOKI_URL: z.string().url().optional(),
  LOKI_TIMEOUT_MS: z.string().transform(Number).pipe(z.number().int().positive()).default('30000'),
  // The namespace every query is pinned to — Loki is single-tenant, so this is the env boundary.
  LOKI_NAMESPACE: z.string().regex(/^[a-z0-9-]{1,63}$/).optional(),
  // How the audit reads find the audit/v1 lines. `label` — by a `log_type` stream label, which the
  // collector must promote (docs/observability.md). `json` — by jinbe's container, then the line's
  // own `log_type` field: works on any Loki, at the cost of parsing that container's lines.
  LOKI_AUDIT_SELECTOR: z.enum(['label', 'json']).default('json'),
  // The container that writes the audit lines, for `json` mode (the chart's container name).
  LOKI_AUDIT_CONTAINER: z.string().regex(/^[a-z0-9-]{1,63}$/).default('jinbe'),
  // The gateway's container in LOKI_NAMESPACE: its "Access request granted/denied" lines are what the
  // audit reads gateway decisions from (audit/gateway). `ACCESS_ROLLUP=off` stops the hourly summary.
  LOKI_GATEWAY_CONTAINER: z.string().regex(/^[a-z0-9-]{1,63}$/).default('oathkeeper'),
  ACCESS_ROLLUP: z.enum(['on', 'off']).default('on'),
  // Prometheus / Mimir, read by the Home (certificate expiry today). Unset: those tiles say
  // "not connected" (not_configured), never zero.
  PROMETHEUS_URL: z.string().url().optional(),
  GRAFANA_URL: z.string().url().optional(),
  // Most rows one audit export job writes; beyond it the export is marked truncated.
  AUDIT_EXPORT_MAX_ROWS: z.string().transform(Number).pipe(z.number().int().positive().max(1_000_000)).default('100000'),

  // Service Creation Defaults (for Oathkeeper rules and kustomization).
  // The defaults are placeholders — every production deployment must set
  // these explicitly to the deployer's namespace/domain.
  SERVICE_DEFAULT_NAMESPACE: z.string().default('default'),
  SERVICE_DEFAULT_DOMAIN: z.string().default('example.com'),
  SERVICE_DEFAULT_PORT: z.string().transform(Number).pipe(z.number().positive()).default('8080'),

  // Internal service URLs for bootstrap (Oathkeeper upstream rules)
  LOGIN_UI_URL: z.string().url().optional(),
  // The page an organization invitation link opens (login-ui), given `?token=<token>`: shown once to the
  // inviter, who sends it (jinbe has no mailer). Unset: the invitation answers its token alone.
  INVITATION_URL: z.string().url().optional(),
  ADMIN_UI_URL: z.string().url().optional(),

  // Domain configuration (for Oathkeeper rule generation)
  AUTH_DOMAIN: fqdnSchema.optional(),
  APP_DOMAIN: fqdnSchema.optional(),
  API_DOMAIN: fqdnSchema.optional(),


  // Oathkeeper enabled handler sets (comma-separated → string[]). These are the
  // handlers actually REGISTERED in the gateway's Oathkeeper config. jinbe
  // validates every access-rule handler against these sets fail-closed, so a
  // rule can never reference a handler the gateway doesn't know (which would
  // make Oathkeeper reject the entire ruleset at load → gateway down). The
  // deployer derives these from the gateway config; the defaults mirror the
  // currently-registered set so behavior is safe even before they're wired.
  OATHKEEPER_ENABLED_AUTHENTICATORS: z
    .string()
    .default('cookie_session,noop')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  OATHKEEPER_ENABLED_AUTHORIZERS: z
    .string()
    .default('allow,remote_json')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  OATHKEEPER_ENABLED_MUTATORS: z
    .string()
    .default('noop,header')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),
  OATHKEEPER_ENABLED_ERROR_HANDLERS: z
    .string()
    .default('redirect,json')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),

  // Default admin identity (only required on first bootstrap — see src/cli/bootstrap.ts).
  // ADMIN_PASSWORD seeds the first super_admins identity: it must clear the
  // length + entropy + distinct-character floors scored by the shared policy in
  // ./admin-password.ts (same helper the seed-admin runtime guard uses, so the
  // two layers can never drift). Validated whenever present; the first-run
  // presence check lives in src/cli/bootstrap.ts.
  ADMIN_EMAIL: z.string().email().optional(),
  ADMIN_PASSWORD: z
    .string()
    .superRefine((v, ctx) => {
      const weakness = checkAdminPasswordHardening(v)
      if (weakness) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `ADMIN_PASSWORD is ${describeAdminPasswordWeakness(weakness)}`,
        })
      }
    })
    .optional(),
  ADMIN_NAME: z.string().min(1).default('Admin'),

  // Reset path guards (CLI only). Both must be set; reset only if RESET_CONFIRM matches the running image SHA.
  JINBE_BOOTSTRAP_DANGEROUS_RESET: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  JINBE_BOOTSTRAP_RESET_CONFIRM: z.string().optional(),

  // Sidecar notification service (jinbe-service)
  JINBE_SERVICE_URL: z.string().url().optional(),

  // ── RBAC-bundle backup (S3) ──────────────────────────────────────────────
  // Mirrors the chart `backup.*` values. When enabled, jinbe writes its own
  // scheduled snapshots to the bucket and reads them back (list, download,
  // restore, and the first-init restore, which runs after the model is seeded).
  // Credentials come from the default AWS chain (IRSA) — no static keys.
  BACKUP_ENABLED: z.string().default('false').transform((v) => v === 'true'),
  BACKUP_S3_BUCKET: z.string().optional(),
  BACKUP_S3_PREFIX: z.string().default('auth-backup'),
  BACKUP_S3_REGION: z.string().default('eu-west-3'),
  // Cron for jinbe's own scheduled backup (UTC). Default daily 02:00.
  BACKUP_SCHEDULE: z.string().default('0 2 * * *'),
  // First init (no bootstrap marker) and the backup: auto = restore latest.json when backup is on,
  // keep the seeded model when there is none or it fails; false = never restore (a deliberate fresh
  // rebuild); true = disaster recovery: restore or fail the bootstrap (exit 9). Chart: backup.restoreOnFirstInit.
  BACKUP_RESTORE_ON_FIRST_INIT: z.enum(['auto', 'true', 'false']).default('auto'),
})

// Parse and validate environment variables
const parseEnv = () => {
  try {
    return envSchema.parse(process.env)
  } catch (error) {
    if (error instanceof z.ZodError) {
      // One JSON line, written by hand: the logger reads its level and base fields from this very
      // object, so it cannot exist yet. Names and messages only — never the values.
      const issues = error.errors.map((err) => ({ variable: err.path.join('.'), message: err.message }))
      process.stderr.write(`${JSON.stringify({
        level: 'fatal', time: new Date().toISOString(), service: 'jinbe', log_type: 'app', component: 'config',
        msg: 'Invalid environment variables', issues,
      })}\n`)
      process.exit(1)
    }
    throw error
  }
}

export const env = parseEnv()

// Type export for TypeScript
export type Env = z.infer<typeof envSchema>
