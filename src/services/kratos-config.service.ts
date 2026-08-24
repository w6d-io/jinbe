import { readFile, writeFile } from 'fs/promises'
import { parseDocument, isMap } from 'yaml'
import { env } from '../config/env.js'

/**
 * Kratos self-service authentication method management.
 *
 * Kratos has NO admin API for its own configuration — auth methods
 * (password, code, passkey, …) live exclusively under `selfservice.methods`
 * in kratos.yml. Kratos hot-reloads that file (watcherx), so patching it is
 * the runtime toggle mechanism: no restart, next flow reflects the change.
 *
 * This service surgically patches ONLY the `selfservice.methods.<m>.enabled`
 * (and `code.passwordless_enabled`) keys via the yaml Document API, preserving
 * every comment and unrelated key in the file.
 *
 * Requires KRATOS_CONFIG_PATH pointing at the same kratos.yml the Kratos
 * process watches (shared mount). Unset → feature disabled (routes 501).
 *
 * ponytail: file-mount mode only. In-cluster ConfigMap patching (mounted
 * ConfigMaps are read-only in the pod) is the follow-up for the Helm chart.
 */

/** Methods togglable with a bare `enabled: true`. */
const BARE_METHODS = ['password', 'code', 'totp', 'lookup_secret', 'link', 'profile'] as const
/**
 * Methods whose `enabled: true` is INVALID without an accompanying config
 * block (webauthn/passkey need rp.*, oidc needs providers). Enabling one of
 * these without config would make Kratos reject the whole file on reload —
 * so we only allow the toggle when the config block already exists.
 */
const CONFIG_REQUIRED_METHODS = ['webauthn', 'passkey', 'oidc'] as const

export const KNOWN_METHODS = [...BARE_METHODS, ...CONFIG_REQUIRED_METHODS] as const
export type AuthMethod = (typeof KNOWN_METHODS)[number]

export interface MethodState {
  enabled: boolean
  /** Method has a `config` block in kratos.yml (required for webauthn/passkey/oidc). */
  configured: boolean
  /** Only meaningful for `code`: first-factor (passwordless) login. */
  passwordlessEnabled?: boolean
}

export interface MethodPatch {
  enabled?: boolean
  passwordlessEnabled?: boolean
}

export class KratosConfigError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number = 400
  ) {
    super(message)
    this.name = 'KratosConfigError'
  }
}

export class KratosConfigService {
  constructor(private readonly path: string | undefined = env.KRATOS_CONFIG_PATH) {}

  /** Feature is only available when the Kratos config file is mounted. */
  enabled(): boolean {
    return !!this.path
  }

  /**
   * Self-registration switch (selfservice.flows.registration.enabled).
   * Absent key = Kratos default (enabled). false = accounts are created only
   * by administrators — the registration flow 400s self_service_flow_disabled.
   */
  async getRegistrationEnabled(): Promise<boolean> {
    const doc = await this.load()
    return doc.getIn(['selfservice', 'flows', 'registration', 'enabled']) !== false
  }

  async setRegistrationEnabled(enabled: boolean): Promise<boolean> {
    const doc = await this.load()
    doc.setIn(['selfservice', 'flows', 'registration', 'enabled'], enabled)
    await writeFile(this.path!, doc.toString(), 'utf8')
    return enabled
  }

  async getMethods(): Promise<Record<AuthMethod, MethodState>> {
    const doc = await this.load()
    const out = {} as Record<AuthMethod, MethodState>
    for (const m of KNOWN_METHODS) {
      const node = doc.getIn(['selfservice', 'methods', m])
      const enabled = doc.getIn(['selfservice', 'methods', m, 'enabled']) === true
      const configured = isMap(node) ? node.has('config') : false
      const state: MethodState = { enabled, configured }
      if (m === 'code') {
        state.passwordlessEnabled =
          doc.getIn(['selfservice', 'methods', m, 'passwordless_enabled']) === true
      }
      out[m] = state
    }
    return out
  }

  /**
   * Apply a partial patch ({ password: {enabled: false}, … }) to kratos.yml.
   * Returns the resulting full state. Throws KratosConfigError on invalid input.
   */
  async setMethods(patch: Partial<Record<AuthMethod, MethodPatch>>): Promise<Record<AuthMethod, MethodState>> {
    const doc = await this.load()

    for (const [method, p] of Object.entries(patch) as [AuthMethod, MethodPatch][]) {
      if (!KNOWN_METHODS.includes(method)) {
        throw new KratosConfigError(`Unknown auth method: ${method}`)
      }
      if (typeof p.enabled === 'boolean') {
        if (
          p.enabled &&
          (CONFIG_REQUIRED_METHODS as readonly string[]).includes(method) &&
          !this.hasConfigBlock(doc, method)
        ) {
          throw new KratosConfigError(
            `Cannot enable '${method}': it requires a config block in kratos.yml ` +
              `(${method === 'oidc' ? 'config.providers' : 'config.rp'}). Add it to the file first.`
          )
        }
        doc.setIn(['selfservice', 'methods', method, 'enabled'], p.enabled)
      }
      if (typeof p.passwordlessEnabled === 'boolean') {
        if (method !== 'code') {
          throw new KratosConfigError(`passwordlessEnabled only applies to 'code' (got '${method}')`)
        }
        doc.setIn(['selfservice', 'methods', method, 'passwordless_enabled'], p.passwordlessEnabled)
      }
    }

    await writeFile(this.path!, doc.toString(), 'utf8')
    return this.getMethods()
  }

  private hasConfigBlock(doc: ReturnType<typeof parseDocument>, method: string): boolean {
    const node = doc.getIn(['selfservice', 'methods', method])
    return isMap(node) && node.has('config')
  }

  private async load() {
    if (!this.path) {
      throw new KratosConfigError('KRATOS_CONFIG_PATH is not configured on this deployment.', 501)
    }
    let raw: string
    try {
      raw = await readFile(this.path, 'utf8')
    } catch {
      throw new KratosConfigError(`Kratos config not readable at ${this.path}`, 503)
    }
    const doc = parseDocument(raw)
    if (doc.errors.length > 0) {
      throw new KratosConfigError(`Kratos config at ${this.path} is not valid YAML: ${doc.errors[0].message}`, 500)
    }
    return doc
  }
}

export const kratosConfigService = new KratosConfigService()
