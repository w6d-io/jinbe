import type { OathkeeperRule, RouteRule } from '../services/redis-rbac.repository.js'

export interface BootstrapLogger {
  info(obj: unknown, msg?: string): void
  info(msg: string): void
  warn(obj: unknown, msg?: string): void
  warn(msg: string): void
  error(obj: unknown, msg?: string): void
  error(msg: string): void
  debug(obj: unknown, msg?: string): void
  debug(msg: string): void
}

export interface BootstrapDomains {
  auth: string
  app: string
  api: string
}

export interface BootstrapUrls {
  kratosPublic: string
  kratosAdmin: string
  loginUi: string
  adminUi: string
  jinbeInternal: string
}

export interface BootstrapAdmin {
  email: string
  password: string
  name: string
}

export interface BootstrapConfig {
  domains: BootstrapDomains
  urls: BootstrapUrls
  admin: BootstrapAdmin | null
}

export interface RunBootstrapOptions {
  logger: BootstrapLogger
  config: BootstrapConfig
  /** Image git SHA — recorded in the marker for forensic audit. */
  gitSha: string
  /** Application version (e.g. v0.3.0) — informational, recorded in marker. */
  version: string
  /**
   * Reset path. When true, clears the existing marker and re-runs full
   * bootstrap. Caller is responsible for enforcing the
   * JINBE_BOOTSTRAP_DANGEROUS_RESET + JINBE_BOOTSTRAP_RESET_CONFIRM guards.
   */
  force?: boolean
}

export type { OathkeeperRule, RouteRule }
