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
}

export type { OathkeeperRule, RouteRule }
