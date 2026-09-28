/**
 * Whether this process has observed the bootstrap marker. Set once by server.ts after
 * waitForBootstrap resolves; read by /api/health and the Home health strip.
 */
let ready = false

export function markBootstrapReady(): void {
  ready = true
}

export function isBootstrapReady(): boolean {
  return ready
}
