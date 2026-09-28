/**
 * Credentials for the Kratos and Hydra admin APIs. Behind the chart's sidecar (kratos.adminAuth,
 * hydra.adminAuth) every admin call needs `Authorization: Bearer <token>`; without a token no header
 * is sent, which is what an admin API with no sidecar expects.
 */
export function adminAuthHeaders(token: string | undefined): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/**
 * A URL fit for a log line or an error message: scheme, host and path only. Userinfo and the query
 * (where a credential could have been put) are dropped; an unparseable value is not echoed at all.
 */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}`
  } catch {
    return '[invalid url]'
  }
}
