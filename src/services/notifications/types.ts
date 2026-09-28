export interface EntityEvent {
  action: 'created' | 'updated' | 'deleted'
  entity_type: 'user' | 'organization' | 'role'
  payload: Record<string, unknown>
  timestamp: string
}

export interface NotifyResult {
  acknowledged: boolean
}

/**
 * Notifier is the transport-agnostic interface for delivering entity events.
 * Implementations handle a single transport (HTTP, Kafka, AMQP, etc.).
 */
export interface Notifier {
  readonly name: string
  notify(event: EntityEvent): Promise<NotifyResult>
}

/**
 * A delivery that failed, with the reason in words an operator can act on ("POST
 * http://jinbe-service:8080/ingest: getaddrinfo ENOTFOUND jinbe-service", not "fetch failed").
 * `permanent`: retrying cannot help (the receiver refused this event), so it is dead-lettered at once.
 */
export class NotifyError extends Error {
  readonly permanent: boolean

  constructor(message: string, opts: { permanent?: boolean } = {}) {
    super(message)
    this.name = 'NotifyError'
    this.permanent = opts.permanent ?? false
  }
}
