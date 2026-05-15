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
