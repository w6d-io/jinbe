import { auditEventService } from './audit-event.service.js'
import type { AuditActor } from './audit-event.service.js'

/**
 * The notice owed to a user's OLD address when an administrator changes it (mcp-write-wave.md §3):
 * "the sign-in address of your account was changed on <date> by an administrator; if this was not
 * expected, contact support". Fixed text, no requester words, no new address.
 *
 * NOT MAILED YET — recorded. jinbe has no mailer: mail leaves through the Kratos courier, whose SMTP
 * connection (courier.smtp.connection_uri) is Kratos' own secret, and Kratos has no admin endpoint
 * that sends an arbitrary message. Kratos' `verifiable_address_changed` template is not sent on an
 * admin identity PATCH as far as this service can tell, and every self-service flow Kratos would
 * start for the old address after the change (recovery, verification) mails text that is wrong for
 * this purpose ("no account uses this address"). So the notice is written to the audit trail
 * (`user.address_notice_pending`), where kuma and the security team see it, until either the chart
 * gives jinbe the courier connection or a Kratos hook sends it. `delivered: false` says so to the
 * caller rather than claiming a mail went out.
 */

export type AddressNoticeOutcome = { delivered: false; recorded: boolean; channel: 'audit' }

export async function noticeAddressChanged(
  identityId: string,
  oldAddressDigest: string,
  actor: AuditActor & { requestId?: string | null },
): Promise<AddressNoticeOutcome> {
  const id = await auditEventService.emit({
    category: 'auth',
    kind: 'security',
    verb: 'notice',
    target: `user:${identityId}`,
    targetType: 'user',
    targetId: identityId,
    result: 'ok',
    severity: 'warn',
    actor,
    requestId: actor.requestId ?? null,
    source: 'jinbe-api',
    v1Event: 'user.address_notice_pending',
    details: { notice: 'address_changed', to: oldAddressDigest, channel: 'audit', reason: 'no_mailer' },
  }).catch(() => null)
  return { delivered: false, recorded: id !== null, channel: 'audit' }
}
