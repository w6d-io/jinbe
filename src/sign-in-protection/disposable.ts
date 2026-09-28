/**
 * Throwaway-inbox domains refused at sign-up when `registration.blockDisposable` is on.
 *
 * Deliberately short and stable: the services people actually reach for, not a scraped list of
 * thousands that ages by the week. Anything missing goes in the console's own deny-list
 * (`registration.denyDomains`), which applies whatever this switch says. A domain matches itself
 * and every subdomain of it.
 */
export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  '10minutemail.com', '10minutemail.net', '1secmail.com', '1secmail.net', '1secmail.org', '20minutemail.com',
  '33mail.com', 'anonaddy.me', 'burnermail.io', 'byom.de', 'dispostable.com', 'discard.email', 'dropmail.me',
  'emailondeck.com', 'fakeinbox.com', 'fakemail.net', 'getairmail.com', 'getnada.com', 'guerrillamail.biz',
  'guerrillamail.com', 'guerrillamail.de', 'guerrillamail.info', 'guerrillamail.net', 'guerrillamail.org',
  'guerrillamailblock.com', 'harakirimail.com', 'inboxbear.com', 'inboxkitten.com', 'incognitomail.org',
  'mail.tm', 'mail-temp.com', 'mailcatch.com', 'maildrop.cc', 'mailinator.com', 'mailinator.net', 'mailnesia.com',
  'mailpoof.com', 'mailsac.com', 'mintemail.com', 'moakt.com', 'mohmal.com', 'mytemp.email', 'nada.email',
  'sharklasers.com', 'spam4.me', 'spamgourmet.com', 'spambox.us', 'temp-mail.io', 'temp-mail.org', 'tempail.com',
  'tempmail.com', 'tempmail.dev', 'tempmail.net', 'tempmailo.com', 'tempr.email', 'throwawaymail.com',
  'tmail.ws', 'tmpmail.net', 'tmpmail.org', 'trashmail.com', 'trashmail.de', 'trashmail.net', 'wegwerfmail.de',
  'yopmail.com', 'yopmail.fr', 'yopmail.net', 'grr.la', 'pokemail.net', 'emailfake.com', 'luxusmail.org',
  'cmail.club', 'mailto.plus', 'fexpost.com', 'fexbox.org', 'rover.info', 'chitthi.in', 'any.pink', 'merepost.com',
])

/** `a.b.example.com` → [`a.b.example.com`, `b.example.com`, `example.com`]. */
export function domainAndParents(domain: string): string[] {
  const labels = domain.split('.')
  const out: string[] = []
  for (let i = 0; i < labels.length - 1; i++) out.push(labels.slice(i).join('.'))
  return out
}

export function isDisposable(domain: string): boolean {
  return domainAndParents(domain).some((d) => DISPOSABLE_DOMAINS.has(d))
}
