/**
 * Demo email generator for the Malicious Email Scorer.
 *
 * Inserts crafted sample emails straight into YOUR OWN inbox (Gmail API
 * messages.insert). Nothing is sent to anyone. Each sample demonstrates one
 * behaviour of the scorer, so the demo is predictable and repeatable.
 *
 * Safety:
 * - Only scope: gmail.insert (add messages to this mailbox). It cannot read,
 *   send, or delete mail. Kept in a separate project so the add-on itself
 *   never gets this permission.
 * - Every link points to a reserved ".example" domain that never resolves.
 * - Every subject starts with "[Demo]" so samples can't be mistaken for real
 *   mail. To clean up, search Gmail for subject:[Demo] and delete.
 *
 * Note: Gmail adds real Authentication-Results headers only to mail it
 * receives over SMTP. Inserted samples carry a simulated header instead.
 *
 * Usage: open this project in the Apps Script editor, select
 * insertDemoEmails, click Run.
 */

const SAMPLES = [
  {
    name: 'Look-alike PayPal domain',
    expected: 'Likely malicious',
    from: 'PayPal <service@paypa1.com>',
    replyTo: 'paypal.helpdesk@gmail.com',
    auth: 'spf=none smtp.mailfrom=paypa1.com; dkim=none; dmarc=none',
    subject: 'Your account has been limited',
    body: 'We noticed unusual activity on your account. Please confirm your details within 24 hours to avoid suspension.',
    link: { text: 'https://www.paypal.com/signin', href: 'https://paypa1-secure.example/login' },
  },
  {
    name: 'Brand name on a free email account',
    expected: 'Suspicious',
    from: 'Microsoft Account Team <ms.account.team@outlook.com>',
    auth: 'dkim=pass header.i=@outlook.com; spf=pass smtp.mailfrom=outlook.com; dmarc=pass (p=NONE) header.from=outlook.com',
    subject: 'Unusual sign-in activity',
    body: 'We detected a sign-in to your Microsoft account from a new device. If this was not you, secure your account now.',
    link: { text: 'Review recent activity', href: 'https://account-review.example/microsoft' },
  },
  {
    name: 'Hebrew bank impersonation',
    expected: 'Likely malicious (credential phishing pattern)',
    from: 'בנק הפועלים <service@poalim-secure-update.com>',
    auth: 'spf=softfail smtp.mailfrom=poalim-secure-update.com; dkim=none',
    subject: 'החשבון שלך הוגבל זמנית',
    body: 'לקוח יקר, זיהינו פעילות חריגה בחשבונך. יש לאמת את פרטיך בהקדם כדי למנוע חסימה.',
    link: { text: 'לאימות החשבון', href: 'https://poalim-verify.example/login' },
  },
  {
    name: 'Look-alike domain that passes authentication',
    expected: 'Suspicious (attack pattern)',
    from: 'Billing Team <billing@paypal-billing-center.com>',
    auth: 'dkim=pass header.i=@paypal-billing-center.com; spf=pass; dmarc=pass (p=REJECT) header.from=paypal-billing-center.com',
    subject: 'Invoice #48213 is ready',
    body: 'Your monthly invoice is attached to your account. Please review the payment details.',
    link: { text: 'View invoice', href: 'https://billing-portal.example/invoice/48213' },
  },
  {
    name: 'CEO fraud (no links, passes authentication)',
    expected: 'Likely malicious (CEO / payment fraud pattern)',
    from: 'Dana Levi <dana@acme-industries.com>',
    replyTo: 'dana.levi.ceo@gmail.com',
    auth: 'dkim=pass header.i=@acme-industries.com; spf=pass; dmarc=pass (p=NONE) header.from=acme-industries.com',
    subject: 'Urgent - wire transfer needed today',
    body: 'I am in a meeting and cannot talk. Please wire 48,000 USD to our new supplier today and keep this confidential until the deal is announced. I will send the bank details once you confirm.',
  },
  {
    name: 'Legitimate verified sender',
    expected: 'Looks safe (verified sender)',
    from: 'Google <no-reply@accounts.google.com>',
    auth: 'dkim=pass header.i=@accounts.google.com; spf=pass; dmarc=pass (p=REJECT) header.from=accounts.google.com',
    subject: 'Security checkup complete',
    body: 'Your recent security checkup found no issues with your Google Account.',
  },
];

function insertDemoEmails() {
  SAMPLES.forEach(function (sample) {
    Gmail.Users.Messages.insert({ raw: buildRawMessage(sample), labelIds: ['INBOX', 'UNREAD'] }, 'me');
    console.log('Inserted: ' + sample.name + '  ->  expected: ' + sample.expected);
  });
  console.log('Done. Search Gmail for subject:[Demo] to find (or delete) the samples.');
}

/** Builds an RFC 822 message: headers + plain-text and HTML parts. */
function buildRawMessage(sample) {
  const boundary = 'demo-' + Utilities.getUuid();
  const html = '<p>' + escapeHtml(sample.body) + '</p>' +
    (sample.link
      ? '<p><a href="' + escapeHtml(sample.link.href) + '">' + escapeHtml(sample.link.text) + '</a></p>'
      : '');

  const headers = [
    'Authentication-Results: mx.google.com; ' + sample.auth,
    'From: ' + encodeAddress(sample.from),
    sample.replyTo ? 'Reply-To: ' + sample.replyTo : null,
    'To: undisclosed-recipients:;',
    'Subject: ' + encodeHeader('[Demo] ' + sample.subject),
    'Date: ' + new Date().toUTCString(),
    'Message-ID: <' + boundary + '@demo.invalid>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="' + boundary + '"',
  ].filter(Boolean);

  const raw = headers.join('\r\n') + '\r\n\r\n' +
    part(boundary, 'text/plain', sample.body + (sample.link ? '\n\n' + sample.link.href : '')) +
    part(boundary, 'text/html', html) +
    '--' + boundary + '--\r\n';

  return Utilities.base64EncodeWebSafe(Utilities.newBlob(raw).getBytes());
}

function part(boundary, type, text) {
  return '--' + boundary + '\r\n' +
    'Content-Type: ' + type + '; charset=UTF-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' +
    Utilities.base64Encode(text, Utilities.Charset.UTF_8) + '\r\n';
}

/** Headers must be ASCII: encode non-ASCII text (e.g. Hebrew) per RFC 2047. */
function encodeHeader(text) {
  return /^[\x20-\x7e]*$/.test(text)
    ? text
    : '=?UTF-8?B?' + Utilities.base64Encode(text, Utilities.Charset.UTF_8) + '?=';
}

/** 'Display Name <addr@x.com>' -> encode only the display name. */
function encodeAddress(value) {
  const match = value.match(/^(.*)<([^>]+)>$/);
  if (!match) return value;
  const name = match[1].trim();
  return (/^[\x20-\x7e]*$/.test(name) ? '"' + name + '"' : encodeHeader(name)) + ' <' + match[2] + '>';
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
