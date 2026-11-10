/**
 * Extracts from the opened message only the fields the backend analyzes.
 *
 * Data minimization: every field sent here is used by an analyzer. Nothing
 * else leaves Gmail - no attachments (not even their names or hashes, since
 * there is no attachment analysis), no Return-Path, no recipients.
 * Limits mirror the backend schema (backend/app/models.py) so a big email is
 * truncated here instead of being rejected there.
 */

const LIMITS = {
  HEADER: 4000,
  SUBJECT: 1000,
  BODY: 200000,
};

/**
 * @param {GmailApp.GmailMessage} message
 * @return {Object} request body for POST /analyze
 */
function extractEmail(message) {
  return {
    sender: truncate(message.getFrom(), LIMITS.HEADER),
    reply_to: truncate(message.getReplyTo(), LIMITS.HEADER),
    subject: truncate(message.getSubject(), LIMITS.SUBJECT),
    authentication_results: nonEmpty([
      truncate(message.getHeader('Authentication-Results'), LIMITS.HEADER),
    ]),
    body_text: truncate(message.getPlainBody(), LIMITS.BODY),
    body_html: truncate(message.getBody(), LIMITS.BODY),
  };
}

function truncate(value, max) {
  const s = value == null ? '' : String(value);
  return s.length > max ? s.substring(0, max) : s;
}

function nonEmpty(list) {
  return list.filter(function (s) {
    return s;
  });
}
