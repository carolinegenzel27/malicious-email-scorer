/**
 * Extracts from the opened message only the fields the backend needs.
 *
 * Data minimization: we send metadata and text, never attachment contents.
 * Limits mirror the backend schema (backend/app/models.py) so a big email is
 * truncated here instead of being rejected there.
 */

const LIMITS = {
  HEADER: 4000,
  SUBJECT: 1000,
  BODY: 200000,
  ATTACHMENTS: 50,
  HASH_MAX_BYTES: 10 * 1024 * 1024, // don't hash files over 10 MB (slow)
};

/**
 * @param {GmailApp.GmailMessage} message
 * @return {Object} request body for POST /analyze
 */
function extractEmail(message) {
  return {
    sender: truncate(message.getFrom(), LIMITS.HEADER),
    reply_to: truncate(message.getReplyTo(), LIMITS.HEADER),
    return_path: truncate(message.getHeader('Return-Path'), LIMITS.HEADER),
    subject: truncate(message.getSubject(), LIMITS.SUBJECT),
    authentication_results: nonEmpty([
      truncate(message.getHeader('Authentication-Results'), LIMITS.HEADER),
    ]),
    body_text: truncate(message.getPlainBody(), LIMITS.BODY),
    body_html: truncate(message.getBody(), LIMITS.BODY),
    attachments: extractAttachments(message),
  };
}

function extractAttachments(message) {
  return message
    .getAttachments({ includeInlineImages: false })
    .slice(0, LIMITS.ATTACHMENTS)
    .map(function (blob) {
      const size = blob.getSize();
      return {
        filename: truncate(blob.getName(), 500),
        content_type: truncate(blob.getContentType(), 200),
        size_bytes: size,
        // The hash lets the backend look the file up in threat intelligence
        // without the file itself ever leaving Gmail.
        sha256: size <= LIMITS.HASH_MAX_BYTES ? sha256Hex(blob.getBytes()) : '',
      };
    });
}

function sha256Hex(bytes) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes)
    .map(function (b) {
      return ((b + 256) % 256).toString(16).padStart(2, '0');
    })
    .join('');
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
