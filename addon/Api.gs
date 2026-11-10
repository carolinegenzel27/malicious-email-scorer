/**
 * Client for the analysis backend.
 *
 * The backend URL is not secret and is also pinned in appsscript.json
 * (urlFetchWhitelist), so the add-on cannot be made to call anything else.
 * The API key IS secret: it lives in Script Properties, never in source code.
 */

const BACKEND_URL = 'https://malicious-email-scorer-vx4h.onrender.com';

const VERDICTS = ['safe', 'suspicious', 'malicious'];
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

/** Error with a message that is safe to show to the user. */
function UserFacingError(message, retryable) {
  this.message = message;
  this.retryable = Boolean(retryable);
}

/**
 * @param {Object} email output of extractEmail()
 * @return {Object} validated analysis result
 * @throws {UserFacingError}
 */
function requestAnalysis(email) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('API_KEY');
  if (!apiKey) {
    throw new UserFacingError('Add-on is not configured: API_KEY script property is missing.');
  }

  let response;
  try {
    response = UrlFetchApp.fetch(BACKEND_URL + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { 'X-API-Key': apiKey },
      payload: JSON.stringify(email),
      muteHttpExceptions: true, // we handle status codes ourselves
    });
  } catch (err) {
    throw classifyFetchError(err);
  }

  const code = response.getResponseCode();
  if (code === 401) {
    throw new UserFacingError('Add-on is misconfigured: the backend rejected the API key.');
  }
  if (code !== 200) {
    console.warn('Backend returned HTTP ' + code);
    throw new UserFacingError('The analysis server returned an error (' + code + ').', true);
  }

  return validateResult(response.getContentText());
}

/**
 * UrlFetchApp throws for very different reasons. Telling them apart matters:
 * "server is waking up" is only true for timeouts, and a misleading message
 * sends the user (and us) debugging in the wrong direction.
 */
function classifyFetchError(err) {
  const raw = String((err && err.message) || err);
  console.warn('Backend fetch failed: ' + raw);
  // Apps Script error text contains no secrets (no headers or payload), so a
  // short excerpt is safe to show and makes failures diagnosable.
  const detail = ' (' + raw.substring(0, 200) + ')';

  if (/permission|authoriz/i.test(raw)) {
    return new UserFacingError(
      'The add-on lacks permission to contact the analysis server. Re-open the add-on and approve access.' + detail
    );
  }
  if (/whitelist|allowlist/i.test(raw)) {
    return new UserFacingError('The add-on is not allowed to call this server URL.' + detail);
  }
  if (/timeout|timed out/i.test(raw)) {
    return new UserFacingError(
      'The analysis server is waking up. Please try again in a few seconds.',
      true
    );
  }
  return new UserFacingError('Could not reach the analysis server.' + detail, true);
}

/**
 * The backend response is external input too: parse defensively and accept
 * only the shape we expect, so a broken or compromised backend cannot break
 * or spoof the UI.
 */
function validateResult(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new UserFacingError('The analysis server returned an invalid response.', true);
  }
  if (
    !data ||
    typeof data.score !== 'number' ||
    VERDICTS.indexOf(data.verdict) === -1 ||
    !Array.isArray(data.findings)
  ) {
    throw new UserFacingError('The analysis server returned an unexpected response.', true);
  }

  return {
    score: Math.max(0, Math.min(100, Math.round(data.score))),
    verdict: data.verdict,
    summary: String(data.summary || ''),
    findings: data.findings.slice(0, 30).map(function (f) {
      return {
        severity: SEVERITIES.indexOf(f.severity) !== -1 ? f.severity : 'info',
        category: String(f.category || ''),
        title: String(f.title || ''),
        detail: String(f.detail || ''),
        points: Number(f.points) || 0,
      };
    }),
  };
}
