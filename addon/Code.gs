/**
 * Malicious Email Scorer - Gmail Add-on entry points.
 *
 * Flow: Gmail trigger -> extractEmail (Extract.gs) -> requestAnalysis (Api.gs)
 *       -> buildResultCard (Cards.gs)
 */

/** Contextual trigger: runs when the user opens an email (see appsscript.json). */
function onGmailMessageOpen(e) {
  return [analyzeOpenedMessage(e)];
}

/** "Try again" button on the error card. */
function onRetry(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(analyzeOpenedMessage(e)))
    .build();
}

/** Homepage trigger: sidebar opened with no email selected. */
function onHomepage() {
  return buildHomepageCard();
}

function analyzeOpenedMessage(e) {
  try {
    // The event's access token unlocks THIS message only (least privilege).
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    const message = GmailApp.getMessageById(e.gmail.messageId);
    const result = requestAnalysis(extractEmail(message));
    return buildResultCard(result);
  } catch (err) {
    if (err instanceof UserFacingError) {
      return buildErrorCard(err.message, err.retryable);
    }
    // Unexpected bug: log details for us, show a generic message to the user.
    console.error(err && err.stack ? err.stack : err);
    return buildErrorCard('Something went wrong while analyzing this email.', true);
  }
}
