/**
 * Malicious Email Scorer - Gmail Add-on (step 1: hello world).
 *
 * For now this only reads the opened email and shows basic details,
 * to prove the add-on can access the message. Analysis comes later.
 */

/**
 * Contextual trigger: runs every time the user opens an email
 * (wired up in appsscript.json -> gmail.contextualTriggers).
 *
 * @param {Object} e Event object from Gmail. Contains a short-lived access
 *                   token that grants access to THIS message only.
 * @return {Card[]}
 */
function onGmailMessageOpen(e) {
  // Unlock access to the currently opened message only (least privilege:
  // our scope is "current message", not the whole mailbox).
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Malicious Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .setHeader('Opened email')
        .addWidget(infoRow('From', message.getFrom()))
        .addWidget(infoRow('Subject', message.getSubject() || '(no subject)'))
        .addWidget(infoRow('Date', message.getDate().toLocaleString()))
    )
    .build();

  return [card];
}

/**
 * Homepage trigger: shown when the sidebar is opened with no email selected.
 * @return {Card}
 */
function onHomepage() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Malicious Email Scorer'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText('Open an email to analyze it.')
      )
    )
    .build();
}

/**
 * One label/value row. The value comes from the email, so it is UNTRUSTED:
 * we escape it before display.
 */
function infoRow(label, untrustedValue) {
  return CardService.newDecoratedText()
    .setTopLabel(label)
    .setText(escapeHtml(untrustedValue))
    .setWrapText(true);
}

/**
 * Card text supports a small subset of HTML (<b>, <a>, <font>...).
 * An attacker controls the sender name and subject, so without escaping they
 * could inject formatting or fake clickable links into OUR trusted UI.
 */
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
