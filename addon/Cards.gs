/**
 * UI: turns an analysis result into Gmail add-on cards.
 *
 * Every string shown here originates from the email or the backend, so it is
 * escaped before rendering (card text supports a subset of HTML).
 */

const VERDICT_STYLE = {
  safe: { icon: '🟢', label: 'Looks safe' },
  suspicious: { icon: '🟠', label: 'Suspicious' },
  malicious: { icon: '🔴', label: 'Likely malicious' },
};

const SEVERITY_ICON = {
  info: '✅',
  low: '🟡',
  medium: '🟠',
  high: '🔴',
  critical: '🛑',
};

function buildResultCard(result) {
  const style = VERDICT_STYLE[result.verdict];

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle(style.icon + ' ' + style.label)
        .setSubtitle('Risk score: ' + result.score + ' / 100')
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(escapeHtml(result.summary))
      )
    );

  // Warnings first, then the reassuring "info" findings.
  const warnings = result.findings.filter(function (f) {
    return f.severity !== 'info';
  });
  const positives = result.findings.filter(function (f) {
    return f.severity === 'info';
  });

  if (warnings.length) {
    card.addSection(findingsSection('Why we flagged it', warnings));
  }
  if (positives.length) {
    card.addSection(findingsSection('What checked out', positives).setCollapsible(true));
  }
  if (!result.findings.length) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText('No warning signs found.')
      )
    );
  }

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        '<i>Automated assessment. If in doubt, verify with the sender through another channel.</i>'
      )
    )
  );
  return card.build();
}

function findingsSection(header, findings) {
  const section = CardService.newCardSection().setHeader(header);
  findings.forEach(function (f) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(SEVERITY_ICON[f.severity] + ' ' + escapeHtml(f.category))
        .setText('<b>' + escapeHtml(f.title) + '</b>')
        .setBottomLabel(escapeHtml(f.detail))
        .setWrapText(true)
    );
  });
  return section;
}

function buildErrorCard(message, retryable) {
  const section = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(escapeHtml(message))
  );
  if (retryable) {
    section.addWidget(
      CardService.newTextButton()
        .setText('Try again')
        .setOnClickAction(CardService.newAction().setFunctionName('onRetry'))
    );
  }
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('⚠️ Could not analyze this email'))
    .addSection(section)
    .build();
}

function buildHomepageCard() {
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
 * An attacker controls the sender name, subject and body. Without escaping
 * they could inject formatting or fake links into OUR trusted UI.
 */
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
