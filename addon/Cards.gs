/**
 * UI: turns an analysis result into Gmail add-on cards.
 *
 * Layout, top to bottom: verdict with a risk meter, one plain-language
 * sentence, what to do about it, the reasons, then technical details
 * collapsed. The user should know what to do without reading further than
 * the first two sections.
 *
 * Every string from the email or the backend is escaped before rendering
 * (card text supports a subset of HTML).
 */

const ICON_BASE = 'https://www.gstatic.com/images/icons/material/system/2x/';

const VERDICT_STYLE = {
  safe: { label: 'Looks safe', color: '#188038', icon: 'verified_user' },
  suspicious: { label: 'Suspicious', color: '#e37400', icon: 'gpp_maybe' },
  malicious: { label: 'Likely malicious', color: '#d93025', icon: 'gpp_bad' },
};

const METER_EMPTY_COLOR = '#dadce0';
const METER_SEGMENTS = 10;

// Advice for named attack patterns; falls back to advice per verdict.
const PATTERN_ADVICE = {
  'pattern.ceo_fraud':
    "Don't reply or pay. Confirm the request by calling the sender on a number you already know.",
  'pattern.credential_phishing':
    "Don't click the link or enter any details. If you're worried about your account, go to the site directly.",
  'pattern.brand_spoofing_new_domain':
    "This isn't really from the brand it names. Don't click links or open attachments.",
  'pattern.malware_delivery':
    "Don't open the attachment. If you were expecting a file from this sender, confirm with them another way first.",
  'pattern.attacker_owned_lookalike':
    "This isn't really from the brand it imitates. Don't click links or open attachments.",
};
const VERDICT_ADVICE = {
  malicious: "Don't click links, open attachments, or reply. Report it as phishing.",
  suspicious: 'Before clicking links or replying, verify with the sender through another channel.',
};

// Icon per finding: exact id first, then id prefix.
const FINDING_ICONS = {
  'content.money_request': 'payment',
  'content.credential_request': 'vpn_key',
  'content.urgency': 'schedule',
  'content.secrecy': 'lock',
  'sender.new_domain': 'event',
  'sender.young_domain': 'event',
  'sender.established_domain': 'event',
  'sender.domain_age_unknown': 'event',
  'sender.free_email': 'alternate_email',
  'pattern.verified_brand': 'verified_user',
  pattern: 'report',
  sender: 'person',
  links: 'link',
  attachments: 'attach_file',
  auth: 'security',
};

function buildResultCard(result) {
  const style = VERDICT_STYLE[result.verdict];
  const patterns = result.findings.filter(isAttackPattern);
  const warnings = result.findings.filter(function (f) {
    return f.severity !== 'info' && !isAttackPattern(f);
  });
  const details = result.findings.filter(function (f) {
    return f.severity === 'info';
  });

  const card = CardService.newCardBuilder().addSection(verdictSection(result, style, patterns, warnings));

  const advice = adviceFor(result.verdict, patterns);
  if (advice) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newDecoratedText()
          .setStartIcon(icon('lightbulb'))
          .setText(colored('<b>What to do</b>', style.color))
          .setBottomLabel(advice)
          .setWrapText(true)
      )
    );
  }

  // The strongest pattern is already the summary sentence; list the rest.
  const reasons = patterns.slice(1).concat(warnings);
  if (reasons.length) {
    card.addSection(findingsSection('Why we flagged it', reasons));
  }
  if (details.length) {
    card.addSection(findingsSection('Technical details', details).setCollapsible(true));
  }

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        '<font color="#5f6368"><i>Automated assessment. If in doubt, verify with the sender through another channel.</i></font>'
      )
    )
  );
  return card.build();
}

function verdictSection(result, style, patterns, warnings) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setStartIcon(icon(style.icon))
        .setText(colored('<b>' + style.label + '</b>', style.color))
        .setBottomLabel('Risk ' + result.score + ' of 100')
    )
    .addWidget(CardService.newTextParagraph().setText(riskMeter(result.score, style.color)));
  const summary = summarize(result, patterns, warnings);
  if (summary) {
    section.addWidget(CardService.newTextParagraph().setText(escapeHtml(summary)));
  }
  return section;
}

/**
 * One plain-language sentence, only when it adds something: the named attack
 * pattern, or reassurance when nothing was found. Otherwise the reasons list
 * says it already, and repeating its first line would be noise.
 */
function summarize(result, patterns, warnings) {
  if (patterns.length) {
    return patterns[0].detail;
  }
  if (warnings.length) {
    return null;
  }
  const verified = result.findings.some(function (f) {
    return f.id === 'pattern.verified_brand';
  });
  return verified ? 'No warning signs found, and the sender is verified.' : 'No warning signs found.';
}

function adviceFor(verdict, patterns) {
  for (let i = 0; i < patterns.length; i++) {
    if (PATTERN_ADVICE[patterns[i].id]) {
      return PATTERN_ADVICE[patterns[i].id];
    }
  }
  return VERDICT_ADVICE[verdict] || null;
}

/** Ten segments, filled in the verdict colour: risk at a glance. */
function riskMeter(score, color) {
  let filled = Math.round(score / (100 / METER_SEGMENTS));
  if (score > 0 && filled === 0) {
    filled = 1;
  }
  const segment = '▰';
  return (
    colored(segment.repeat(filled), color) +
    colored(segment.repeat(METER_SEGMENTS - filled), METER_EMPTY_COLOR)
  );
}

function findingsSection(header, findings) {
  const section = CardService.newCardSection().setHeader(header);
  findings.forEach(function (f) {
    section.addWidget(
      CardService.newDecoratedText()
        .setStartIcon(icon(iconFor(f)))
        .setText('<b>' + escapeHtml(f.title) + '</b>')
        .setBottomLabel(escapeHtml(f.detail))
        .setWrapText(true)
    );
  });
  return section;
}

function iconFor(finding) {
  if (FINDING_ICONS[finding.id]) {
    return FINDING_ICONS[finding.id];
  }
  const prefix = finding.id.split('.')[0];
  return FINDING_ICONS[prefix] || 'info';
}

function isAttackPattern(finding) {
  return finding.category === 'attack pattern' && finding.severity !== 'info';
}

function icon(name) {
  return CardService.newIconImage().setIconUrl(ICON_BASE + name + '_black_48dp.png');
}

/** color is always one of our constants, never input. */
function colored(html, color) {
  return '<font color="' + color + '">' + html + '</font>';
}

function buildErrorCard(message, retryable) {
  const section = CardService.newCardSection().addWidget(
    CardService.newDecoratedText()
      .setStartIcon(icon('warning'))
      .setText('<b>Could not analyze this email</b>')
      .setBottomLabel(escapeHtml(message))
      .setWrapText(true)
  );
  if (retryable) {
    section.addWidget(
      CardService.newTextButton()
        .setText('Try again')
        .setOnClickAction(CardService.newAction().setFunctionName('onRetry'))
    );
  }
  return CardService.newCardBuilder().addSection(section).build();
}

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newDecoratedText()
          .setStartIcon(icon('security'))
          .setText('<b>Malicious Email Scorer</b>')
          .setBottomLabel('Open an email to check it for phishing.')
          .setWrapText(true)
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
