const button = document.getElementById('check-button');
const input = document.getElementById('domain-input');
const selectorInput = document.getElementById('selector-input');
const result = document.getElementById('result');

let currentDomain = null;
let starButton = null;

async function runCheck(domainArg, selectorArg) {
  const domain = (domainArg !== undefined ? domainArg : input.value).trim();
  const customSelector = (selectorArg !== undefined ? selectorArg : selectorInput.value).trim();
  input.value = domain;
  if (selectorArg !== undefined) selectorInput.value = customSelector;

  if (!domain) {
    showMessage('Please enter a domain.', true);
    return;
  }

  showMessage('Checking...');
  button.disabled = true;

  try {
    let url = `/check?domain=${encodeURIComponent(domain)}`;
    if (customSelector) {
      url += `&selector=${encodeURIComponent(customSelector)}`;
    }
    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok) {
      showMessage(data.error || 'Something went wrong on our end. Please try again.', true);
      return;
    }

    if (data.type === 'subdomain') {
      showNotice('subdomain', `This looks like a subdomain, and email security records are typically set on the root domain. Try checking ${data.rootDomain} instead.`);
      return;
    }

    if (data.type === 'nonexistent') {
      showNotice('nonexistent', "This domain doesn't appear to exist. Check the spelling.");
      return;
    }

    renderResult(data, customSelector);
    handlePostCheck(data);
  } catch (err) {
    showMessage("Couldn't connect to the checker. Check your connection and try again.", true);
  } finally {
    button.disabled = false;
  }
}

button.addEventListener('click', () => runCheck());

// Pressing Enter in either input runs the same check as clicking the button.
// button.click() is a no-op while button.disabled is true (native disabled
// buttons don't fire click), so this can't trigger an overlapping request
// while one is already in flight.
function submitOnEnter(e) {
  if (e.key === 'Enter') {
    button.click();
  }
}
input.addEventListener('keydown', submitOnEnter);
selectorInput.addEventListener('keydown', submitOnEnter);

function showMessage(text, isError = false) {
  result.replaceChildren();
  const p = document.createElement('p');
  p.className = isError ? 'result-message result-message-error' : 'result-message';
  p.textContent = text;
  result.appendChild(p);
}

// kind: 'subdomain' | 'nonexistent'
function showNotice(kind, text) {
  result.replaceChildren();

  const notice = document.createElement('div');
  notice.className = `notice ${kind}`;

  const icon = document.createElement('span');
  icon.className = 'notice-icon';
  icon.textContent = kind === 'subdomain' ? 'i' : '✕';

  const p = document.createElement('p');
  p.textContent = text;

  notice.appendChild(icon);
  notice.appendChild(p);
  result.appendChild(notice);
}

function scoreClass(score) {
  if (score >= 80) return 'score-good';
  if (score >= 50) return 'score-medium';
  return 'score-poor';
}

// Builds the score circle: a track + arc SVG (arc fills clockwise from the
// top, proportional to score/100) sitting directly on the page background,
// with the number centered on top via a grid-overlaid label (reuses the
// existing score-value/score-max classes and color-coding, unchanged from
// the plain-number version). strokeWidth must match the CSS stroke-width
// on .score-ring-track/.score-ring-fill, and radius is kept a few px
// inside the viewBox edge so the stroke never clips.
function createScoreRing(score) {
  const cls = scoreClass(score);
  const size = 150;
  const strokeWidth = 12;
  const radius = size / 2 - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);

  const wrap = document.createElement('div');
  wrap.className = 'score-ring';

  const svgNs = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNs, 'svg');
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);

  const track = document.createElementNS(svgNs, 'circle');
  track.setAttribute('class', 'score-ring-track');
  track.setAttribute('cx', size / 2);
  track.setAttribute('cy', size / 2);
  track.setAttribute('r', radius);

  const fill = document.createElementNS(svgNs, 'circle');
  fill.setAttribute('class', `score-ring-fill ${cls}`);
  fill.setAttribute('cx', size / 2);
  fill.setAttribute('cy', size / 2);
  fill.setAttribute('r', radius);
  fill.setAttribute('stroke-dasharray', circumference);
  fill.setAttribute('stroke-dashoffset', offset);

  svg.appendChild(track);
  svg.appendChild(fill);

  const label = document.createElement('div');
  label.className = 'score-ring-label';
  const scoreValue = document.createElement('span');
  scoreValue.className = `score-value ${cls}`;
  scoreValue.textContent = score;
  const scoreMax = document.createElement('span');
  scoreMax.className = `score-max ${cls}`;
  scoreMax.textContent = '/ 100';
  label.appendChild(scoreValue);
  label.appendChild(scoreMax);

  wrap.appendChild(svg);
  wrap.appendChild(label);
  return wrap;
}

// Builds the collapsed-by-default "Show technical details" panel with the
// raw record exactly as returned, plus every key=value tag parsed out of it
// (adkim, aspf, pct, rua, etc.) shown as-is, without interpreting them.
function createTechDetails(record, tags) {
  const details = document.createElement('details');
  details.className = 'tech-details';

  const summary = document.createElement('summary');
  summary.textContent = 'Show technical details';
  details.appendChild(summary);

  const content = document.createElement('div');
  content.className = 'tech-content';

  // `record` is normally a single raw record string, but callers (e.g. SPF
  // when multiple records are found) may pass an array to show each one.
  const records = Array.isArray(record) ? record : [record];
  records.forEach((r, i) => {
    const recordBlock = document.createElement('div');
    recordBlock.className = 'tech-record';
    const recordLabel = document.createElement('div');
    recordLabel.className = 'tech-label';
    recordLabel.textContent = records.length > 1 ? `Raw record ${i + 1}` : 'Raw record';
    const recordValue = document.createElement('code');
    recordValue.className = 'tech-record-value';
    recordValue.textContent = r;
    recordBlock.appendChild(recordLabel);
    recordBlock.appendChild(recordValue);
    content.appendChild(recordBlock);
  });

  const tagEntries = Object.entries(tags || {});
  if (tagEntries.length > 0) {
    const tagsBlock = document.createElement('div');
    tagsBlock.className = 'tech-tags';
    const tagsLabel = document.createElement('div');
    tagsLabel.className = 'tech-label';
    tagsLabel.textContent = 'Parameters';
    tagsBlock.appendChild(tagsLabel);

    const dl = document.createElement('dl');
    tagEntries.forEach(([key, value]) => {
      const dt = document.createElement('dt');
      dt.textContent = key;
      const dd = document.createElement('dd');
      dd.textContent = value;
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    tagsBlock.appendChild(dl);
    content.appendChild(tagsBlock);
  }

  details.appendChild(content);
  return details;
}

// Builds the collapsed-by-default "What does this mean?" panel that explains
// the score in plain language, reusing the same tech-details/tech-content
// classes as "Show technical details" so it matches that toggle/arrow style.
function createScoreExplainer() {
  const details = document.createElement('details');
  details.className = 'tech-details score-explainer';

  const summary = document.createElement('summary');
  summary.textContent = 'What does this mean?';
  details.appendChild(summary);

  const content = document.createElement('div');
  content.className = 'tech-content';

  const intro = document.createElement('p');
  intro.className = 'score-explainer-text';
  intro.textContent = 'Your score reflects whether your domain has three protections set up that stop other people from sending fake emails pretending to be you.';
  content.appendChild(intro);

  const list = document.createElement('ul');
  list.className = 'score-explainer-list';
  [
    ['SPF', ' is like a guest list, it says which servers are allowed to send mail as you.'],
    ['DKIM', " is like a wax seal, it proves an email wasn't tampered with on the way."],
    ['DMARC', ' is the instructions for what happens when something looks fake, whether it gets blocked, sent to spam, or let through anyway.']
  ].forEach(([term, rest]) => {
    const li = document.createElement('li');
    const strong = document.createElement('strong');
    strong.textContent = term;
    li.appendChild(strong);
    li.appendChild(document.createTextNode(rest));
    list.appendChild(li);
  });
  content.appendChild(list);

  const closing = document.createElement('p');
  closing.className = 'score-explainer-text';
  closing.textContent = "A higher score means more of these are set up correctly. It's not an official industry score, just a quick way to see where you stand and what to fix first. Check the recommendations below for exactly what to do next.";
  content.appendChild(closing);

  details.appendChild(content);
  return details;
}

// status: 'pass' | 'warn' | 'fail' | 'info'
function createCheckItem(status, label, detail, record, tags, note) {
  const li = document.createElement('div');
  li.className = `check ${status}`;

  const icon = document.createElement('span');
  icon.className = 'check-icon';
  icon.textContent = status === 'pass' ? '✓' : status === 'warn' ? '!' : status === 'info' ? 'i' : '✕';

  const body = document.createElement('div');
  body.className = 'check-body';

  const summaryLine = document.createElement('div');
  summaryLine.className = 'check-summary';
  const labelSpan = document.createElement('span');
  labelSpan.className = 'check-label';
  labelSpan.textContent = `${label}: `;
  const detailSpan = document.createElement('span');
  detailSpan.className = 'check-detail';
  detailSpan.textContent = detail;
  summaryLine.appendChild(labelSpan);
  summaryLine.appendChild(detailSpan);
  body.appendChild(summaryLine);

  if (note) {
    const noteEl = document.createElement('p');
    noteEl.className = 'check-note';
    noteEl.textContent = note;
    body.appendChild(noteEl);
  }

  if (record) {
    body.appendChild(createTechDetails(record, tags));
  }

  li.appendChild(icon);
  li.appendChild(body);
  return li;
}

function spfCheckItem(spf) {
  if (spf.found) {
    return createCheckItem('pass', 'SPF', 'Found', spf.record, spf.tags);
  }
  if (spf.status === 'multiple_records') {
    return createCheckItem(
      'fail', 'SPF', `Multiple SPF records found (${spf.records.length}), invalid`,
      spf.records, spf.tags,
      'RFC 7208 allows only one SPF record per domain. Publishing more than one causes SPF evaluation to ' +
      'return a "permerror", which fails SPF entirely for receiving mail servers.'
    );
  }
  return createCheckItem('fail', 'SPF', 'Not found');
}

function dkimCheckItem(dkim, customSelector) {
  if (dkim.found) {
    let detail = `Found (selector: ${dkim.selector})`;
    let status = 'pass';
    let note = null;
    const keyStrength = dkim.keyStrength;
    if (keyStrength && keyStrength.parseError) {
      // A record and public key exist, but the key data itself couldn't be
      // parsed — surfaced distinctly so it doesn't silently look identical
      // to a normal, healthy key (which would otherwise happen here, since
      // both leave keyStrength.bits falsy).
      status = 'warn';
      detail += ", found a key but couldn't parse it";
      note = "A public key was found for this selector, but it couldn't be parsed to determine its type or " +
        'strength — it may be malformed, truncated, or use a format this check doesn\'t recognize. ' +
        "Double-check the record was copied correctly from your provider's DKIM setup instructions.";
    } else if (keyStrength && keyStrength.type && keyStrength.bits) {
      detail += `, ${keyStrength.type.toUpperCase()}-${keyStrength.bits}`;
      if (keyStrength.type === 'rsa' && keyStrength.bits < 1024) {
        status = 'warn';
        note = `This ${keyStrength.bits}-bit RSA key is weak, below the 1024-bit floor generally considered ` +
          'secure against factoring attacks. It should be rotated to a 2048-bit key.';
      }
    }
    return createCheckItem(status, 'DKIM', detail, dkim.record, dkim.tags, note);
  }
  if (dkim.status === 'revoked') {
    return createCheckItem(
      'warn', 'DKIM', `Found, but inactive, empty public key (selector: "${dkim.selector}")`,
      dkim.record, dkim.tags
    );
  }
  const detail = customSelector
    ? `Not found among common selectors or "${customSelector}"`
    : 'Not found among common selectors';
  const note = customSelector
    ? `DKIM selectors can't be fully discovered via DNS alone, so this means no record was found among ` +
      `common selector names or the custom selector "${customSelector}" you provided. This isn't a guaranteed ` +
      "absence of DKIM. Double-check the selector, or the domain's provider may use a different one."
    : "DKIM selectors can't be fully discovered via DNS alone, so this only means no record was found among " +
      "common selector names. It isn't a guaranteed absence of DKIM. The domain's provider may use a custom " +
      "selector this check doesn't know about.";
  return createCheckItem('fail', 'DKIM', detail, null, null, note);
}

function dmarcCheckItem(dmarc) {
  if (!dmarc.found) {
    return createCheckItem('fail', 'DMARC', 'Not found');
  }
  const detail = `Found (policy: ${dmarc.policy || 'none specified'})`;
  const status = dmarc.policy === 'reject' ? 'pass' : 'warn';
  const note = `Alignment (SPF: ${dmarc.alignment.spf}, DKIM: ${dmarc.alignment.dkim}). Relaxed (the default) ` +
    'allows a subdomain match; strict requires the exact sending/signing domain to match.';
  return createCheckItem(status, 'DMARC', detail, dmarc.record, dmarc.tags, note);
}

// Builds a single informational item for the "Additional signals" grid.
// Status is 'pass' when found, 'info' (never 'fail') when not — most
// domains haven't adopted these protocols yet, so absence isn't a
// misconfiguration worth flagging as a failure. checkFailed (currently only
// set by DNSSEC, which depends on an external DNS-over-HTTPS service rather
// than a direct DNS query) is surfaced as "couldn't verify" instead of
// silently looking identical to a genuine "not found".
function extraCheckItem(label, data, description) {
  if (data.checkFailed) {
    return createCheckItem(
      'info', label, "Couldn't verify", null, null,
      `${description} This check relies on an external DNS-over-HTTPS lookup, which didn't respond — that's ` +
      "likely a temporary issue and not necessarily related to this domain. Try again in a moment."
    );
  }
  const status = data.found ? 'pass' : 'info';
  const detail = data.found ? 'Found' : 'Not found';
  return createCheckItem(status, label, detail, data.record || null, null, description);
}

// Builds the "Additional signals" section: a 2x2 grid of newer/less-common
// email security protocols that aren't part of the score above.
function createExtrasSection(extras) {
  const section = document.createElement('div');
  section.className = 'extras-section';

  const heading = document.createElement('h3');
  heading.textContent = 'Additional signals';
  section.appendChild(heading);

  const subtitle = document.createElement('p');
  subtitle.className = 'extras-subtitle';
  subtitle.textContent = "Not part of the score above. These are newer or less common protocols, so their absence isn't a misconfiguration.";
  section.appendChild(subtitle);

  const grid = document.createElement('div');
  grid.className = 'checks extras-grid';
  grid.appendChild(extraCheckItem(
    'MTA-STS', extras.mtaSts,
    'Enforces TLS encryption for inbound mail, rejecting delivery over unencrypted or unauthenticated connections.'
  ));
  grid.appendChild(extraCheckItem(
    'TLS-RPT', extras.tlsRpt,
    'Requests reports about failed TLS connections when other mail servers try to deliver to this domain.'
  ));
  grid.appendChild(extraCheckItem(
    'DNSSEC', extras.dnssec,
    "Cryptographically signs DNS records so they can't be spoofed or tampered with in transit."
  ));
  grid.appendChild(extraCheckItem(
    'BIMI', extras.bimi,
    'Displays a verified brand logo next to authenticated emails in supporting inboxes.'
  ));
  section.appendChild(grid);

  return section;
}

// Builds a single recommendation block. rec is { issue, fix }: fix is null
// for the "all clear" case, which renders as a single confirmation line
// instead of an issue/fix pair.
function createRecommendationItem(rec) {
  const item = document.createElement('div');

  if (rec.fix === null) {
    item.className = 'recommendation recommendation-allclear';
    const text = document.createElement('p');
    text.className = 'recommendation-text';
    text.textContent = rec.issue;
    item.appendChild(text);
    return item;
  }

  item.className = 'recommendation';

  const issueRow = document.createElement('p');
  issueRow.className = 'recommendation-row';
  const issueLabel = document.createElement('span');
  issueLabel.className = 'recommendation-label';
  issueLabel.textContent = "What's going on: ";
  issueRow.appendChild(issueLabel);
  issueRow.appendChild(document.createTextNode(rec.issue));
  item.appendChild(issueRow);

  const fixRow = document.createElement('p');
  fixRow.className = 'recommendation-row';
  const fixLabel = document.createElement('span');
  fixLabel.className = 'recommendation-label';
  fixLabel.textContent = 'What to do: ';
  fixRow.appendChild(fixLabel);
  fixRow.appendChild(document.createTextNode(rec.fix));
  item.appendChild(fixRow);

  return item;
}

// Star icon path (Material "star" glyph, 24x24 viewBox). Fill/outline is
// toggled purely with CSS (.star-button.starred), not by swapping paths.
const STAR_PATH = 'M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z';

function createResultHeader(domain) {
  currentDomain = domain;

  const header = document.createElement('div');
  header.className = 'result-header';

  const heading = document.createElement('h2');
  heading.className = 'result-domain';
  heading.textContent = domain;
  header.appendChild(heading);

  starButton = document.createElement('button');
  starButton.type = 'button';
  starButton.className = 'star-button';
  starButton.hidden = true;
  starButton.setAttribute('aria-pressed', 'false');
  starButton.setAttribute('aria-label', `Star ${domain}`);

  const svgNs = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNs, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '22');
  svg.setAttribute('height', '22');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(svgNs, 'path');
  path.setAttribute('d', STAR_PATH);
  svg.appendChild(path);
  starButton.appendChild(svg);

  starButton.addEventListener('click', () => toggleStar(domain));
  header.appendChild(starButton);

  return header;
}

function setStarState(starred) {
  if (!starButton) return;
  starButton.classList.toggle('starred', starred);
  starButton.setAttribute('aria-pressed', String(starred));
  starButton.setAttribute('aria-label', starred ? `Unstar ${currentDomain}` : `Star ${currentDomain}`);
}

// Fire-and-forget: save to check_history and check starred status when
// logged in. Neither should block or slow down the result already on
// screen, and neither should surface an error to the user on failure —
// this is a best-effort convenience feature, not core functionality.
async function handlePostCheck(data) {
  if (!window.trueSealAuth) return;
  await window.trueSealAuth.ready;
  const user = window.trueSealAuth.getUser();

  if (!user) {
    if (starButton) starButton.hidden = true;
    return;
  }

  saveCheckHistory(user, data.domain, data.score);
  refreshStarState(user, data.domain);
}

async function saveCheckHistory(user, domain, score) {
  try {
    const client = await window.trueSealAuth.getClient();
    await client.from('check_history').insert({ user_id: user.id, domain, score });
  } catch (err) {
    // best-effort only
  }
}

async function refreshStarState(user, domain) {
  if (!starButton) return;
  starButton.hidden = false;
  starButton.disabled = true;
  try {
    const client = await window.trueSealAuth.getClient();
    const { data } = await client
      .from('starred_domains')
      .select('id')
      .eq('user_id', user.id)
      .eq('domain', domain)
      .maybeSingle();
    setStarState(!!data);
  } catch (err) {
    setStarState(false);
  } finally {
    starButton.disabled = false;
  }
}

async function toggleStar(domain) {
  if (!window.trueSealAuth || !starButton) return;
  const user = window.trueSealAuth.getUser();
  if (!user) return;

  starButton.disabled = true;
  const wasStarred = starButton.classList.contains('starred');
  try {
    const client = await window.trueSealAuth.getClient();
    if (wasStarred) {
      await client.from('starred_domains').delete().eq('user_id', user.id).eq('domain', domain);
      setStarState(false);
    } else {
      const { error } = await client.from('starred_domains').insert({ user_id: user.id, domain });
      // 23505 = unique_violation — e.g. a double-click racing two inserts.
      // The desired end state (a row exists) is already true, so treat it
      // the same as success rather than surfacing an error.
      if (error && error.code !== '23505') throw error;
      setStarState(true);
    }
  } catch (err) {
    // leave star state unchanged on failure
  } finally {
    starButton.disabled = false;
  }
}

function renderResult(data, customSelector) {
  result.replaceChildren();

  result.appendChild(createResultHeader(data.domain));

  const grid = document.createElement('div');
  grid.className = 'result-grid';

  const scoreCol = document.createElement('div');
  scoreCol.className = 'result-col result-col-score';
  scoreCol.appendChild(createScoreRing(data.score));
  scoreCol.appendChild(createScoreExplainer());

  const dkimCol = document.createElement('div');
  dkimCol.className = 'result-col';
  dkimCol.appendChild(dkimCheckItem(data.dkim, customSelector));

  const dmarcSpfCol = document.createElement('div');
  dmarcSpfCol.className = 'result-col';
  dmarcSpfCol.appendChild(spfCheckItem(data.spf));
  dmarcSpfCol.appendChild(dmarcCheckItem(data.dmarc));

  grid.appendChild(scoreCol);
  grid.appendChild(dkimCol);
  grid.appendChild(dmarcSpfCol);

  const recommendations = document.createElement('div');
  recommendations.className = 'recommendations';
  const heading = document.createElement('h3');
  heading.textContent = 'Recommendations';
  const list = document.createElement('div');
  list.className = 'recommendation-list';
  data.recommendations.forEach(rec => {
    list.appendChild(createRecommendationItem(rec));
  });
  recommendations.appendChild(heading);
  recommendations.appendChild(list);

  result.appendChild(grid);
  result.appendChild(recommendations);
  result.appendChild(createExtrasSection(data.extras));
}

// Lets the History modal (on this or another page) trigger a re-check and
// keep the on-page star icon in sync after an unstar action there.
window.trueSealChecker = {
  runCheck,
  syncStarButton: () => {
    if (!window.trueSealAuth || !currentDomain) return;
    window.trueSealAuth.ready.then(() => {
      const user = window.trueSealAuth.getUser();
      if (user) refreshStarState(user, currentDomain);
    });
  }
};

// Arriving from the History modal's "click to re-check" on another page
// (index.html?domain=example.com) auto-runs the check once, then cleans the
// URL so a refresh doesn't re-trigger it.
(function autoCheckFromQueryParam() {
  const params = new URLSearchParams(window.location.search);
  const domainParam = params.get('domain');
  if (!domainParam) return;
  runCheck(domainParam, '');
  const url = new URL(window.location.href);
  url.searchParams.delete('domain');
  window.history.replaceState({}, '', url);
})();
