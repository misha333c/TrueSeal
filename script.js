const button = document.getElementById('check-button');
const input = document.getElementById('domain-input');
const result = document.getElementById('result');

button.addEventListener('click', async () => {
  const domain = input.value.trim();

  if (!domain) {
    showMessage('Please enter a domain.');
    return;
  }

  showMessage('Checking...');
  button.disabled = true;

  try {
    const response = await fetch(`/check?domain=${encodeURIComponent(domain)}`);
    const data = await response.json();

    if (!response.ok) {
      showMessage(data.error || 'Something went wrong.');
      return;
    }

    if (data.type === 'subdomain') {
      showNotice('subdomain', `This looks like a subdomain — email security records are typically set on the root domain. Try checking ${data.rootDomain} instead.`);
      return;
    }

    if (data.type === 'nonexistent') {
      showNotice('nonexistent', "This domain doesn't appear to exist — check the spelling.");
      return;
    }

    renderResult(data);
  } catch (err) {
    showMessage('Could not reach the server. Is it running?');
  } finally {
    button.disabled = false;
  }
});

function showMessage(text) {
  result.replaceChildren();
  const p = document.createElement('p');
  p.className = 'result-message';
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

// status: 'pass' | 'warn' | 'fail'
function createCheckItem(status, label, detail, record, tags, note) {
  const li = document.createElement('li');
  li.className = `check ${status}`;

  const icon = document.createElement('span');
  icon.className = 'check-icon';
  icon.textContent = status === 'pass' ? '✓' : status === 'warn' ? '!' : '✕';

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
      'fail', 'SPF', `Multiple SPF records found (${spf.records.length}) — invalid`,
      spf.records, spf.tags,
      'RFC 7208 allows only one SPF record per domain. Publishing more than one causes SPF evaluation to ' +
      'return a "permerror", which fails SPF entirely for receiving mail servers.'
    );
  }
  return createCheckItem('fail', 'SPF', 'Not found');
}

function dkimCheckItem(dkim) {
  if (dkim.found) {
    return createCheckItem('pass', 'DKIM', `Found (selector: ${dkim.selector})`, dkim.record, dkim.tags);
  }
  if (dkim.status === 'revoked') {
    return createCheckItem(
      'warn', 'DKIM', `Found, but inactive — empty public key (selector: "${dkim.selector}")`,
      dkim.record, dkim.tags
    );
  }
  return createCheckItem(
    'fail', 'DKIM', 'Not found among common selectors',
    null, null,
    "DKIM selectors can't be fully discovered via DNS alone, so this only means no record was found among " +
    "common selector names — not a guaranteed absence of DKIM. The domain's provider may use a custom " +
    "selector this check doesn't know about."
  );
}

function dmarcCheckItem(dmarc) {
  if (!dmarc.found) {
    return createCheckItem('fail', 'DMARC', 'Not found');
  }
  const detail = `Found (policy: ${dmarc.policy || 'none specified'})`;
  const status = dmarc.policy === 'reject' ? 'pass' : 'warn';
  return createCheckItem(status, 'DMARC', detail, dmarc.record, dmarc.tags);
}

function renderResult(data) {
  result.replaceChildren();

  const scoreRow = document.createElement('div');
  scoreRow.className = 'score-row';
  const scoreValue = document.createElement('span');
  scoreValue.className = `score-value ${scoreClass(data.score)}`;
  scoreValue.textContent = data.score;
  const scoreMax = document.createElement('span');
  scoreMax.className = `score-max ${scoreClass(data.score)}`;
  scoreMax.textContent = '/ 100';
  scoreRow.appendChild(scoreValue);
  scoreRow.appendChild(scoreMax);

  const checks = document.createElement('ul');
  checks.className = 'checks';
  checks.appendChild(spfCheckItem(data.spf));
  checks.appendChild(dkimCheckItem(data.dkim));
  checks.appendChild(dmarcCheckItem(data.dmarc));

  const recommendations = document.createElement('div');
  recommendations.className = 'recommendations';
  const heading = document.createElement('h3');
  heading.textContent = 'Recommendations';
  const list = document.createElement('ul');
  data.recommendations.forEach(rec => {
    const li = document.createElement('li');
    li.textContent = rec;
    list.appendChild(li);
  });
  recommendations.appendChild(heading);
  recommendations.appendChild(list);

  result.appendChild(scoreRow);
  result.appendChild(createScoreExplainer());
  result.appendChild(checks);
  result.appendChild(recommendations);
}
