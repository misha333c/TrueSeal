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

// status: 'pass' | 'warn' | 'fail'
function createCheckItem(status, label, detail) {
  const li = document.createElement('li');
  li.className = `check ${status}`;

  const icon = document.createElement('span');
  icon.className = 'check-icon';
  icon.textContent = status === 'pass' ? '✓' : status === 'warn' ? '!' : '✕';

  const text = document.createElement('span');
  const labelSpan = document.createElement('span');
  labelSpan.className = 'check-label';
  labelSpan.textContent = `${label}: `;
  const detailSpan = document.createElement('span');
  detailSpan.className = 'check-detail';
  detailSpan.textContent = detail;
  text.appendChild(labelSpan);
  text.appendChild(detailSpan);

  li.appendChild(icon);
  li.appendChild(text);
  return li;
}

function spfCheckItem(spf) {
  return spf.found
    ? createCheckItem('pass', 'SPF', 'Found')
    : createCheckItem('fail', 'SPF', 'Not found');
}

function dkimCheckItem(dkim) {
  if (dkim.found) {
    return createCheckItem('pass', 'DKIM', `Found (selector: ${dkim.selector})`);
  }
  if (dkim.status === 'revoked') {
    return createCheckItem('warn', 'DKIM', `Found, but inactive — empty public key (selector: "${dkim.selector}")`);
  }
  return createCheckItem('fail', 'DKIM', 'Not found among common selectors');
}

function dmarcCheckItem(dmarc) {
  if (!dmarc.found) {
    return createCheckItem('fail', 'DMARC', 'Not found');
  }
  const detail = `Found (policy: ${dmarc.policy || 'none specified'})`;
  const status = dmarc.policy === 'reject' ? 'pass' : 'warn';
  return createCheckItem(status, 'DMARC', detail);
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
  result.appendChild(checks);
  result.appendChild(recommendations);
}
