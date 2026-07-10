const express = require('express');
const dns = require('dns').promises;

const app = express();
const PORT = 3000;

// Serve index.html, style.css, script.js from this same folder
app.use(express.static(__dirname));

// Common DKIM selectors used by popular email providers.
// There's no DNS way to discover a domain's selector, so we just try the
// usual suspects. A "not found" here means "not found among these", not
// "definitely no DKIM".
const COMMON_DKIM_SELECTORS = [
  'google', 'default', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1'
];

// Requires at least one dot (a label + TLD), each label 1-63 chars, no
// leading/trailing hyphens, and no whitespace, protocol, or path characters.
const DOMAIN_REGEX = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/;

function isValidDomainFormat(domain) {
  return domain.length <= 253 && DOMAIN_REGEX.test(domain);
}

async function checkSpf(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map(parts => parts.join(''));
    const spf = flat.find(txt => txt.startsWith('v=spf1'));
    return { found: !!spf, record: spf || null };
  } catch (err) {
    return { found: false, record: null };
  }
}

async function checkDmarc(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const dmarc = flat.find(txt => txt.startsWith('v=DMARC1'));
    if (!dmarc) return { found: false, record: null, policy: null };

    const policyMatch = dmarc.match(/p=(\w+)/);
    const policy = policyMatch ? policyMatch[1] : null;
    return { found: true, record: dmarc, policy };
  } catch (err) {
    return { found: false, record: null, policy: null };
  }
}

async function checkDkim(domain) {
  for (const selector of COMMON_DKIM_SELECTORS) {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const flat = records.map(parts => parts.join(''));
      const dkim = flat.find(txt => txt.includes('v=DKIM1'));
      if (dkim) {
        // Some zones (notably example.com) publish a wildcard DKIM record
        // under every selector with an empty "p=" — that's a revoked/placeholder
        // key, not a usable one, so it doesn't count as a real match.
        const publicKeyMatch = dkim.match(/p=([^;]*)/);
        const publicKey = publicKeyMatch ? publicKeyMatch[1].trim() : '';
        if (!publicKey) continue;
        return { found: true, selector, record: dkim };
      }
    } catch (err) {
      // that selector doesn't exist, try the next one
    }
  }
  return { found: false, selector: null, record: null };
}

function buildScoreAndAdvice(spf, dkim, dmarc) {
  let score = 0;
  const recommendations = [];

  if (spf.found) {
    score += 30;
  } else {
    recommendations.push(
      'No SPF record found. Add a TXT record (e.g. "v=spf1 include:_spf.yourprovider.com ~all") ' +
      'so receiving mail servers know which servers are allowed to send email for your domain.'
    );
  }

  if (dkim.found) {
    score += 30;
  } else {
    recommendations.push(
      'No DKIM record found for common selectors. Check your email provider\'s dashboard for their ' +
      'DKIM setup instructions — they will give you the exact selector and TXT record to add.'
    );
  }

  if (dmarc.found) {
    if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
      score += 40;
    } else if (dmarc.policy === 'none') {
      score += 20;
      recommendations.push(
        'Your DMARC policy is set to "p=none", which only monitors and does not block spoofed email. ' +
        'Once you\'ve confirmed legitimate mail passes SPF/DKIM, consider upgrading to "p=quarantine" or "p=reject".'
      );
    } else {
      score += 20;
    }
  } else {
    recommendations.push(
      'No DMARC record found. Add a TXT record at "_dmarc.yourdomain.com" (e.g. "v=DMARC1; p=none; rua=mailto:you@yourdomain.com") ' +
      'to start monitoring who is sending email as your domain.'
    );
  }

  if (recommendations.length === 0) {
    recommendations.push('Great job — SPF, DKIM, and DMARC all look good!');
  }

  return { score, recommendations };
}

app.get('/check', async (req, res) => {
  const domain = (req.query.domain || '').trim().toLowerCase();

  if (!domain) {
    return res.status(400).json({ error: 'Please provide a domain.' });
  }

  if (!isValidDomainFormat(domain)) {
    return res.status(400).json({
      error: 'Invalid domain format. Enter a plain domain like "example.com" — no spaces, "http://", or paths.'
    });
  }

  const [spf, dkim, dmarc] = await Promise.all([
    checkSpf(domain),
    checkDkim(domain),
    checkDmarc(domain)
  ]);

  const { score, recommendations } = buildScoreAndAdvice(spf, dkim, dmarc);

  res.json({ domain, spf, dkim, dmarc, score, recommendations });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
