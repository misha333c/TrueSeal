const express = require('express');
const dns = require('dns').promises;
const psl = require('psl');

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

// Pulls every "key=value" tag out of a raw record (works for both the
// ";"-delimited tags in DMARC/DKIM records and the space-delimited
// mechanisms in SPF records) without interpreting what any of them mean —
// this is purely for showing the raw technical data to the user as-is.
function parseRecordTags(record) {
  const tags = {};
  if (!record) return tags;
  record.split(/[;\s]+/).forEach(token => {
    const trimmed = token.trim();
    if (!trimmed) return;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (key) tags[key] = value;
  });
  return tags;
}

// Uses the public suffix list to find the registrable root domain (e.g.
// "www.google.co.uk" -> "google.co.uk"). If the input already is its own
// root domain, parsed.domain === domain and subdomain is null.
function findRootDomain(domain) {
  const parsed = psl.parse(domain);
  return parsed.domain;
}

// A domain "exists" in DNS if the parent zone delegates it via NS records.
// ENOTFOUND means the name itself isn't registered/delegated (NXDOMAIN);
// any other outcome (including ENODATA, which means the name exists but
// has no NS records) is treated as "exists" so we don't report false negatives.
async function domainExists(domain) {
  try {
    await dns.resolveNs(domain);
    return true;
  } catch (err) {
    return err.code !== 'ENOTFOUND';
  }
}

async function checkSpf(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map(parts => parts.join(''));
    const spf = flat.find(txt => txt.startsWith('v=spf1'));
    if (!spf) return { found: false, record: null, tags: {} };
    return { found: true, record: spf, tags: parseRecordTags(spf) };
  } catch (err) {
    return { found: false, record: null, tags: {} };
  }
}

async function checkDmarc(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const dmarc = flat.find(txt => txt.startsWith('v=DMARC1'));
    if (!dmarc) return { found: false, record: null, policy: null, tags: {} };

    const policyMatch = dmarc.match(/p=(\w+)/);
    const policy = policyMatch ? policyMatch[1] : null;
    return { found: true, record: dmarc, policy, tags: parseRecordTags(dmarc) };
  } catch (err) {
    return { found: false, record: null, policy: null, tags: {} };
  }
}

async function checkDkim(domain) {
  // Some zones (notably example.com) publish a wildcard DKIM record under
  // every selector with an empty "p=" — that's a revoked/placeholder key,
  // not a usable one, so it doesn't count as a real match. But it's still
  // meaningfully different from no record at all, so we remember the first
  // one we see and keep looking for a selector with an actual working key.
  let revoked = null;

  for (const selector of COMMON_DKIM_SELECTORS) {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const flat = records.map(parts => parts.join(''));
      const dkim = flat.find(txt => txt.includes('v=DKIM1'));
      if (dkim) {
        const publicKeyMatch = dkim.match(/p=([^;]*)/);
        const publicKey = publicKeyMatch ? publicKeyMatch[1].trim() : '';
        if (!publicKey) {
          if (!revoked) revoked = { selector, record: dkim };
          continue;
        }
        return { found: true, status: 'found', selector, record: dkim, tags: parseRecordTags(dkim) };
      }
    } catch (err) {
      // that selector doesn't exist, try the next one
    }
  }

  if (revoked) {
    return {
      found: false,
      status: 'revoked',
      selector: revoked.selector,
      record: revoked.record,
      tags: parseRecordTags(revoked.record)
    };
  }
  return { found: false, status: 'not_found', selector: null, record: null, tags: {} };
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
  } else if (dkim.status === 'revoked') {
    recommendations.push(
      `A DKIM record was found (selector "${dkim.selector}"), but it has no public key, which means it's ` +
      'inactive — either it was intentionally disabled/revoked, or the setup was never finished. Mail ' +
      'signed with this selector will fail DKIM checks. Contact your email provider to re-enable it with a ' +
      'real key, or remove the stale record if it\'s no longer needed.'
    );
  } else {
    recommendations.push(
      'No DKIM record found for common selectors. Check your email provider\'s dashboard for their ' +
      'DKIM setup instructions — they will give you the exact selector and TXT record to add.'
    );
  }

  if (dmarc.found) {
    if (dmarc.policy === 'reject') {
      score += 40;
    } else if (dmarc.policy === 'quarantine') {
      score += 30;
      recommendations.push(
        'Your DMARC policy is set to "p=quarantine", which sends suspicious mail to spam rather than ' +
        'blocking it outright — a solid middle ground. Once you\'ve confirmed legitimate mail reliably passes ' +
        'SPF/DKIM, consider upgrading to "p=reject" for the strongest protection.'
      );
    } else if (dmarc.policy === 'none') {
      score += 15;
      recommendations.push(
        'Your DMARC policy is set to "p=none". This means a record exists and you\'ll receive reports, but ' +
        'it isn\'t actually enforcing anything yet — spoofed mail is delivered normally. Once you\'ve confirmed ' +
        'legitimate mail reliably passes SPF/DKIM, move to "p=quarantine" or "p=reject" so the record actually protects you.'
      );
    } else {
      score += 10;
      recommendations.push(
        'Your DMARC record doesn\'t specify a policy ("p=none", "p=quarantine", or "p=reject"), so it\'s not ' +
        'clear how receiving mail servers should treat spoofed email. Add an explicit policy so the record ' +
        'actually does something.'
      );
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

  const rootDomain = findRootDomain(domain);

  if (!rootDomain) {
    return res.status(400).json({
      error: 'Invalid domain format. Enter a plain domain like "example.com" — no spaces, "http://", or paths.'
    });
  }

  if (rootDomain !== domain) {
    return res.json({ domain, type: 'subdomain', rootDomain });
  }

  if (!(await domainExists(domain))) {
    return res.json({ domain, type: 'nonexistent' });
  }

  const [spf, dkim, dmarc] = await Promise.all([
    checkSpf(domain),
    checkDkim(domain),
    checkDmarc(domain)
  ]);

  const { score, recommendations } = buildScoreAndAdvice(spf, dkim, dmarc);

  res.json({ domain, type: 'checked', spf, dkim, dmarc, score, recommendations });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
