const express = require('express');
const rateLimit = require('express-rate-limit');
const dns = require('dns').promises;
const psl = require('psl');

const app = express();
const PORT = 3000;

// Serve index.html, style.css, script.js from this same folder
app.use(express.static(__dirname));

// Each /check request can trigger multiple real DNS lookups (SPF recursion,
// DKIM selector probing, etc.), so this endpoint specifically is rate
// limited to prevent abuse from tying up outbound DNS.
const checkLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again in a minute.' }
});

// Common DKIM selectors used by popular email providers.
// There's no DNS way to discover a domain's selector, so we just try the
// usual suspects. A "not found" here means "not found among these", not
// "definitely no DKIM".
const COMMON_DKIM_SELECTORS = [
  'google', 'default', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1',
  's2', 'k2', 'k3', 'dkim1', 'dkim2', 'mandrill', 'zoho', 'pm', 'mailgun', 'smtp'
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

// Same lookup rule RFC 7208 §4.6.4 caps at 10 for real evaluation; we allow
// deeper recursion (15) purely so counting can surface a runaway chain
// instead of silently truncating it at the same limit that flags it.
const MAX_SPF_RECURSION_DEPTH = 15;

// Caps the total number of DNS lookups performed across the whole recursive
// count for a single request, separate from the depth cap above — without
// this, a domain with many include: mechanisms spread across multiple levels
// could still trigger an excessive number of sequential DNS queries even
// while staying under the depth limit. 50 is a generous ceiling well above
// any real-world case (real domains stay under 10).
const MAX_SPF_TOTAL_LOOKUPS = 50;

// Fetches the single v=spf1 TXT record for a domain, for recursive lookup
// counting only. Anything that isn't exactly one record (missing, or
// multiple/permerror) contributes no further lookups, so this returns null.
async function fetchSpfRecordForCounting(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map(parts => parts.join(''));
    const spfRecords = flat.filter(txt => txt.startsWith('v=spf1'));
    return spfRecords.length === 1 ? spfRecords[0] : null;
  } catch (err) {
    return null;
  }
}

// RFC 7208 §4.6.4: counts the mechanisms/modifiers that each cost one DNS
// lookup (include, a, mx, ptr, exists, redirect) — ip4/ip6/all are free.
// Recurses into include:/redirect= targets, tracking visited domains in the
// current chain to break circular includes, and stops past
// MAX_SPF_RECURSION_DEPTH so a pathological chain can't recurse forever.
async function countSpfLookups(domain, record, visited = new Set(), depth = 0, counter = { total: 0 }) {
  if (depth > MAX_SPF_RECURSION_DEPTH || visited.has(domain)) {
    return 0;
  }
  visited.add(domain);

  const tokens = record.split(/\s+/).filter(Boolean);
  let count = 0;

  for (const token of tokens) {
    // Total-lookup cap: once we've hit it, stop issuing further DNS queries
    // anywhere in the recursion and return what we have so far.
    if (counter.total >= MAX_SPF_TOTAL_LOOKUPS) {
      break;
    }

    const mechanism = token.replace(/^[+\-~?]/, '');

    let target = null;
    if (mechanism.startsWith('include:')) {
      target = mechanism.slice('include:'.length);
    } else if (mechanism.startsWith('redirect=')) {
      target = mechanism.slice('redirect='.length);
    }

    if (target !== null) {
      count += 1;
      counter.total += 1;
      const targetRecord = await fetchSpfRecordForCounting(target);
      if (targetRecord) {
        count += await countSpfLookups(target, targetRecord, visited, depth + 1, counter);
      }
    } else if (
      mechanism === 'a' || mechanism.startsWith('a:') || mechanism.startsWith('a/') ||
      mechanism === 'mx' || mechanism.startsWith('mx:') || mechanism.startsWith('mx/') ||
      mechanism === 'ptr' || mechanism.startsWith('ptr:') ||
      mechanism.startsWith('exists:')
    ) {
      count += 1;
      counter.total += 1;
    }
  }

  return count;
}

async function checkSpf(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map(parts => parts.join(''));
    const spfRecords = flat.filter(txt => txt.startsWith('v=spf1'));

    if (spfRecords.length === 0) {
      return { found: false, status: 'not_found', record: null, records: [], tags: {}, lookupCount: 0 };
    }

    // RFC 7208: a domain must publish exactly one SPF record. Two or more
    // causes SPF evaluation to return "permerror", which many receivers
    // treat as an outright SPF failure — so this is not just "the first
    // one wins", it invalidates SPF for the domain entirely.
    if (spfRecords.length >= 2) {
      return { found: false, status: 'multiple_records', record: null, records: spfRecords, tags: {}, lookupCount: 0 };
    }

    const spf = spfRecords[0];
    const lookupCount = await countSpfLookups(domain, spf);
    return { found: true, status: 'found', record: spf, records: spfRecords, tags: parseRecordTags(spf), lookupCount };
  } catch (err) {
    return { found: false, status: 'not_found', record: null, records: [], tags: {}, lookupCount: 0 };
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

  if (spf.found && spf.lookupCount >= 10) {
    recommendations.push(
      `This domain's SPF record requires ${spf.lookupCount} DNS lookups, which exceeds RFC 7208's 10-lookup ` +
      'limit — so SPF is already failing (permerror) for receiving mail servers even though a record exists. ' +
      'Consolidate "include:" mechanisms or use SPF flattening to reduce the lookup count below 10.'
    );
  } else if (spf.found) {
    score += 30;
    if (spf.lookupCount >= 8) {
      recommendations.push(
        `This domain's SPF record is close to SPF's 10-DNS-lookup limit (RFC 7208), currently at ` +
        `${spf.lookupCount} of 10. Adding more third-party sending services (marketing tools, CRMs, etc.) ` +
        'risks pushing it over the limit and causing SPF to fail entirely (permerror) for receiving mail servers.'
      );
    }
  } else if (spf.status === 'multiple_records') {
    recommendations.push(
      `Found ${spf.records.length} SPF records for this domain, which is invalid — RFC 7208 permits only ` +
      'one SPF record per domain. With more than one published, SPF evaluation returns a "permerror" and ' +
      'SPF fails entirely for receiving mail servers, even if each individual record looks fine on its own. ' +
      'Fix this by merging all the "include:" mechanisms from every record into a single "v=spf1" TXT record, ' +
      'then removing the duplicates.'
    );
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

    if (!dmarc.tags.rua) {
      if (dmarc.policy === 'none') {
        recommendations.push(
          'Your DMARC record has no "rua" reporting address and is set to "p=none". This means spoofed mail ' +
          'isn\'t being blocked or quarantined, and you\'re not receiving reports about it either — in its ' +
          'current state, the record isn\'t actively protecting your domain or giving you any visibility into ' +
          'abuse. Add "rua=mailto:you@yourdomain.com" and consider moving to "p=quarantine" or "p=reject" once ' +
          'you\'ve reviewed the reports.'
        );
      } else if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
        recommendations.push(
          'Your DMARC policy is enforcing correctly, but there\'s no "rua" reporting address set, so you have ' +
          'no visibility into what mail is being blocked or quarantined on your behalf. Add ' +
          '"rua=mailto:you@yourdomain.com" to your DMARC record to start receiving aggregate reports.'
        );
      }
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

app.get('/check', checkLimiter, async (req, res) => {
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
