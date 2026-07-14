const dns = require('dns').promises;
const psl = require('psl');
const crypto = require('crypto');

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

// Parses a DKIM public key (base64, as published in the "p=" tag) to figure
// out its algorithm and strength. ed25519 keys are a fixed 256 bits with no
// ASN.1/DER wrapper, so they're reported directly; everything else is
// assumed to be DER-encoded SubjectPublicKeyInfo and handed to Node's crypto
// module to parse. Malformed/truncated keys are reported as unknown rather
// than throwing, since a broken key is still worth showing to the user.
function getDkimKeyStrength(publicKeyBase64, keyTypeTag) {
  if (keyTypeTag === 'ed25519') {
    return { type: 'ed25519', bits: 256 };
  }
  try {
    const der = Buffer.from(publicKeyBase64, 'base64');
    const keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (keyObject.asymmetricKeyType === 'rsa') {
      return { type: 'rsa', bits: keyObject.asymmetricKeyDetails.modulusLength };
    }
    return { type: keyObject.asymmetricKeyType, bits: null };
  } catch (err) {
    return { type: keyTypeTag || null, bits: null };
  }
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
    const tags = parseRecordTags(dmarc);
    // RFC 7489 §6.4: both adkim and aspf default to relaxed ('r') when the
    // tag is absent, so this makes that effective default explicit — the
    // raw tag dump above won't show a tag that isn't there.
    const alignment = {
      dkim: tags.adkim === 's' ? 'strict' : 'relaxed',
      spf: tags.aspf === 's' ? 'strict' : 'relaxed'
    };
    return { found: true, record: dmarc, policy, tags, alignment };
  } catch (err) {
    return { found: false, record: null, policy: null, tags: {} };
  }
}

// Looks up a single selector's DKIM record. Returns null if that selector
// has no DKIM1 record at all (including DNS errors — the selector just
// doesn't exist), otherwise an object describing what was found, revoked
// or not.
async function checkDkimSelector(domain, selector) {
  try {
    const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const dkim = flat.find(txt => txt.includes('v=DKIM1'));
    if (!dkim) return null;

    const publicKeyMatch = dkim.match(/p=([^;]*)/);
    const publicKey = publicKeyMatch ? publicKeyMatch[1].trim() : '';
    if (!publicKey) {
      return { selector, record: dkim, revoked: true };
    }
    const tags = parseRecordTags(dkim);
    const keyStrength = getDkimKeyStrength(publicKey, tags.k);
    return { selector, record: dkim, tags, keyStrength, revoked: false };
  } catch (err) {
    return null;
  }
}

// customSelector, when provided, is tried before the common-selector list —
// a matching custom selector short-circuits the probing entirely. If it
// doesn't match anything, this falls through to COMMON_DKIM_SELECTORS as
// usual, since the custom one being wrong doesn't mean DKIM isn't set up
// under one of the common names.
async function checkDkim(domain, customSelector) {
  // Some zones (notably example.com) publish a wildcard DKIM record under
  // every selector with an empty "p=" — that's a revoked/placeholder key,
  // not a usable one, so it doesn't count as a real match. But it's still
  // meaningfully different from no record at all, so we remember the first
  // one we see and keep looking for a selector with an actual working key.
  let revoked = null;

  const selectors = customSelector ? [customSelector, ...COMMON_DKIM_SELECTORS] : COMMON_DKIM_SELECTORS;

  for (const selector of selectors) {
    const result = await checkDkimSelector(domain, selector);
    if (!result) continue;

    if (result.revoked) {
      if (!revoked) revoked = { selector: result.selector, record: result.record };
      continue;
    }

    return {
      found: true, status: 'found', selector: result.selector, record: result.record,
      tags: result.tags, keyStrength: result.keyStrength
    };
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

// The four checks below are informational only (not scored) — they surface
// newer/less-common email security signals without penalizing domains that
// haven't adopted them yet.

async function checkMtaSts(domain) {
  try {
    const records = await dns.resolveTxt(`_mta-sts.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const record = flat.find(txt => txt.startsWith('v=STSv1')) || null;
    return { found: !!record, record };
  } catch (err) {
    return { found: false, record: null };
  }
}

async function checkTlsRpt(domain) {
  try {
    const records = await dns.resolveTxt(`_smtp._tls.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const record = flat.find(txt => txt.startsWith('v=TLSRPTv1')) || null;
    return { found: !!record, record };
  } catch (err) {
    return { found: false, record: null };
  }
}

async function checkBimi(domain) {
  try {
    const records = await dns.resolveTxt(`default._bimi.${domain}`);
    const flat = records.map(parts => parts.join(''));
    const record = flat.find(txt => txt.startsWith('v=BIMI1')) || null;
    return { found: !!record, record };
  } catch (err) {
    return { found: false, record: null };
  }
}

// Node's built-in dns module doesn't support 'DNSKEY' as a queryable rrtype,
// so DNSSEC presence is checked via Google's DNS-over-HTTPS JSON API instead.
async function checkDnssec(domain) {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`, {
      signal: AbortSignal.timeout(5000)
    });
    const data = await res.json();
    const found = data.Status === 0 && Array.isArray(data.Answer) && data.Answer.some(r => r.type === 48);
    return { found };
  } catch (err) {
    return { found: false };
  }
}

function buildScoreAndAdvice(spf, dkim, dmarc) {
  let score = 0;
  const recommendations = [];

  if (spf.found && spf.lookupCount >= 10) {
    recommendations.push({
      issue: `Your SPF record needs ${spf.lookupCount} DNS lookups to evaluate, which exceeds RFC 7208's ` +
        '10-lookup limit, so SPF is already failing ("permerror") for anyone receiving your mail, even ' +
        'though a record exists.',
      fix: 'Combine your "include:" mechanisms or ask your email provider about SPF flattening to bring the lookup count below 10.'
    });
  } else if (spf.found) {
    score += 30;
    if (spf.lookupCount >= 8) {
      recommendations.push({
        issue: `Your SPF record is close to RFC 7208's 10-DNS-lookup limit, currently at ${spf.lookupCount} of 10.`,
        fix: 'Be cautious adding more third-party sending services (marketing tools, CRMs, etc.), since one more could push it over the limit and break SPF entirely ("permerror").'
      });
    }
  } else if (spf.status === 'multiple_records') {
    recommendations.push({
      issue: `Found ${spf.records.length} SPF records for this domain, which is invalid. RFC 7208 permits ` +
        'only one per domain, so SPF evaluation returns a "permerror" and fails entirely, even if each ' +
        'individual record looks fine on its own.',
      fix: 'Merge all the "include:" mechanisms from every record into a single "v=spf1" TXT record, then remove the duplicates.'
    });
  } else {
    recommendations.push({
      issue: 'No SPF record was found for this domain.',
      fix: 'Add a TXT record (e.g. "v=spf1 include:_spf.yourprovider.com ~all") so receiving mail servers know which servers are allowed to send email for your domain.'
    });
  }

  if (dkim.found) {
    const keyStrength = dkim.keyStrength || {};
    if (keyStrength.type === 'rsa' && keyStrength.bits < 1024) {
      score += 15;
      recommendations.push({
        issue: `Your DKIM key (selector "${dkim.selector}") is only ${keyStrength.bits}-bit RSA, which is ` +
          'below the 1024-bit floor generally considered secure against factoring attacks.',
        fix: 'Rotate to a 2048-bit key.'
      });
    } else {
      score += 30;
      if (keyStrength.type === 'rsa' && keyStrength.bits < 2048) {
        recommendations.push({
          issue: `Your DKIM key (selector "${dkim.selector}") is ${keyStrength.bits}-bit RSA. It's not insecure, ` +
            'but below the modern 2048-bit baseline.',
          fix: 'Worth upgrading to a 2048-bit key next time DKIM settings are touched.'
        });
      }
    }
  } else if (dkim.status === 'revoked') {
    recommendations.push({
      issue: `A DKIM record was found (selector "${dkim.selector}"), but it has no public key, so it's ` +
        'inactive, either intentionally disabled/revoked, or the setup was never finished. Mail signed ' +
        'with this selector will fail DKIM checks.',
      fix: 'Contact your email provider to re-enable it with a real key, or remove the stale record if it\'s no longer needed.'
    });
  } else {
    recommendations.push({
      issue: 'No DKIM record was found for common selectors.',
      fix: 'Check your email provider\'s dashboard for their DKIM setup instructions, which will give you the exact selector and TXT record to add.'
    });
  }

  if (dmarc.found) {
    if (dmarc.policy === 'reject') {
      score += 40;
    } else if (dmarc.policy === 'quarantine') {
      score += 30;
      recommendations.push({
        issue: 'Your DMARC policy is set to "p=quarantine", which sends suspicious mail to spam rather than blocking it outright, a solid middle ground.',
        fix: 'Once you\'ve confirmed legitimate mail reliably passes SPF/DKIM, consider upgrading to "p=reject" for the strongest protection.'
      });
    } else if (dmarc.policy === 'none') {
      score += 15;
      recommendations.push({
        issue: 'Your DMARC policy is set to "p=none". A record exists and you\'ll receive reports, but it isn\'t enforcing anything yet, so spoofed mail is delivered normally.',
        fix: 'Once you\'ve confirmed legitimate mail reliably passes SPF/DKIM, move to "p=quarantine" or "p=reject" so the record actually protects you.'
      });
    } else {
      score += 10;
      recommendations.push({
        issue: 'Your DMARC record doesn\'t specify a policy ("p=none", "p=quarantine", or "p=reject"), so it\'s not clear how receiving mail servers should treat spoofed email.',
        fix: 'Add an explicit policy so the record actually does something.'
      });
    }

    if (!dmarc.tags.rua) {
      if (dmarc.policy === 'none') {
        recommendations.push({
          issue: 'Your DMARC record has no "rua" reporting address and is set to "p=none", so spoofed mail isn\'t being blocked or quarantined, and you\'re not receiving reports about it either.',
          fix: 'Add "rua=mailto:you@yourdomain.com" and consider moving to "p=quarantine" or "p=reject" once you\'ve reviewed the reports.'
        });
      } else if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
        recommendations.push({
          issue: 'Your DMARC policy is enforcing correctly, but there\'s no "rua" reporting address set, so you have no visibility into what mail is being blocked or quarantined on your behalf.',
          fix: 'Add "rua=mailto:you@yourdomain.com" to your DMARC record to start receiving aggregate reports.'
        });
      }
    }

    if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
      const relaxedProtocols = [];
      if (dmarc.alignment.spf === 'relaxed') relaxedProtocols.push('SPF');
      if (dmarc.alignment.dkim === 'relaxed') relaxedProtocols.push('DKIM');
      if (relaxedProtocols.length > 0) {
        recommendations.push({
          issue: `${relaxedProtocols.join(' and ')} alignment ${relaxedProtocols.length > 1 ? 'are' : 'is'} ` +
            'set to relaxed (the default), which allows a subdomain of your sending/signing domain to still count as aligned.',
          fix: 'This is optional hardening, not required. Only switch to strict alignment ("adkim=s"/"aspf=s") after confirming your legitimate mail already passes SPF/DKIM from the exact sending domain, since strict mode will break alignment for mail sent from subdomains.'
        });
      }
    }
  } else {
    recommendations.push({
      issue: 'No DMARC record was found for this domain.',
      fix: 'Add a TXT record at "_dmarc.yourdomain.com" (e.g. "v=DMARC1; p=none; rua=mailto:you@yourdomain.com") to start monitoring who is sending email as your domain.'
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({ issue: 'SPF, DKIM, and DMARC all look good!', fix: null });
  }

  return { score, recommendations };
}

module.exports = {
  isValidDomainFormat,
  parseRecordTags,
  findRootDomain,
  domainExists,
  countSpfLookups,
  checkSpf,
  checkDmarc,
  checkDkim,
  getDkimKeyStrength,
  buildScoreAndAdvice,
  checkMtaSts,
  checkTlsRpt,
  checkBimi,
  checkDnssec
};
