const dns = require('dns').promises;
const psl = require('psl');
const crypto = require('crypto');
const { domainToASCII } = require('url');

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

// Converts an internationalized domain (e.g. "münchen.de") to its ASCII/
// punycode form (e.g. "xn--mnchen-3ya.de") so IDN input validates against
// DOMAIN_REGEX and resolves correctly — Node's dns module, like the wire
// protocol itself, only understands ASCII labels. Already-ASCII input
// (including domains that are already in punycode form) passes through
// unchanged. Invalid input (stray whitespace, disallowed characters) comes
// back as '' per the WHATWG URL spec, which correctly falls through to the
// standard "Invalid domain format" error rather than needing special-casing.
function toAsciiDomain(domain) {
  return domainToASCII(domain);
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
    // The key data itself couldn't be parsed (invalid base64/DER), as
    // opposed to a recognized-but-uncommon key type (handled above, which
    // also leaves bits: null but isn't a parse failure). Callers use this
    // flag to surface "found, but couldn't be parsed" instead of silently
    // showing the same result as a normal, healthy key.
    return { type: keyTypeTag || null, bits: null, parseError: true };
  }
}

// Uses the public suffix list to find the registrable root domain (e.g.
// "www.google.co.uk" -> "google.co.uk"). If the input already is its own
// root domain, parsed.domain === domain and subdomain is null.
function findRootDomain(domain) {
  const parsed = psl.parse(domain);
  return parsed.domain;
}

// Error codes that mean the DNS query itself couldn't get a reliable answer
// (resolver unreachable, timed out, refused, etc.) as opposed to a definitive
// "this name doesn't exist" (ENOTFOUND) or "name exists, just no data of this
// type" (ENODATA) response. Distinguishing these matters because a transient
// resolver failure isn't proof the domain doesn't exist — reporting it as
// such would be a false negative dressed up as a normal result.
const DNS_TRANSIENT_ERROR_CODES = new Set([
  'ETIMEOUT', 'ECONNREFUSED', 'ESERVFAIL', 'EREFUSED', 'EBADRESP',
  'ECANCELLED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH'
]);

// A domain "exists" in DNS if the parent zone delegates it via NS records.
// Returns 'nonexistent' only for a definitive NXDOMAIN (ENOTFOUND); a
// transient resolver failure (timeout, refused, unreachable, etc.) returns
// 'error' instead of being silently folded into either "exists" or
// "doesn't exist". Any other outcome (including ENODATA, which means the
// name exists but has no NS records) is treated as 'exists' so we don't
// report false negatives.
async function checkDomainStatus(domain) {
  try {
    await dns.resolveNs(domain);
    return 'exists';
  } catch (err) {
    if (err.code === 'ENOTFOUND') return 'nonexistent';
    if (DNS_TRANSIENT_ERROR_CODES.has(err.code)) return 'error';
    return 'exists';
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
//
// Alongside the running total, counter.includes collects a per-entry cost
// for each include: mechanism written directly in the domain's own record
// (depth 0 only) — its own lookup plus everything its chain recurses into.
// Nested includes (found inside a vendor's own record) are folded into
// their parent's cost rather than listed separately, since they aren't
// something the domain owner can directly remove.
async function countSpfLookups(domain, record, visited = new Set(), depth = 0, counter = { total: 0, includes: [] }) {
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
    let isInclude = false;
    if (mechanism.startsWith('include:')) {
      target = mechanism.slice('include:'.length);
      isInclude = true;
    } else if (mechanism.startsWith('redirect=')) {
      target = mechanism.slice('redirect='.length);
    }

    if (target !== null) {
      let ownCount = 1;
      count += 1;
      counter.total += 1;
      const targetRecord = await fetchSpfRecordForCounting(target);
      if (targetRecord) {
        const nested = await countSpfLookups(target, targetRecord, visited, depth + 1, counter);
        count += nested;
        ownCount += nested;
      }
      if (isInclude && depth === 0) {
        counter.includes.push({ target, count: ownCount });
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
    const counter = { total: 0, includes: [] };
    const lookupCount = await countSpfLookups(domain, spf, new Set(), 0, counter);
    return {
      found: true, status: 'found', record: spf, records: spfRecords, tags: parseRecordTags(spf),
      lookupCount, includeCosts: counter.includes
    };
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
// Unlike the other checks, this depends on an external HTTP service rather
// than a direct DNS query, so a failure here (network issue, DoH outage,
// timeout) is distinguished from a genuine "not signed" result via
// checkFailed, rather than both silently collapsing to found: false.
async function checkDnssec(domain) {
  let data;
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`, {
      signal: AbortSignal.timeout(5000)
    });
    data = await res.json();
  } catch (err) {
    return { found: false, checkFailed: true };
  }
  const found = data.Status === 0 && Array.isArray(data.Answer) && data.Answer.some(r => r.type === 48);
  return { found };
}

// Builds the "what to do" text for an over-limit SPF record. Ranks each
// top-level include: by how many lookups its chain costs, then tries to
// point at the smallest concrete set of includes whose removal would bring
// the domain back under the limit — falling back to just the ranked list
// (letting the user decide) when no include or small combination clearly
// accounts for enough of the overage on its own. This never proposes a
// rewritten/flattened record, only which existing includes to look at.
function buildSpfOverLimitFix(spf) {
  const over = spf.lookupCount - 9;
  const ranked = [...(spf.includeCosts || [])].sort((a, b) => b.count - a.count);

  const plural = n => (n === 1 ? '' : 's');
  const overPhrase = `You're ${over} lookup${plural(over)} over the limit.`;

  if (ranked.length === 0) {
    return 'Combine your "include:" mechanisms or ask your email provider about SPF flattening to bring the lookup count below 10.';
  }

  const rankedList = ranked
    .map(i => `include:${i.target} (${i.count} lookup${plural(i.count)})`)
    .join(', ');

  const top = ranked[0];
  if (top.count >= over) {
    return `${overPhrase} include:${top.target} alone accounts for ${top.count} lookup${plural(top.count)} — ` +
      `if unused, removing it would bring you under the limit. Ranked by lookup cost, highest first: ${rankedList}.`;
  }

  const combo = [];
  let cumulative = 0;
  for (const entry of ranked) {
    combo.push(entry);
    cumulative += entry.count;
    if (cumulative >= over) break;
  }

  if (cumulative >= over && combo.length > 1) {
    const comboList = combo.map(i => `include:${i.target}`).join(' + ');
    return `${overPhrase} No single include accounts for enough on its own, but removing ${comboList} together ` +
      `(${cumulative} lookups) would bring you under the limit if they're unused. ` +
      `Ranked by lookup cost, highest first: ${rankedList}.`;
  }

  return `${overPhrase} No single include is a clear fix on its own — here's the full breakdown, ranked by ` +
    `lookup cost, highest first, so you can decide what to trim: ${rankedList}.`;
}

// Boils the full check down to a single plain-English headline sentence plus
// a severity, checked in order with first match winning — separate from
// buildScoreAndAdvice's itemized recommendations, this is meant to be read
// on its own as the one-line takeaway.
function buildVerdict(spf, dkim, dmarc) {
  if (spf.found && spf.lookupCount >= 10) {
    return {
      severity: 'fail',
      text: 'Your SPF record is technically broken right now. Even your real emails may be getting rejected.'
    };
  }
  if (!spf.found && !dkim.found) {
    return {
      severity: 'fail',
      text: 'Your domain has no email protection at all. Anyone can send email pretending to be you.'
    };
  }
  if (!dkim.found) {
    return {
      severity: 'warn',
      text: "We couldn't confirm your DKIM setup automatically. This is often just a naming difference, not a real problem. Confirm it below to be sure."
    };
  }
  if (!spf.found) {
    return {
      severity: 'fail',
      text: "Anyone can currently send email that looks like it's from you. Nothing is checking who's allowed to send on your behalf."
    };
  }
  if (!dmarc.found) {
    return {
      severity: 'warn',
      text: "You're mostly set up, but without DMARC, nothing actually stops someone from sending fake emails using your exact address."
    };
  }
  if (dmarc.policy === 'none') {
    return {
      severity: 'warn',
      text: "You're now getting visibility into spoofed email, but nothing is blocking it yet. This is monitoring, not protection."
    };
  }
  if (dmarc.policy === 'quarantine') {
    return {
      severity: 'info',
      text: "You're in solid shape. Suspicious mail gets flagged, though not fully blocked yet."
    };
  }
  if (dmarc.policy === 'reject') {
    return {
      severity: 'good',
      text: "Your emails are fully protected. Scammers can't convincingly impersonate this domain."
    };
  }
  return {
    severity: 'info',
    text: "Your DMARC record doesn't specify a policy, so it's not clear how spoofed email is handled."
  };
}

function buildScoreAndAdvice(spf, dkim, dmarc) {
  let score = 0;
  const recommendations = [];

  if (spf.found && spf.lookupCount >= 10) {
    recommendations.push({
      issue: `Your SPF record needs ${spf.lookupCount} DNS lookups to evaluate, which exceeds RFC 7208's ` +
        '10-lookup limit, so SPF is already failing ("permerror") for anyone receiving your mail, even ' +
        'though a record exists.',
      fix: buildSpfOverLimitFix(spf),
      severity: 'fail'
    });
  } else if (spf.found) {
    score += 30;
    if (spf.lookupCount >= 8) {
      recommendations.push({
        issue: `Your SPF record is close to RFC 7208's 10-DNS-lookup limit, currently at ${spf.lookupCount} of 10.`,
        fix: 'Be cautious adding more third-party sending services (marketing tools, CRMs, etc.), since one more could push it over the limit and break SPF entirely ("permerror").',
        severity: 'warn'
      });
    }
  } else if (spf.status === 'multiple_records') {
    recommendations.push({
      issue: `Found ${spf.records.length} SPF records for this domain, which is invalid. RFC 7208 permits ` +
        'only one per domain, so SPF evaluation returns a "permerror" and fails entirely, even if each ' +
        'individual record looks fine on its own.',
      fix: 'Merge all the "include:" mechanisms from every record into a single "v=spf1" TXT record, then remove the duplicates.',
      severity: 'fail'
    });
  } else {
    recommendations.push({
      issue: 'No SPF record was found for this domain.',
      fix: 'Add a TXT record (e.g. "v=spf1 include:_spf.yourprovider.com ~all") so receiving mail servers know which servers are allowed to send email for your domain.',
      severity: 'fail'
    });
  }

  if (dkim.found) {
    const keyStrength = dkim.keyStrength || {};
    if (keyStrength.parseError) {
      // A record and public key were found, but the key data itself couldn't
      // be parsed — checked first so this doesn't fall into the "< 1024"
      // branch below (keyStrength.bits is null there, and null < 1024 is
      // true in JS, which would misreport an unparseable key as "weak").
      score += 15;
      recommendations.push({
        issue: `A DKIM record and public key were found (selector "${dkim.selector}"), but the key data ` +
          "couldn't be parsed to verify its type or strength — it may be malformed, truncated, or use a " +
          "format this check doesn't recognize.",
        fix: "Double-check the record was copied correctly from your email provider's DKIM setup instructions, and republish it if needed.",
        severity: 'warn'
      });
    } else if (keyStrength.type === 'rsa' && keyStrength.bits < 1024) {
      score += 15;
      recommendations.push({
        issue: `Your DKIM key (selector "${dkim.selector}") is only ${keyStrength.bits}-bit RSA, which is ` +
          'below the 1024-bit floor generally considered secure against factoring attacks.',
        fix: 'Rotate to a 2048-bit key.',
        severity: 'fail'
      });
    } else {
      score += 30;
      if (keyStrength.type === 'rsa' && keyStrength.bits < 2048) {
        recommendations.push({
          issue: `Your DKIM key (selector "${dkim.selector}") is ${keyStrength.bits}-bit RSA. It's not insecure, ` +
            'but below the modern 2048-bit baseline.',
          fix: 'Worth upgrading to a 2048-bit key next time DKIM settings are touched.',
          severity: 'info'
        });
      }
    }
  } else if (dkim.status === 'revoked') {
    recommendations.push({
      issue: `A DKIM record was found (selector "${dkim.selector}"), but it has no public key, so it's ` +
        'inactive, either intentionally disabled/revoked, or the setup was never finished. Mail signed ' +
        'with this selector will fail DKIM checks.',
      fix: 'Contact your email provider to re-enable it with a real key, or remove the stale record if it\'s no longer needed.',
      severity: 'fail'
    });
  } else {
    recommendations.push({
      issue: 'No DKIM record was found for common selectors.',
      fix: "Send us a quick test email and we'll check the real thing in seconds — or check your email provider's dashboard for their DKIM setup instructions.",
      severity: 'fail',
      id: 'dkim-not-found'
    });
  }

  if (dmarc.found) {
    if (dmarc.policy === 'reject') {
      score += 40;
    } else if (dmarc.policy === 'quarantine') {
      score += 30;
      recommendations.push({
        issue: 'Your DMARC policy is set to "p=quarantine", which sends suspicious mail to spam rather than blocking it outright, a solid middle ground.',
        fix: "Good spot. Move to full blocking once you're confident it's safe.",
        severity: 'info'
      });
    } else if (dmarc.policy === 'none') {
      score += 15;
      recommendations.push({
        issue: 'Your DMARC policy is set to "p=none". A record exists and you\'ll receive reports, but it isn\'t enforcing anything yet, so spoofed mail is delivered normally.',
        fix: "You're watching, not blocking yet. Turn on real protection once you trust your setup.",
        severity: 'warn'
      });
    } else {
      score += 10;
      recommendations.push({
        issue: "Your DMARC record doesn't say what to do with suspicious mail.",
        fix: 'Add a policy so servers know whether to block, flag, or allow it.',
        severity: 'warn'
      });
    }

    if (!dmarc.tags.rua) {
      if (dmarc.policy === 'none') {
        recommendations.push({
          issue: "You're not getting any reports on who's sending mail as your domain.",
          fix: 'Add a reporting address to start seeing that.',
          severity: 'warn'
        });
      } else if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
        recommendations.push({
          issue: "Your DMARC policy is already enforcing, but you're not getting any reports on who's sending mail as your domain.",
          fix: 'Add a reporting address to start seeing that.',
          severity: 'info'
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
          fix: 'This is optional hardening, not required. Only switch to strict alignment ("adkim=s"/"aspf=s") after confirming your legitimate mail already passes SPF/DKIM from the exact sending domain, since strict mode will break alignment for mail sent from subdomains.',
          severity: 'info'
        });
      }
    }
  } else {
    recommendations.push({
      issue: "There's no DMARC record, so nothing stops scammers from sending fake email as you.",
      fix: 'Add a TXT record at "_dmarc.yourdomain.com" (e.g. "v=DMARC1; p=none; rua=mailto:you@yourdomain.com") to start monitoring who is sending email as your domain.',
      severity: 'fail'
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({ issue: 'SPF, DKIM, and DMARC all look good!', fix: null });
  }

  return { score, recommendations };
}

module.exports = {
  isValidDomainFormat,
  toAsciiDomain,
  parseRecordTags,
  findRootDomain,
  checkDomainStatus,
  countSpfLookups,
  checkSpf,
  checkDmarc,
  checkDkim,
  getDkimKeyStrength,
  buildScoreAndAdvice,
  buildVerdict,
  checkMtaSts,
  checkTlsRpt,
  checkBimi,
  checkDnssec
};
