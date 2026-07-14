const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const lib = require('./lib');

const app = express();
const PORT = 3000;

// Sets standard HTTP security headers (CSP, X-Frame-Options, etc.) using
// helmet's defaults.
app.use(helmet());

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

// A DKIM selector is a DNS label, so it gets interpolated straight into a
// query name (`${selector}._domainkey.${domain}`) — restrict it to a safe
// DNS label charset (letters, digits, hyphens, underscores, dots) rather
// than the stricter domain-format check, since selectors are just a label
// and don't need to look like a full domain.
const SELECTOR_REGEX = /^[a-zA-Z0-9._-]{1,63}$/;

function isValidSelectorFormat(selector) {
  return SELECTOR_REGEX.test(selector);
}

app.get('/check', checkLimiter, async (req, res) => {
  const domain = (req.query.domain || '').trim().toLowerCase();
  const customSelector = (req.query.selector || '').trim();

  if (!domain) {
    return res.status(400).json({ error: 'Please provide a domain.' });
  }

  // Selectors are case-sensitive in some setups, so this isn't lowercased
  // like the domain. It gets interpolated straight into a DNS query name,
  // so validate it against a safe DNS label charset before it's ever used.
  if (customSelector && !isValidSelectorFormat(customSelector)) {
    return res.status(400).json({
      error: 'Invalid DKIM selector format. Selectors may only contain letters, digits, hyphens, underscores, and dots.'
    });
  }

  // RFC 1035 caps a full domain name at 253 characters — reject anything
  // longer here, before any DNS lookups are attempted, since it's clearly
  // invalid/abusive input.
  if (domain.length > 253) {
    return res.status(400).json({
      error: 'Domain is too long. Domain names cannot exceed 253 characters.'
    });
  }

  if (!lib.isValidDomainFormat(domain)) {
    return res.status(400).json({
      error: 'Invalid domain format. Enter a plain domain like "example.com", with no spaces, "http://", or paths.'
    });
  }

  const rootDomain = lib.findRootDomain(domain);

  if (!rootDomain) {
    return res.status(400).json({
      error: 'Invalid domain format. Enter a plain domain like "example.com", with no spaces, "http://", or paths.'
    });
  }

  if (rootDomain !== domain) {
    return res.json({ domain, type: 'subdomain', rootDomain });
  }

  if (!(await lib.domainExists(domain))) {
    return res.json({ domain, type: 'nonexistent' });
  }

  const [spf, dkim, dmarc, mtaSts, tlsRpt, dnssec, bimi] = await Promise.all([
    lib.checkSpf(domain),
    lib.checkDkim(domain, customSelector),
    lib.checkDmarc(domain),
    lib.checkMtaSts(domain),
    lib.checkTlsRpt(domain),
    lib.checkDnssec(domain),
    lib.checkBimi(domain)
  ]);

  const { score, recommendations } = lib.buildScoreAndAdvice(spf, dkim, dmarc);

  res.json({
    domain, type: 'checked', spf, dkim, dmarc, score, recommendations,
    extras: { mtaSts, tlsRpt, dnssec, bimi }
  });
});

// Global error handler — must be the last app.use() call (Express
// identifies error-handling middleware by its 4-argument signature). Logs
// the full error server-side for debugging, but never sends the error
// message, stack trace, or other internal details in the response, since
// that could leak internal file paths or implementation details to users.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
