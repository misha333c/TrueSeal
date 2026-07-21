const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const lib = require('./lib');

// Loads SUPABASE_URL/SUPABASE_ANON_KEY from .env into process.env. Silently
// ignored if the file doesn't exist (e.g. production envs that inject vars
// directly) so this never crashes startup.
try {
  process.loadEnvFile();
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
}

const app = express();
const PORT = 3000;

// Sets standard HTTP security headers (CSP, X-Frame-Options, etc.) using
// helmet's defaults, widened just enough to allow the Supabase JS client
// (script-src for the unpkg CDN build, connect-src for the browser's direct
// calls to the Supabase project's auth API) and the DKIM selector Worker's
// /lookup polling endpoint (connect-src).
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'script-src': ["'self'", 'https://unpkg.com'],
      'connect-src': ["'self'", 'https://*.supabase.co', 'wss://*.supabase.co', 'https://trueseal-dkim-selector-test.trueseal-dkim.workers.dev']
    }
  }
}));

// Serve index.html, style.css, script.js from this same folder
app.use(express.static(__dirname));

// Hands the frontend the Supabase project URL and anon (public) key, read
// server-side from .env, so they don't need to be hardcoded into a static
// JS file. The anon key is safe to expose to the browser by design — it's
// what Supabase's client-side SDK is meant to use — but this still keeps
// it out of committed source in case the deployment setup changes later.
app.get('/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL || '',
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || ''
  });
});

// Each /check request can trigger multiple real DNS lookups (SPF recursion,
// DKIM selector probing, etc.), so this endpoint specifically is rate
// limited to prevent abuse from tying up outbound DNS.
const checkLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "You've made too many requests. Please wait a minute and try again." }
});

// Express 4 doesn't forward a rejected promise from an async route handler
// to the error-handling middleware on its own — an uncaught rejection would
// just leave the request hanging with no response at all, which is a worse
// silent failure than a generic 500. This wrapper ensures any unexpected
// throw/rejection reaches next(err), so the global handler below always
// gets a chance to respond.
function asyncHandler(fn) {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
}

// In-memory cache for /check results, keyed by normalized domain (and
// custom selector, since that can change the DKIM outcome) — avoids
// redundant real DNS/DoH work for repeat checks of the same domain within
// the TTL window. Deliberately a plain Map, not a database/external store:
// this is per-process, best-effort memoization, not a durability guarantee.
const CACHE_TTL_MS = 5 * 60 * 1000;
const checkCache = new Map();

function cacheKeyFor(domain, customSelector) {
  return `${domain}::${customSelector || 'default'}`;
}

function getCachedResult(key) {
  const entry = checkCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp >= CACHE_TTL_MS) {
    checkCache.delete(key);
    return null;
  }
  return entry.result;
}

// Sweeps expired entries so the Map doesn't grow unbounded over a long
// server session. Run once per request rather than on a separate interval
// timer — cheap enough given the rate limiter already caps traffic at 30
// requests/minute, and avoids managing a timer handle's lifecycle.
function sweepExpiredCacheEntries() {
  const now = Date.now();
  for (const [key, entry] of checkCache) {
    if (now - entry.timestamp >= CACHE_TTL_MS) {
      checkCache.delete(key);
    }
  }
}

// A DKIM selector is a DNS label, so it gets interpolated straight into a
// query name (`${selector}._domainkey.${domain}`) — restrict it to a safe
// DNS label charset (letters, digits, hyphens, underscores, dots) rather
// than the stricter domain-format check, since selectors are just a label
// and don't need to look like a full domain.
const SELECTOR_REGEX = /^[a-zA-Z0-9._-]{1,63}$/;

function isValidSelectorFormat(selector) {
  return SELECTOR_REGEX.test(selector);
}

app.get('/check', checkLimiter, asyncHandler(async (req, res) => {
  const rawDomain = (req.query.domain || '').trim().toLowerCase();
  const customSelector = (req.query.selector || '').trim();

  if (!rawDomain) {
    return res.status(400).json({ error: 'Please provide a domain.' });
  }

  // Converts internationalized domains (e.g. "münchen.de") to their ASCII/
  // punycode form (e.g. "xn--mnchen-3ya.de") so IDN input validates and
  // resolves correctly, since DOMAIN_REGEX and DNS itself both only
  // understand ASCII labels. Already-ASCII input (including domains already
  // in punycode form) passes through unchanged; disallowed input becomes ''
  // here, which correctly falls through to the "Invalid domain format"
  // error below.
  const domain = lib.toAsciiDomain(rawDomain);

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

  // Everything past this point involves real DNS/DoH work, so it's the
  // range worth caching. Sweeping here (rather than on a separate interval)
  // keeps the Map bounded without needing to manage a timer's lifecycle.
  sweepExpiredCacheEntries();
  const cacheKey = cacheKeyFor(domain, customSelector);
  const cachedResult = getCachedResult(cacheKey);
  if (cachedResult) {
    return res.json({ ...cachedResult, cached: true });
  }

  const domainStatus = await lib.checkDomainStatus(domain);

  if (domainStatus === 'nonexistent') {
    const result = { domain, type: 'nonexistent' };
    checkCache.set(cacheKey, { result, timestamp: Date.now() });
    return res.json({ ...result, cached: false });
  }

  if (domainStatus === 'error') {
    // Not cached — a transient resolver failure shouldn't be memoized as
    // if it were a real, stable result; the next request should retry DNS.
    return res.status(503).json({
      error: "We couldn't reach the DNS servers to check this domain — this might be a temporary network issue. Try again in a moment."
    });
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

  const result = {
    domain, type: 'checked', spf, dkim, dmarc, score, recommendations,
    extras: { mtaSts, tlsRpt, dnssec, bimi }
  };
  checkCache.set(cacheKey, { result, timestamp: Date.now() });
  res.json({ ...result, cached: false });
}));

// Global error handler — must be the last app.use() call (Express
// identifies error-handling middleware by its 4-argument signature). Logs
// the full error server-side for debugging, but never sends the error
// message, stack trace, or other internal details in the response, since
// that could leak internal file paths or implementation details to users.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our end. Please try again.' });
});

// Only auto-start the listener when run directly (`node server.js` /
// `npm start`) — tests require this module to get `app` for supertest
// without binding a real port.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
