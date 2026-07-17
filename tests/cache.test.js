const request = require('supertest');

// Mirrors the dns mock pattern used in dns-checks.test.js. Each test gets a
// fresh module registry (see beforeEach) so the server's in-memory cache
// Map and the rate limiter's counter both start clean per test, letting
// different tests reuse the same domain names without interfering.
jest.mock('dns', () => ({
  promises: {
    resolveTxt: jest.fn(),
    resolveNs: jest.fn()
  }
}));

function notFoundError() {
  return Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' });
}

// Wires up a domain that exists and has a plain SPF record but nothing
// else (no DKIM under any selector, no DMARC, no extras) — enough to
// exercise a full, realistic /check request without caring about the
// specific SPF/DKIM/DMARC content, which isn't what this file is testing.
function installDefaultDnsMocks() {
  const dns = require('dns').promises;
  dns.resolveNs.mockResolvedValue(['ns1.example.com']);
  dns.resolveTxt.mockImplementation(async (name) => {
    if (
      name.startsWith('_dmarc.') ||
      name.includes('._domainkey.') ||
      name.startsWith('_mta-sts.') ||
      name.startsWith('_smtp._tls.') ||
      name.startsWith('default._bimi.')
    ) {
      throw notFoundError();
    }
    return [['v=spf1 -all']];
  });
  return dns;
}

let dns;
let app;

beforeEach(() => {
  jest.resetModules();
  dns = installDefaultDnsMocks();
  global.fetch = jest.fn().mockResolvedValue({ json: async () => ({ Status: 2, Answer: [] }) });
  app = require('../server');
});

afterEach(() => {
  delete global.fetch;
});

describe('/check response caching', () => {
  test('a second identical request within the TTL is served from cache and triggers no new DNS calls', async () => {
    const first = await request(app).get('/check?domain=cache-hit-test.com');
    expect(first.status).toBe(200);
    expect(first.body.cached).toBe(false);
    expect(first.body.type).toBe('checked');

    const txtCallsAfterFirst = dns.resolveTxt.mock.calls.length;
    const nsCallsAfterFirst = dns.resolveNs.mock.calls.length;
    expect(txtCallsAfterFirst).toBeGreaterThan(0);
    expect(nsCallsAfterFirst).toBeGreaterThan(0);

    const second = await request(app).get('/check?domain=cache-hit-test.com');
    expect(second.status).toBe(200);
    expect(second.body.cached).toBe(true);
    expect(second.body.score).toBe(first.body.score);
    expect(second.body.spf).toEqual(first.body.spf);
    expect(second.body.recommendations).toEqual(first.body.recommendations);

    // No additional DNS work at all for the cache hit — not the DKIM/SPF/
    // DMARC/extras lookups, and not even the initial NS existence check.
    expect(dns.resolveTxt.mock.calls.length).toBe(txtCallsAfterFirst);
    expect(dns.resolveNs.mock.calls.length).toBe(nsCallsAfterFirst);
  });

  test('a different domain is not served from another domain\'s cache entry', async () => {
    const first = await request(app).get('/check?domain=cache-domain-a.com');
    expect(first.body.cached).toBe(false);
    const callsAfterFirst = dns.resolveTxt.mock.calls.length;

    const second = await request(app).get('/check?domain=cache-domain-b.com');
    expect(second.body.cached).toBe(false);
    expect(dns.resolveTxt.mock.calls.length).toBeGreaterThan(callsAfterFirst);
  });

  test('the same domain with a different custom DKIM selector is not served from cache', async () => {
    const first = await request(app).get('/check?domain=cache-selector-test.com&selector=alpha');
    expect(first.body.cached).toBe(false);
    const callsAfterFirst = dns.resolveTxt.mock.calls.length;

    const second = await request(app).get('/check?domain=cache-selector-test.com&selector=beta');
    expect(second.body.cached).toBe(false);
    expect(dns.resolveTxt.mock.calls.length).toBeGreaterThan(callsAfterFirst);
  });

  test('the same domain and same custom selector is served from cache on a repeat request', async () => {
    const first = await request(app).get('/check?domain=cache-selector-repeat.com&selector=alpha');
    expect(first.body.cached).toBe(false);

    const second = await request(app).get('/check?domain=cache-selector-repeat.com&selector=alpha');
    expect(second.body.cached).toBe(true);
    expect(second.body.dkim).toEqual(first.body.dkim);
  });

  test('a "nonexistent" result is cached too, without re-running the NS lookup', async () => {
    dns.resolveNs.mockRejectedValue(notFoundError());

    const first = await request(app).get('/check?domain=cache-nonexistent-test.com');
    expect(first.body).toMatchObject({ type: 'nonexistent', cached: false });
    const nsCallsAfterFirst = dns.resolveNs.mock.calls.length;

    const second = await request(app).get('/check?domain=cache-nonexistent-test.com');
    expect(second.body).toMatchObject({ type: 'nonexistent', cached: true });
    expect(dns.resolveNs.mock.calls.length).toBe(nsCallsAfterFirst);
  });

  test('a custom selector that actually resolves still works correctly through the full route (existing custom-selector behavior)', async () => {
    dns.resolveTxt.mockImplementation(async (name) => {
      if (name === 'mycustom._domainkey.cache-custom-selector.com') {
        return [['v=DKIM1; k=rsa; p=abc']];
      }
      if (
        name.startsWith('_dmarc.') || name.includes('._domainkey.') ||
        name.startsWith('_mta-sts.') || name.startsWith('_smtp._tls.') || name.startsWith('default._bimi.')
      ) {
        throw notFoundError();
      }
      return [['v=spf1 -all']];
    });

    const res = await request(app).get('/check?domain=cache-custom-selector.com&selector=mycustom');
    expect(res.body.cached).toBe(false);
    expect(res.body.dkim.found).toBe(true);
    expect(res.body.dkim.selector).toBe('mycustom');
  });

  test('a cache hit still counts against the rate limit — caching cannot be used to bypass it', async () => {
    const domain = 'cache-rate-limit-test.com';
    let last;
    for (let i = 0; i < 31; i++) {
      last = await request(app).get(`/check?domain=${domain}`);
    }
    // 30 requests are allowed through (the first populates the cache, the
    // rest are cache hits); the 31st request in the same window is still
    // blocked by the limiter, proving cache hits are not exempt from it.
    expect(last.status).toBe(429);
    expect(last.body.error).toMatch(/too many requests/i);
  });
});
