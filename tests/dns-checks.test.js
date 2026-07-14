const crypto = require('crypto');

jest.mock('dns', () => ({
  promises: {
    resolveTxt: jest.fn(),
    resolveNs: jest.fn()
  }
}));

const dns = require('dns').promises;
const lib = require('../lib');

function realRsaKeyBase64(bits = 2048) {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

function notFoundError() {
  return Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' });
}

beforeEach(() => {
  dns.resolveTxt.mockReset();
  dns.resolveNs.mockReset();
});

describe('checkSpf', () => {
  test('a single v=spf1 record is found with the correct lookup count', async () => {
    dns.resolveTxt.mockImplementation(async (name) => {
      if (name === 'lookup-test.com') return [['v=spf1 include:_spf.lookup-test.com ~all']];
      if (name === '_spf.lookup-test.com') return [['v=spf1 -all']];
      throw notFoundError();
    });

    const result = await lib.checkSpf('lookup-test.com');
    expect(result.found).toBe(true);
    expect(result.lookupCount).toBe(1);
  });

  test('two v=spf1 records are reported as multiple_records', async () => {
    dns.resolveTxt.mockResolvedValue([['v=spf1 ~all'], ['v=spf1 -all']]);

    const result = await lib.checkSpf('multi.com');
    expect(result.status).toBe('multiple_records');
    expect(result.found).toBe(false);
  });

  test('no matching TXT record returns found: false', async () => {
    dns.resolveTxt.mockResolvedValue([['some unrelated record']]);

    const result = await lib.checkSpf('none.com');
    expect(result.found).toBe(false);
  });

  test('a DNS error returns found: false without throwing', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());

    await expect(lib.checkSpf('missing.com')).resolves.toEqual(
      expect.objectContaining({ found: false })
    );
  });
});

describe('checkDkim', () => {
  test('a common selector with a real public key is found with the correct keyStrength', async () => {
    const base64 = realRsaKeyBase64(2048);
    dns.resolveTxt.mockImplementation(async (name) => {
      if (name === 'google._domainkey.example.com') {
        return [[`v=DKIM1; k=rsa; p=${base64}`]];
      }
      throw notFoundError();
    });

    const result = await lib.checkDkim('example.com');
    expect(result.found).toBe(true);
    expect(result.selector).toBe('google');
    expect(result.keyStrength).toEqual({ type: 'rsa', bits: 2048 });
  });

  test('an empty p= tag is reported as revoked', async () => {
    dns.resolveTxt.mockImplementation(async (name) => {
      if (name === 'google._domainkey.revoked.com') {
        return [['v=DKIM1; p=']];
      }
      throw notFoundError();
    });

    const result = await lib.checkDkim('revoked.com');
    expect(result.found).toBe(false);
    expect(result.status).toBe('revoked');
    expect(result.selector).toBe('google');
  });

  test('when every selector fails, status is not_found', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());

    const result = await lib.checkDkim('nothing.com');
    expect(result.found).toBe(false);
    expect(result.status).toBe('not_found');
  });

  test('a custom selector that resolves is tried first and short-circuits common-selector probing', async () => {
    const base64 = realRsaKeyBase64(2048);
    dns.resolveTxt.mockImplementation(async (name) => {
      if (name === 'custom1._domainkey.custom.com') {
        return [[`v=DKIM1; k=rsa; p=${base64}`]];
      }
      throw notFoundError();
    });

    const result = await lib.checkDkim('custom.com', 'custom1');
    expect(result.found).toBe(true);
    expect(result.selector).toBe('custom1');
    expect(dns.resolveTxt).toHaveBeenCalledTimes(1);
  });
});

describe('checkDmarc', () => {
  test('a valid record with adkim=s;aspf=r resolves the correct policy and alignment', async () => {
    dns.resolveTxt.mockResolvedValue([['v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:a@b.com']]);

    const result = await lib.checkDmarc('aligned.com');
    expect(result.found).toBe(true);
    expect(result.policy).toBe('reject');
    expect(result.alignment).toEqual({ dkim: 'strict', spf: 'relaxed' });
  });

  test('no matching record returns found: false', async () => {
    dns.resolveTxt.mockResolvedValue([['unrelated']]);

    const result = await lib.checkDmarc('none.com');
    expect(result.found).toBe(false);
  });

  test('a DNS error returns found: false without throwing', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());

    await expect(lib.checkDmarc('missing.com')).resolves.toEqual(
      expect.objectContaining({ found: false })
    );
  });
});

describe('checkMtaSts / checkTlsRpt / checkBimi', () => {
  test('checkMtaSts finds a matching v=STSv1 record', async () => {
    dns.resolveTxt.mockResolvedValue([['v=STSv1; id=123']]);

    const result = await lib.checkMtaSts('sts.com');
    expect(result).toEqual({ found: true, record: 'v=STSv1; id=123' });
  });

  test('checkMtaSts reports found: false when there is no match', async () => {
    dns.resolveTxt.mockResolvedValue([['unrelated']]);
    expect(await lib.checkMtaSts('none.com')).toEqual({ found: false, record: null });
  });

  test('checkMtaSts reports found: false on a DNS error', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());
    expect(await lib.checkMtaSts('missing.com')).toEqual({ found: false, record: null });
  });

  test('checkTlsRpt finds a matching v=TLSRPTv1 record', async () => {
    dns.resolveTxt.mockResolvedValue([['v=TLSRPTv1; rua=mailto:a@b.com']]);

    const result = await lib.checkTlsRpt('tlsrpt.com');
    expect(result).toEqual({ found: true, record: 'v=TLSRPTv1; rua=mailto:a@b.com' });
  });

  test('checkTlsRpt reports found: false when there is no match', async () => {
    dns.resolveTxt.mockResolvedValue([['unrelated']]);
    expect(await lib.checkTlsRpt('none.com')).toEqual({ found: false, record: null });
  });

  test('checkTlsRpt reports found: false on a DNS error', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());
    expect(await lib.checkTlsRpt('missing.com')).toEqual({ found: false, record: null });
  });

  test('checkBimi finds a matching v=BIMI1 record', async () => {
    dns.resolveTxt.mockResolvedValue([['v=BIMI1; l=https://example.com/logo.svg']]);

    const result = await lib.checkBimi('bimi.com');
    expect(result).toEqual({ found: true, record: 'v=BIMI1; l=https://example.com/logo.svg' });
  });

  test('checkBimi reports found: false when there is no match', async () => {
    dns.resolveTxt.mockResolvedValue([['unrelated']]);
    expect(await lib.checkBimi('none.com')).toEqual({ found: false, record: null });
  });

  test('checkBimi reports found: false on a DNS error', async () => {
    dns.resolveTxt.mockRejectedValue(notFoundError());
    expect(await lib.checkBimi('missing.com')).toEqual({ found: false, record: null });
  });
});

describe('checkDnssec', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('a DNSKEY answer (type 48) reports found: true', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ Status: 0, Answer: [{ type: 48, data: 'abc' }] })
    });

    expect(await lib.checkDnssec('signed.com')).toEqual({ found: true });
  });

  test('a successful response with no Answer entries reports found: false', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ Status: 0, Answer: [] })
    });

    expect(await lib.checkDnssec('unsigned.com')).toEqual({ found: false });
  });

  test('a failed/rejected fetch reports found: false without throwing', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network error'));

    await expect(lib.checkDnssec('offline.com')).resolves.toEqual({ found: false });
  });
});
