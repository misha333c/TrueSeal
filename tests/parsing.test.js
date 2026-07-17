const crypto = require('crypto');
const { parseRecordTags, isValidDomainFormat, getDkimKeyStrength, toAsciiDomain } = require('../lib');

describe('parseRecordTags', () => {
  test('parses a semicolon-delimited DMARC-style record', () => {
    const tags = parseRecordTags('v=DMARC1; p=reject; rua=mailto:a@b.com');
    expect(tags).toEqual({ v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.com' });
  });

  test('parses a space-delimited record, skipping mechanisms without a value', () => {
    const tags = parseRecordTags('v=spf1 include:_spf.example.com ip4=1.2.3.4 ~all');
    expect(tags).toEqual({ v: 'spf1', ip4: '1.2.3.4' });
  });

  test('empty string returns {}', () => {
    expect(parseRecordTags('')).toEqual({});
  });

  test('malformed tokens without "=" are skipped', () => {
    expect(parseRecordTags('foo; bar=baz; qux')).toEqual({ bar: 'baz' });
  });

  test('null returns {}', () => {
    expect(parseRecordTags(null)).toEqual({});
  });

  test('undefined returns {}', () => {
    expect(parseRecordTags(undefined)).toEqual({});
  });
});

describe('isValidDomainFormat', () => {
  test.each([
    ['example.com'],
    ['sub.example.co.uk']
  ])('%s is valid', (domain) => {
    expect(isValidDomainFormat(domain)).toBe(true);
  });

  test('empty string is invalid', () => {
    expect(isValidDomainFormat('')).toBe(false);
  });

  test('a string with no dot is invalid', () => {
    expect(isValidDomainFormat('no-dot')).toBe(false);
  });

  test('a domain with spaces is invalid', () => {
    expect(isValidDomainFormat('example .com')).toBe(false);
  });

  test('a domain with a label starting with a hyphen is invalid', () => {
    expect(isValidDomainFormat('-bad.com')).toBe(false);
  });

  test('a domain with a label ending with a hyphen is invalid', () => {
    expect(isValidDomainFormat('bad-.com')).toBe(false);
  });

  test('a domain over 253 characters is invalid', () => {
    const longDomain = Array(5).fill('a'.repeat(60)).join('.') + '.com';
    expect(longDomain.length).toBeGreaterThan(253);
    expect(isValidDomainFormat(longDomain)).toBe(false);
  });

  // Boundary check: exactly 253 chars (the RFC 1035 presentation-format
  // limit) must pass, and 254 must fail — using labels that are themselves
  // valid (<=63 chars each) so only the total-length boundary is under
  // test, not an incidental label-length violation.
  describe('253/254-character boundary', () => {
    const makeDomain = (lastLabelLen) =>
      ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(lastLabelLen)].join('.');

    test('exactly 253 characters is valid', () => {
      const domain = makeDomain(61);
      expect(domain.length).toBe(253);
      expect(isValidDomainFormat(domain)).toBe(true);
    });

    test('exactly 254 characters is invalid', () => {
      const domain = makeDomain(62);
      expect(domain.length).toBe(254);
      expect(isValidDomainFormat(domain)).toBe(false);
    });
  });

  test('a raw Unicode IDN domain is rejected by format validation directly (must go through toAsciiDomain first)', () => {
    expect(isValidDomainFormat('münchen.de')).toBe(false);
  });

  test('an already-punycode IDN domain is valid', () => {
    expect(isValidDomainFormat('xn--mnchen-3ya.de')).toBe(true);
  });
});

describe('toAsciiDomain', () => {
  test('converts a raw Unicode IDN domain to its punycode form', () => {
    expect(toAsciiDomain('münchen.de')).toBe('xn--mnchen-3ya.de');
  });

  test('a domain already in punycode form passes through unchanged', () => {
    expect(toAsciiDomain('xn--mnchen-3ya.de')).toBe('xn--mnchen-3ya.de');
  });

  test('a plain ASCII domain passes through unchanged', () => {
    expect(toAsciiDomain('example.com')).toBe('example.com');
  });

  test('a non-Latin-script IDN domain converts correctly', () => {
    expect(toAsciiDomain('日本語.jp')).toBe('xn--wgv71a119e.jp');
  });

  test('the converted form of an IDN domain passes isValidDomainFormat', () => {
    expect(isValidDomainFormat(toAsciiDomain('münchen.de'))).toBe(true);
  });

  test('invalid input (e.g. containing spaces) converts to an empty string', () => {
    expect(toAsciiDomain('not a domain')).toBe('');
  });
});

describe('getDkimKeyStrength', () => {
  test('a real RSA-2048 SPKI DER key returns { type: "rsa", bits: 2048 }', () => {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const der = publicKey.export({ type: 'spki', format: 'der' });
    const base64 = der.toString('base64');

    expect(getDkimKeyStrength(base64, 'rsa')).toEqual({ type: 'rsa', bits: 2048 });
  });

  test('an ed25519 keyTypeTag returns { type: "ed25519", bits: 256 } regardless of the key value', () => {
    expect(getDkimKeyStrength('not-even-a-real-key-value', 'ed25519')).toEqual({ type: 'ed25519', bits: 256 });
  });

  test('garbage/invalid base64 returns bits: null instead of throwing', () => {
    expect(() => getDkimKeyStrength('!!!not-valid-base64-key-data!!!', 'rsa')).not.toThrow();
    const result = getDkimKeyStrength('!!!not-valid-base64-key-data!!!', 'rsa');
    expect(result.bits).toBeNull();
  });

  test('garbage/invalid base64 is flagged with parseError: true, distinct from a merely-uncommon key type', () => {
    const result = getDkimKeyStrength('!!!not-valid-base64-key-data!!!', 'rsa');
    expect(result.parseError).toBe(true);
  });

  test('empty string input with no key type tag returns a fully null result flagged as a parse error', () => {
    expect(getDkimKeyStrength('', undefined)).toEqual({ type: null, bits: null, parseError: true });
  });
});
