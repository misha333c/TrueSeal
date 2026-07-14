const crypto = require('crypto');
const { parseRecordTags, isValidDomainFormat, getDkimKeyStrength } = require('../lib');

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

  test('empty string input with no key type tag returns a fully null result', () => {
    expect(getDkimKeyStrength('', undefined)).toEqual({ type: null, bits: null });
  });
});
