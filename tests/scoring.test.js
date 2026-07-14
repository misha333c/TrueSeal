const { buildScoreAndAdvice } = require('../lib');

// Fixtures matching the exact shapes checkSpf/checkDkim/checkDmarc return,
// so buildScoreAndAdvice can be tested as pure logic with no DNS involved.

function spfFound(lookupCount) {
  return { found: true, status: 'found', record: 'v=spf1 include:_spf.example.com ~all', records: ['v=spf1 include:_spf.example.com ~all'], tags: {}, lookupCount };
}
function spfNotFound() {
  return { found: false, status: 'not_found', record: null, records: [], tags: {}, lookupCount: 0 };
}
function spfMultiple(count = 2) {
  return { found: false, status: 'multiple_records', record: null, records: new Array(count).fill('v=spf1 ~all'), tags: {}, lookupCount: 0 };
}

function dkimFound(keyStrength, selector = 'google') {
  return { found: true, status: 'found', selector, record: 'v=DKIM1; k=rsa; p=abc', tags: { k: 'rsa' }, keyStrength };
}
function dkimRevoked(selector = 'google') {
  return { found: false, status: 'revoked', selector, record: 'v=DKIM1; p=', tags: {} };
}
function dkimNotFound() {
  return { found: false, status: 'not_found', selector: null, record: null, tags: {} };
}

function dmarcFound({ policy, tags = {}, alignment = { spf: 'relaxed', dkim: 'relaxed' } }) {
  return { found: true, record: 'v=DMARC1; p=' + policy, policy, tags, alignment };
}
function dmarcNotFound() {
  return { found: false, record: null, policy: null, tags: {} };
}

// Every recommendation is now { issue, fix } — this searches both fields at
// once for tests that just need to confirm some topic is (or isn't)
// mentioned anywhere, without caring which field it landed in.
function mentions(recommendations, substring) {
  return recommendations.some(r => r.issue.includes(substring) || (r.fix || '').includes(substring));
}

describe('buildScoreAndAdvice — SPF', () => {
  test('found with low lookup count awards 30 points and no SPF-specific recommendation', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfFound(3), dkimNotFound(), dmarcNotFound());
    expect(score).toBeGreaterThanOrEqual(30);
    expect(mentions(recommendations, 'SPF') && mentions(recommendations, 'lookup')).toBe(false);
  });

  test('lookupCount >= 10 scores 0 for SPF and includes a permerror recommendation', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfFound(10), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(0);
    expect(recommendations.some(r => r.issue.includes('permerror'))).toBe(true);
  });

  test('lookupCount between 8 and 9 still scores 30 but warns it is close to the limit', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfFound(8), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(30);
    expect(recommendations.some(r => r.issue.includes('close to'))).toBe(true);
  });

  test('multiple_records scores 0 and flags the records as invalid', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfMultiple(3), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(0);
    expect(recommendations.some(r => r.issue.includes('3 SPF records') && r.issue.includes('invalid'))).toBe(true);
  });

  test('not found scores 0 and recommends adding SPF', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(0);
    const rec = recommendations.find(r => r.issue.includes('No SPF record was found'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('Add a TXT record');
  });
});

describe('buildScoreAndAdvice — DKIM', () => {
  test('found with keyStrength.bits >= 2048 awards 30 points and no key-strength recommendation', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimFound({ type: 'rsa', bits: 2048 }), dmarcNotFound());
    expect(score).toBe(30);
    expect(mentions(recommendations, 'bit RSA')).toBe(false);
  });

  test('found with RSA bits < 1024 awards only 15 points and warns about a weak key', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimFound({ type: 'rsa', bits: 512 }), dmarcNotFound());
    expect(score).toBe(15);
    const rec = recommendations.find(r => r.issue.includes('below the 1024-bit floor'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('Rotate to a 2048-bit key');
  });

  test('found with RSA bits between 1024 and 2047 awards full 30 points and suggests upgrading to 2048', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimFound({ type: 'rsa', bits: 1024 }), dmarcNotFound());
    expect(score).toBe(30);
    const rec = recommendations.find(r => r.issue.includes('1024-bit RSA'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('Worth upgrading to a 2048-bit key');
  });

  test('revoked scores 0 and includes a revoked-key recommendation', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimRevoked(), dmarcNotFound());
    expect(score).toBe(0);
    expect(recommendations.some(r => r.issue.includes('inactive'))).toBe(true);
  });

  test('not found scores 0 and recommends checking the provider dashboard', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(0);
    const rec = recommendations.find(r => r.issue.includes('No DKIM record was found for common selectors'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('dashboard');
  });
});

describe('buildScoreAndAdvice — DMARC', () => {
  test('policy reject awards 40 points', () => {
    const { score } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcFound({ policy: 'reject', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'strict', dkim: 'strict' } }));
    expect(score).toBe(40);
  });

  test('policy quarantine awards 30 points and recommends upgrading to reject', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcFound({ policy: 'quarantine', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'strict', dkim: 'strict' } }));
    expect(score).toBe(30);
    const rec = recommendations.find(r => r.issue.includes('p=quarantine'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('p=reject');
  });

  test('policy none awards 15 points and recommends moving off none', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcFound({ policy: 'none', tags: { rua: 'mailto:a@b.com' } }));
    expect(score).toBe(15);
    expect(recommendations.some(r => r.issue.includes('p=none'))).toBe(true);
  });

  test('found with no policy tag awards 10 points', () => {
    const { score } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcFound({ policy: null, tags: { rua: 'mailto:a@b.com' } }));
    expect(score).toBe(10);
  });

  test('not found scores 0 and recommends adding a DMARC record', () => {
    const { score, recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcNotFound());
    expect(score).toBe(0);
    const rec = recommendations.find(r => r.issue.includes('No DMARC record was found'));
    expect(rec).toBeDefined();
    expect(rec.fix).toContain('_dmarc.yourdomain.com');
  });

  test('reject policy with no rua tag recommends adding a reporting address', () => {
    const { recommendations } = buildScoreAndAdvice(spfNotFound(), dkimNotFound(), dmarcFound({ policy: 'reject', tags: {}, alignment: { spf: 'strict', dkim: 'strict' } }));
    expect(recommendations.some(r => r.issue.includes('no visibility into what mail is being blocked'))).toBe(true);
  });

  test('reject policy with both alignment modes relaxed names both SPF and DKIM', () => {
    const { recommendations } = buildScoreAndAdvice(
      spfNotFound(), dkimNotFound(),
      dmarcFound({ policy: 'reject', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'relaxed', dkim: 'relaxed' } })
    );
    const alignmentRec = recommendations.find(r => r.issue.includes('alignment') && r.issue.includes('relaxed'));
    expect(alignmentRec).toBeDefined();
    expect(alignmentRec.issue).toContain('SPF');
    expect(alignmentRec.issue).toContain('DKIM');
  });

  test('reject policy with both alignment modes strict has no alignment recommendation', () => {
    const { recommendations } = buildScoreAndAdvice(
      spfNotFound(), dkimNotFound(),
      dmarcFound({ policy: 'reject', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'strict', dkim: 'strict' } })
    );
    expect(mentions(recommendations, 'alignment')).toBe(false);
  });
});

describe('buildScoreAndAdvice — combined outcomes', () => {
  test('all three fully passing with no issues returns only the "all good" issue/fix pair', () => {
    const { score, recommendations } = buildScoreAndAdvice(
      spfFound(3),
      dkimFound({ type: 'rsa', bits: 2048 }),
      dmarcFound({ policy: 'reject', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'strict', dkim: 'strict' } })
    );
    expect(score).toBe(100);
    expect(recommendations).toEqual([{ issue: 'SPF, DKIM, and DMARC all look good!', fix: null }]);
  });

  test('mixed result: SPF pass + DKIM revoked + DMARC quarantine sums to the expected total', () => {
    const { score } = buildScoreAndAdvice(
      spfFound(3),
      dkimRevoked(),
      dmarcFound({ policy: 'quarantine', tags: { rua: 'mailto:a@b.com' }, alignment: { spf: 'strict', dkim: 'strict' } })
    );
    // 30 (SPF pass) + 0 (DKIM revoked) + 30 (DMARC quarantine) = 60
    expect(score).toBe(60);
  });
});
