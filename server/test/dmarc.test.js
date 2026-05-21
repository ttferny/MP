const { evaluateDMARC } = require('../services/dmarc');

describe('dmarc.js — evaluateDMARC()', () => {
  test('[POSITIVE] includes policy and verdict when DMARC policy exists and alignment passes', () => {
    const spfResult = { status: 'pass', domain: 'company.com' };
    const dkimResult = { status: 'pass', domain: 'company.com' };
    const parsed = { fromDomain: 'company.com', policy: 'reject', pct: 100, aspf: 'r', adkim: 'r' };

    const result = evaluateDMARC(spfResult, dkimResult, parsed);

    expect(result.policy).toBe('reject');
    expect(result.verdict).toBe('deliver');
    expect(result.status).toBe('pass');
    expect(result.action).toBe('deliver');
  });

  test('[NEGATIVE] returns policy null and verdict none when no DMARC record exists', () => {
    const spfResult = { status: 'pass', domain: 'company.com' };
    const dkimResult = { status: 'pass', domain: 'company.com' };
    const parsed = { fromDomain: 'company.com' };

    const result = evaluateDMARC(spfResult, dkimResult, parsed);

    expect(result.policy).toBeNull();
    expect(result.verdict).toBe('none');
    expect(result.status).toBe('error');
    expect(result.action).toBe('none');
  });
});
