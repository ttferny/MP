/**
 * Tests for aiChecker.js
 * Verifies that JSON parsing errors are handled gracefully
 */

const { checkEmailWithAI } = require('../services/aiChecker');

describe('aiChecker.js', () => {
  const mockParsedEmail = {
    from: 'test@example.com',
    fromEmail: 'test@example.com',
    fromDomain: 'example.com',
    envelopeDomain: 'example.com',
    senderIP: '192.0.2.1',
    subject: 'Test Email',
    date: '2024-01-01T00:00:00Z',
    replyTo: null,
    dkimSignature: { s: 'default', d: 'example.com' }
  };

  const mockSPFResult = {
    result: 'pass',
    reason: 'Matched mechanism',
    domain: 'example.com',
    ip: '192.0.2.1'
  };

  const mockDKIMResult = {
    result: 'pass',
    reason: 'DKIM signature verified',
    domain: 'example.com'
  };

  const mockDMARCResult = {
    verdict: 'deliver',
    policy: 'reject',
    reason: 'DMARC passed',
    spfAligned: true,
    dkimAligned: true
  };

  test('should return fallback result when GEMINI_API_KEY is not set', async () => {
    const originalKey = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;

    const result = await checkEmailWithAI(
      mockParsedEmail,
      mockSPFResult,
      mockDKIMResult,
      mockDMARCResult,
      'Test content'
    );

    process.env.GEMINI_API_KEY = originalKey;

    expect(result).toHaveProperty('success', false);
    expect(result).toHaveProperty('classification', 'unknown');
    expect(result).toHaveProperty('technicalSummary');
    expect(result.technicalSummary).toContain('GEMINI_API_KEY');
  });

  test('should handle non-JSON responses gracefully', async () => {
    // This test verifies that the fix handles the case where
    // the API returns HTML or other non-JSON content
    const originalFetch = global.fetch;
    
    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockRejectedValueOnce(
        new SyntaxError('Unexpected token \'<\', "<!DOCTYPE html>" is not valid JSON')
      ),
      text: jest.fn().mockResolvedValueOnce('<!DOCTYPE html><html><body>Error</body></html>')
    });

    process.env.GEMINI_API_KEY = 'test-key';

    const result = await checkEmailWithAI(
      mockParsedEmail,
      mockSPFResult,
      mockDKIMResult,
      mockDMARCResult,
      'Test content'
    );

    global.fetch = originalFetch;

    // Should return fallback result instead of throwing
    expect(result).toHaveProperty('success', false);
    expect(result).toHaveProperty('classification', 'unknown');
    expect(result).toHaveProperty('recommendation', 'review');
  });
});
