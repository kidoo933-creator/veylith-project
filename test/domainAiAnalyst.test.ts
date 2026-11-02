import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DomainAnalysisReport } from '../src/types';
import {
  generateDeterministicDomainAnalysis,
  buildDomainAnalystPrompt,
  validateAiDomainAnalysis,
  AI_ANALYST_DISCLAIMER,
} from '../src/utils/domainAiAnalyst';

describe('Veylith Domain Intelligence — AI Security Analyst Engine', () => {
  // Test fixture representing the baila.live scan evidence from user specification
  const bailaLiveReport: DomainAnalysisReport = {
    domain: 'baila.live',
    targetNormalized: 'baila.live',
    engineVersion: '2.4.0',
    analysisTimestamp: '2026-11-01T12:00:00.000Z',
    resolvedIps: [
      { ip: '104.21.55.2', version: 4, isCdnOrCloud: true },
      { ip: '172.67.188.45', version: 4, isCdnOrCloud: true },
    ],
    dnsRecords: {
      a: ['104.21.55.2', '172.67.188.45'],
      aaaa: [],
      mx: [{ exchange: 'mail.baila.live', priority: 10 }],
      txt: [['v=spf1 include:_spf.mx.cloudflare.net ~all']],
      ns: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
    },
    tlsCertificate: {
      valid: true,
      hostnameMatched: true,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      issuer: 'GTS CA 1P5',
      validFrom: '2026-09-01T00:00:00.000Z',
      validTo: '2026-12-01T00:00:00.000Z',
      daysRemaining: 30,
      provenance: {
        source: 'TLS Handshake Probe',
        timestamp: '2026-11-01T12:00:00.000Z',
        status: 'Retrieved',
      },
    },
    httpProbe: {
      statusCode: 200,
      statusText: 'OK',
      probeUrl: 'https://baila.live',
      finalUrl: 'https://baila.live/',
      redirectChain: [
        { url: 'http://baila.live', statusCode: 308 },
        { url: 'https://baila.live/', statusCode: 200 },
      ],
      redirectCount: 1,
      httpsEnforced: true,
      securityHeaders: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': null,
        'x-frame-options': null,
        'x-content-type-options': null,
        'referrer-policy': null,
        'permissions-policy': null,
      },
      missingSecurityHeaders: [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy',
      ],
      headerObservations: [],
      serverBanner: 'cloudflare',
      provenance: {
        source: 'HTTP Client Probe',
        timestamp: '2026-11-01T12:00:00.000Z',
        status: 'Retrieved',
      },
    },
    rdap: {
      status: 'Forbidden',
      httpStatusCode: 403,
      sourceUrl: 'https://rdap.identitydigital.services/rdap/domain/baila.live',
      errorDetails: 'HTTP 403 Forbidden received from TLD registry server',
      provenance: {
        source: 'IANA / TLD RDAP Resolver',
        timestamp: '2026-11-01T12:00:00.000Z',
        status: 'Blocked',
      },
    },
    uncompletedChecks: [],
    riskScore: 28,
    riskLevel: 'Low',
    riskFactors: ['Missing CSP Header', 'Missing X-Frame-Options Header', 'Missing MIME Sniffing Protection'],
    riskFactorDetails: [],
    scoringLimitations: ['Passive inspection only'],
    dataCompleteness: 92,
    ssrfGuards: {
      passed: true,
      checkedAddresses: ['104.21.55.2', '172.67.188.45'],
    },
    provenance: {
      dns: { source: 'Recursive Resolver', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
      http: { source: 'HTTP Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
      tls: { source: 'TLS Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
      rdap: { source: 'RDAP Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Blocked' },
    },
  };

  describe('1. Baila.live Scenario Evaluation', () => {
    it('generates a complete AI security analysis with all mandatory sections', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      assert.equal(analysis.domain, 'baila.live');
      assert.ok(analysis.overallAssessment.length > 50, 'Overall assessment should be detailed');
      assert.ok(Array.isArray(analysis.keyFactsObserved) && analysis.keyFactsObserved.length >= 4);
      assert.ok(Array.isArray(analysis.findings) && analysis.findings.length >= 5);
      assert.ok(Array.isArray(analysis.positiveHighlights) && analysis.positiveHighlights.length >= 2);
      assert.ok(Array.isArray(analysis.limitations) && analysis.limitations.length >= 2);
      assert.equal(analysis.disclaimer, AI_ANALYST_DISCLAIMER);
    });

    it('generates the Content-Security-Policy (CSP) finding with exact 4-pillar structure', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);
      const cspFinding = analysis.findings.find((f) => f.id === 'finding-header-csp');

      assert.ok(cspFinding, 'CSP finding must exist');
      assert.equal(cspFinding.title, 'Content-Security-Policy (CSP) is missing');
      assert.equal(cspFinding.severity, 'Low');
      assert.equal(cspFinding.confidence, 'Confirmed');
      assert.match(cspFinding.whatThisMeans, /visitor’s browser|restrictions/i);
      assert.match(cspFinding.potentialRisk, /injection|Cross-Site Scripting|scripts/i);
      assert.match(cspFinding.possibleAttackScenario, /hypothetical|unsanitized/i);
      assert.match(cspFinding.howToPreventIt, /Content-Security-Policy|default-src/i);
      assert.match(cspFinding.severityExplanation, /defense-in-depth|not proof/i);
    });

    it('generates the X-Frame-Options clickjacking protection finding', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);
      const xfoFinding = analysis.findings.find((f) => f.id === 'finding-header-xfo');

      assert.ok(xfoFinding, 'X-Frame-Options finding must exist');
      assert.equal(xfoFinding.severity, 'Low');
      assert.match(xfoFinding.whatThisMeans, /frame|iframe/i);
      assert.match(xfoFinding.potentialRisk, /clickjacking/i);
      assert.match(xfoFinding.howToPreventIt, /SAMEORIGIN|DENY|frame-ancestors/i);
    });

    it('generates X-Content-Type-Options, Referrer-Policy, and Permissions-Policy findings', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      const xcto = analysis.findings.find((f) => f.id === 'finding-header-xcto');
      assert.ok(xcto);
      assert.equal(xcto.severity, 'Low');
      assert.match(xcto.whatThisMeans, /sniff|content type/i);

      const ref = analysis.findings.find((f) => f.id === 'finding-header-ref');
      assert.ok(ref);
      assert.equal(ref.severity, 'Informational');

      const perm = analysis.findings.find((f) => f.id === 'finding-header-perm');
      assert.ok(perm);
      assert.equal(perm.severity, 'Informational');
    });

    it('records modern HTTPS and TLS 1.3 as positive highlight and verified observation', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      const tlsHighlight = analysis.positiveHighlights.some((h) => h.includes('TLS'));
      assert.ok(tlsHighlight, 'Must highlight active TLS');

      const tlsFinding = analysis.findings.find((f) => f.id === 'finding-transport-tls');
      assert.ok(tlsFinding);
      assert.equal(tlsFinding.severity, 'Informational');
      assert.match(tlsFinding.whatObserved, /TLSv1.3/);
    });

    it('records observed HSTS as positive highlight', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      const hstsHighlight = analysis.positiveHighlights.some((h) => h.includes('Strict-Transport-Security'));
      assert.ok(hstsHighlight, 'HSTS must be in positive highlights when present in report');
    });

    it('classifies RDAP HTTP 403 as Informational administrative registry response, NOT a vulnerability', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);
      const rdapFinding = analysis.findings.find((f) => f.id === 'finding-rdap-403');

      assert.ok(rdapFinding, 'RDAP 403 finding must exist');
      assert.equal(rdapFinding.severity, 'Informational', 'RDAP 403 must be Informational severity');
      assert.match(rdapFinding.severityExplanation, /NOT a security flaw|administrative/i);
      assert.match(rdapFinding.possibleAttackScenario, /None/i);
      assert.match(rdapFinding.howToPreventIt, /No corrective action/i);
    });

    it('classifies HTTP 308 redirect followed by HTTP 200 as Informational canonical routing', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);
      const redirectFinding = analysis.findings.find((f) => f.id === 'finding-redirect-routing');

      assert.ok(redirectFinding, 'Redirect finding must exist');
      assert.equal(redirectFinding.severity, 'Informational');
      assert.match(redirectFinding.severityExplanation, /standard best practice|canonical/i);
      assert.match(redirectFinding.whatObserved, /308/);
      assert.match(redirectFinding.whatObserved, /200/);
    });
  });

  describe('2. Anti-Hallucination & Severity Invariance Rules', () => {
    it('never assigns High or Critical severity to missing security headers', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);
      const headerFindings = analysis.findings.filter((f) => f.category === 'Header Hardening');

      for (const finding of headerFindings) {
        assert.notEqual(
          finding.severity,
          'High',
          `Finding ${finding.id} must not be High severity`
        );
        assert.notEqual(
          finding.severity,
          'Critical',
          `Finding ${finding.id} must not be Critical severity`
        );
        assert.ok(
          finding.severity === 'Low' || finding.severity === 'Informational',
          `Finding ${finding.id} must be Low or Informational`
        );
      }
    });

    it('does not claim the domain is hacked, compromised, or vulnerable without proof', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      assert.doesNotMatch(analysis.overallAssessment, /\b(is hacked|is compromised|is infected)\b/i);
      for (const f of analysis.findings) {
        assert.doesNotMatch(f.whatThisMeans, /\b(site is hacked|site is compromised)\b/i);
      }
    });

    it('distinguishes observed facts from potential consequences across every finding', () => {
      const analysis = generateDeterministicDomainAnalysis(bailaLiveReport);

      for (const f of analysis.findings) {
        assert.ok(f.whatObserved.length > 5, `${f.id} must state what was observed`);
        assert.ok(f.whatThisMeans.length > 5, `${f.id} must explain what this means`);
        assert.ok(f.potentialRisk.length > 5, `${f.id} must explain potential risk`);
        assert.ok(f.possibleAttackScenario.length > 5, `${f.id} must provide possible attack scenario`);
        assert.ok(f.howToPreventIt.length > 5, `${f.id} must provide mitigation`);
        assert.ok(f.severityExplanation.length > 5, `${f.id} must justify severity`);
      }
    });
  });

  describe('3. Dynamic Execution on Different Domain Configurations', () => {
    it('analyzes an exemplary fully-hardened domain with 0 missing headers', () => {
      const hardenedReport: DomainAnalysisReport = {
        domain: 'secure-bank.example',
        targetNormalized: 'secure-bank.example',
        engineVersion: '2.4.0',
        analysisTimestamp: '2026-11-01T12:00:00.000Z',
        resolvedIps: [{ ip: '198.51.100.10', version: 4 }],
        dnsRecords: { a: ['198.51.100.10'], aaaa: [], mx: [], txt: [], ns: ['ns1.example.com'] },
        tlsCertificate: {
          valid: true,
          hostnameMatched: true,
          protocol: 'TLSv1.3',
          daysRemaining: 120,
          provenance: { source: 'TLS Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
        },
        httpProbe: {
          statusCode: 200,
          statusText: 'OK',
          probeUrl: 'https://secure-bank.example',
          finalUrl: 'https://secure-bank.example',
          redirectChain: [],
          redirectCount: 0,
          httpsEnforced: true,
          securityHeaders: {
            'content-security-policy': "default-src 'self'",
            'x-frame-options': 'DENY',
            'x-content-type-options': 'nosniff',
            'strict-transport-security': 'max-age=31536000',
            'referrer-policy': 'no-referrer',
            'permissions-policy': 'geolocation=()',
          },
          missingSecurityHeaders: [],
          headerObservations: [],
          provenance: { source: 'HTTP Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
        },
        rdap: {
          status: 'Retrieved',
          registrar: 'Exemplary Registrar LLC',
          registrationDate: '2020-01-01T00:00:00Z',
          provenance: { source: 'RDAP', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
        },
        uncompletedChecks: [],
        riskScore: 5,
        riskLevel: 'Low',
        riskFactors: [],
        riskFactorDetails: [],
        scoringLimitations: [],
        dataCompleteness: 100,
        ssrfGuards: { passed: true, checkedAddresses: ['198.51.100.10'] },
        provenance: {
          dns: { source: 'DNS', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
          http: { source: 'HTTP', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
          tls: { source: 'TLS', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
          rdap: { source: 'RDAP', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
        },
      };

      const analysis = generateDeterministicDomainAnalysis(hardenedReport);
      const missingHeaderFindings = analysis.findings.filter((f) => f.title.includes('missing'));

      assert.equal(missingHeaderFindings.length, 0, 'No missing header findings should exist for hardened domain');
      assert.match(analysis.overallAssessment, /exemplary security posture|all key browser hardening headers/i);
    });

    it('handles a domain with TLS certificate errors gracefully with actionable advice', () => {
      const tlsErrorReport: DomainAnalysisReport = {
        ...bailaLiveReport,
        domain: 'expired-tls.example',
        tlsCertificate: {
          valid: false,
          hostnameMatched: false,
          error: 'CERT_HAS_EXPIRED',
          provenance: { source: 'TLS Handshake Probe', timestamp: '2026-11-01T12:00:00Z', status: 'Retrieved' },
        },
      };

      const analysis = generateDeterministicDomainAnalysis(tlsErrorReport);
      const tlsErrorFinding = analysis.findings.find((f) => f.id === 'finding-transport-tls-error');

      assert.ok(tlsErrorFinding, 'Must generate TLS handshake error finding');
      assert.equal(tlsErrorFinding.severity, 'Medium');
      assert.match(tlsErrorFinding.whatObserved, /CERT_HAS_EXPIRED/);
      assert.match(tlsErrorFinding.howToPreventIt, /renewal status/i);
    });
  });

  describe('4. AI Response Validation & Fallback Guardrails', () => {
    it('downgrades exaggerated severity if an AI model erroneously rates a missing header as High or Critical', () => {
      const mockAiOutput = {
        domain: 'baila.live',
        overallAssessment: 'Test assessment',
        keyFactsObserved: ['Fact 1'],
        findings: [
          {
            id: 'ai-f-1',
            title: 'Content-Security-Policy (CSP) is missing',
            category: 'Header Hardening',
            severity: 'High', // Erroneously high!
            severityExplanation: 'Should be Low',
            confidence: 'Confirmed',
            whatObserved: 'Missing CSP',
            whatThisMeans: 'No browser script rules',
            potentialRisk: 'Script injection risk',
            possibleAttackScenario: 'Hypothetical injection',
            howToPreventIt: 'Add CSP',
          },
          {
            id: 'ai-f-2',
            title: 'RDAP returned 403',
            category: 'Registration & RDAP',
            severity: 'Critical', // Erroneously critical!
            severityExplanation: 'Should be Informational',
            confidence: 'Confirmed',
            whatObserved: '403 Forbidden',
            whatThisMeans: 'Registry blocked lookup',
            potentialRisk: 'None',
            possibleAttackScenario: 'None',
            howToPreventIt: 'None',
          },
        ],
        positiveHighlights: ['TLS active'],
        limitations: ['Passive only'],
      };

      const validated = validateAiDomainAnalysis(mockAiOutput, bailaLiveReport);
      assert.ok(validated);

      const csp = validated.findings.find((f) => f.id === 'ai-f-1');
      assert.ok(csp);
      assert.equal(csp.severity, 'Low', 'Missing header severity must be auto-downgraded to Low');

      const rdap = validated.findings.find((f) => f.id === 'ai-f-2');
      assert.ok(rdap);
      assert.equal(rdap.severity, 'Informational', 'RDAP error must be auto-downgraded to Informational');
    });

    it('returns null on malformed AI responses allowing seamless fallback to deterministic engine', () => {
      assert.equal(validateAiDomainAnalysis(null, bailaLiveReport), null);
      assert.equal(validateAiDomainAnalysis('plain text error', bailaLiveReport), null);
      assert.equal(validateAiDomainAnalysis({ randomKey: true }, bailaLiveReport), null);
    });

    it('builds an authoritative prompt for Gemini embedding strict anti-hallucination constraints', () => {
      const { systemPrompt, userPrompt } = buildDomainAnalystPrompt(bailaLiveReport);

      assert.match(systemPrompt, /AI MUST NOT INVENT VULNERABILITIES/);
      assert.match(systemPrompt, /Missing security headers.*must NEVER be classified as High or Critical/);
      assert.match(systemPrompt, /RDAP errors.*are administrative registry responses/);
      assert.match(userPrompt, /baila\.live/);
      assert.match(userPrompt, /Content-Security-Policy/);
      assert.match(userPrompt, /Forbidden/);
    });
  });
});
