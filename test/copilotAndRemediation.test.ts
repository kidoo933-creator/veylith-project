import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectServerTechnology,
  buildHeaderRemediationGuide,
  generateDeterministicDomainAnalysis,
  convertDomainAnalysisToSimpleReport,
} from '../src/utils/domainAiAnalyst';
import { generateFileForensicsSimpleReport } from '../src/utils/fileForensicsAiAnalyst';
import { generatePcapSimpleReport } from '../src/utils/pcapAiAnalyst';
import { DomainAnalysisReport, FileAnalysisResult, PcapAnalysisResult } from '../src/types';

describe('Veylith AI Copilot & Actionable Developer Remediation Suite', () => {
  describe('Technology Detection Engine', () => {
    it('accurately identifies web server technology from server banners', () => {
      assert.equal(detectServerTechnology('nginx/1.24.0 (Ubuntu)'), 'nginx');
      assert.equal(detectServerTechnology('Apache/2.4.56 (Unix) OpenSSL/1.1.1t'), 'apache');
      assert.equal(detectServerTechnology('cloudflare'), 'cloudflare');
      assert.equal(detectServerTechnology('Express'), 'express');
      assert.equal(detectServerTechnology('Node.js / Express 4.19'), 'express');
      assert.equal(detectServerTechnology('Caddy/v2.7.6'), 'caddy');
      assert.equal(detectServerTechnology(undefined), 'generic');
      assert.equal(detectServerTechnology(''), 'generic');
    });
  });

  describe('Technology-Specific Remediation Snippets', () => {
    it('generates Nginx directives and curl commands for CSP', () => {
      const guide = buildHeaderRemediationGuide('csp', 'example.com', 'nginx/1.22.1');
      assert.equal(guide.detectedTechnology, 'nginx');
      assert.ok(guide.configSnippet.includes('add_header Content-Security-Policy'));
      assert.ok(guide.configSnippet.includes("default-src 'self'"));
      assert.ok(guide.configLocation.includes('nginx'));
      assert.equal(guide.verificationCommand, 'curl -I https://example.com | grep -i "content-security-policy"');
      assert.ok(guide.documentationUrl?.includes('Content-Security-Policy'));
      assert.ok(guide.thirdPartyHostedNote?.includes('Cloudflare'));
      assert.ok(Array.isArray(guide.alternativeConfigs));
    });

    it('generates Apache directives and curl commands for HSTS', () => {
      const guide = buildHeaderRemediationGuide('hsts', 'secure.org', 'Apache/2.4.52');
      assert.equal(guide.detectedTechnology, 'apache');
      assert.ok(guide.configSnippet.includes('Header always set Strict-Transport-Security'));
      assert.ok(guide.configSnippet.includes('max-age=31536000'));
      assert.ok(guide.configLocation.includes('apache2'));
      assert.equal(guide.verificationCommand, 'curl -I https://secure.org | grep -i "strict-transport-security"');
    });

    it('generates Express middleware for X-Frame-Options', () => {
      const guide = buildHeaderRemediationGuide('xfo', 'api.test', 'Express');
      assert.equal(guide.detectedTechnology, 'express');
      assert.ok(guide.configSnippet.includes('X-Frame-Options'));
      assert.ok(guide.configSnippet.includes('SAMEORIGIN'));
      assert.equal(guide.verificationCommand, 'curl -I https://api.test | grep -i "x-frame-options"');
    });

    it('generates X-Content-Type-Options nosniff directives', () => {
      const guide = buildHeaderRemediationGuide('xcto', 'static.app', 'nginx');
      assert.ok(guide.configSnippet.includes('X-Content-Type-Options "nosniff"'));
      assert.equal(guide.verificationCommand, 'curl -I https://static.app | grep -i "x-content-type-options"');
    });
  });

  describe('End-to-End Domain Remediation Integration', () => {
    it('attaches remediation guides to all missing security headers in domain report', () => {
      const mockDomainReport = {
        domain: 'vulnerable-site.test',
        targetNormalized: 'vulnerable-site.test',
        engineVersion: '2.5.0',
        analysisTimestamp: new Date().toISOString(),
        resolvedIps: [
          {
            ip: '93.184.216.34',
            version: 'IPv4',
            reverseDns: 'test.host',
            isPrivateOrReserved: false,
            isCdnOrCloud: false,
            provenance: {
              source: 'Authoritative DNS Query',
              retrievedAt: new Date().toISOString(),
              status: 'Retrieved',
            },
          },
        ],
        dnsRecords: {
          a: ['93.184.216.34'],
          aaaa: [],
          mx: [],
          ns: ['ns1.example.com'],
          txt: [],
          cname: [],
          soa: 'ns1.example.com admin.example.com 1',
        },
        httpProbe: {
          statusCode: 200,
          statusText: 'OK',
          probeUrl: 'https://vulnerable-site.test',
          finalUrl: 'https://vulnerable-site.test/',
          redirectChain: [],
          redirectCount: 0,
          httpsEnforced: true,
          serverBanner: 'nginx/1.20.1',
          securityHeaders: {
            'content-security-policy': null,
            'x-frame-options': null,
            'x-content-type-options': null,
            'strict-transport-security': null,
            'referrer-policy': null,
            'permissions-policy': null,
          },
          missingSecurityHeaders: [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
          ],
          headerObservations: [],
          provenance: {
            source: 'HTTP Client Probe',
            retrievedAt: new Date().toISOString(),
            status: 'Retrieved',
          },
        },
        uncompletedChecks: [],
        riskScore: 35,
        riskLevel: 'Low',
        riskFactors: ['Missing security headers'],
        riskFactorDetails: [],
        scoringLimitations: [],
        dataCompleteness: 90,
        ssrfGuards: { passed: true, checkedAddresses: ['93.184.216.34'] },
      } as unknown as DomainAnalysisReport;

      const analysis = generateDeterministicDomainAnalysis(mockDomainReport);

      const cspFinding = analysis.findings.find((f) => f.id === 'finding-header-csp');
      assert.ok(cspFinding, 'CSP finding must exist');
      assert.ok(cspFinding.remediationGuide, 'CSP finding must include remediationGuide');
      assert.equal(cspFinding.remediationGuide?.detectedTechnology, 'nginx');
      assert.ok(cspFinding.remediationGuide?.configSnippet.includes('add_header Content-Security-Policy'));
      assert.ok(cspFinding.remediationGuide?.verificationCommand.includes('curl -I'));

      const xfoFinding = analysis.findings.find((f) => f.id === 'finding-header-xfo');
      assert.ok(xfoFinding?.remediationGuide);
      assert.ok(xfoFinding.remediationGuide?.configSnippet.includes('SAMEORIGIN'));

      const hstsFinding = analysis.findings.find((f) => f.id === 'finding-header-hsts');
      assert.ok(hstsFinding?.remediationGuide);
      assert.ok(hstsFinding.remediationGuide?.configSnippet.includes('max-age=31536000'));

      // Check conversion to Simple Report
      const simpleReport = convertDomainAnalysisToSimpleReport(mockDomainReport);
      const simpleCsp = simpleReport.securityConcerns.find((f) => f.id === 'finding-header-csp');
      assert.ok(simpleCsp?.remediationGuide, 'Simple Report must preserve remediationGuide');
      assert.ok(simpleCsp.remediationGuide?.configSnippet);
    });
  });

  describe('File Forensics Actionable Remediation', () => {
    it('attaches YARA rule and verification command for disguised file extensions', () => {
      const mockFileResult = {
        fileName: 'Invoice_2025.pdf',
        fileSize: 12048,
        fileSizeFormatted: '11.8 KB',
        mimeType: 'application/pdf',
        sha256: 'a'.repeat(64),
        sha1: 'b'.repeat(40),
        md5: 'c'.repeat(32),
        magicBytes: '4D 5A (MZ)',
        detectedFormat: 'Windows Executable (PE/MZ)',
        formatMismatch: true,
        mismatchDescription: 'Extension is .pdf but binary begins with MZ',
        entropy: 7.42,
        entropyEvaluation: { status: 'High', explanation: 'High entropy indicates packing' },
        printableStrings: { total: 10, extracted: [] },
        unavailableChecks: [],
        timestamp: new Date().toISOString(),
      } as unknown as FileAnalysisResult;

      const report = generateFileForensicsSimpleReport(mockFileResult);
      const mismatch = report.securityConcerns.find((f) => f.id === 'fnd-file-mismatch');
      assert.ok(mismatch);
      assert.ok(mismatch.remediationGuide);
      assert.ok(mismatch.remediationGuide.configSnippet.includes('rule Masqueraded_Executable_Binary'));
      assert.ok(mismatch.remediationGuide.verificationCommand.includes('file --mime-type'));
    });
  });

  describe('PCAP Lab Actionable Network Remediation', () => {
    it('attaches firewall iptables and tshark verification commands for C2 beaconing', () => {
      const mockPcapResult = {
        fileName: 'capture_traffic.pcap',
        format: 'PCAP (Standard)',
        totalPackets: 500,
        totalBytes: 524288,
        durationSeconds: 120,
        avgPacketRate: 4.16,
        protocols: { TCP: 400, DNS: 100 },
        topConversations: [],
        anomalies: [
          {
            title: 'Periodic Outbound Beaconing Detected',
            severity: 'High',
            description: 'Regular intervals to external IP',
            evidence: 'Periodic connection every 10.0s to 198.51.100.55',
          },
        ],
        unavailableChecks: [],
        dnsQueries: [],
        httpFlows: [],
        ipFlows: [],
        conversations: [],
        packets: [],
        entropyDistribution: [],
        overallEntropy: 5.2,
        packetSizeMetrics: { min: 64, max: 1514, mean: 512, median: 512, stdDev: 50, p95: 1400 },
        threatIndicators: [],
      } as unknown as PcapAnalysisResult;

      const report = generatePcapSimpleReport(mockPcapResult);
      const beaconFinding = report.securityConcerns.find((f) => f.title.includes('Beaconing'));
      assert.ok(beaconFinding);
      assert.ok(beaconFinding.remediationGuide);
      assert.ok(beaconFinding.remediationGuide.configSnippet.includes('iptables'));
      assert.ok(beaconFinding.remediationGuide.verificationCommand.includes('tcpdump'));
    });
  });
});
