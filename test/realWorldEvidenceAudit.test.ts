import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  computeEntropy,
  computeEntropyBlocks,
  detectFileSignature,
  computeHashes,
} from '../src/utils/forensics';
import { generateFileForensicsSimpleReport } from '../src/utils/fileForensicsAiAnalyst';
import { generatePcapSimpleReport } from '../src/utils/pcapAiAnalyst';
import { generateCaseSimpleReport } from '../src/utils/caseWorkspaceAiAnalyst';
import { generateDeterministicDomainAnalysis } from '../src/utils/domainAiAnalyst';
import { validateHostname, isPrivateOrReservedIP } from '../server/domainEngine';
import {
  FileAnalysisResult,
  PcapAnalysisResult,
  CaseRecord,
  DomainAnalysisReport,
} from '../src/types';

describe('Real-World Evidence Validation Audit — Core Mathematical & Cryptographic Engines', () => {
  it('verifies computeHashes against Node crypto reference implementation for standard vectors', async () => {
    const vectors = [
      '',
      'a',
      'abc',
      'The quick brown fox jumps over the lazy dog',
      'Veylith Forensics Deterministic Audit Payload 2026',
    ];

    for (const text of vectors) {
      const buf = Buffer.from(text, 'utf-8');
      const arrayBuf = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

      const expectedMd5 = crypto.createHash('md5').update(buf).digest('hex');
      const expectedSha1 = crypto.createHash('sha1').update(buf).digest('hex');
      const expectedSha256 = crypto.createHash('sha256').update(buf).digest('hex');

      const computed = await computeHashes(arrayBuf);

      assert.equal(computed.md5, expectedMd5, `MD5 mismatch for input: "${text}"`);
      assert.equal(computed.sha1, expectedSha1, `SHA-1 mismatch for input: "${text}"`);
      assert.equal(computed.sha256, expectedSha256, `SHA-256 mismatch for input: "${text}"`);
    }
  });

  it('verifies Shannon entropy boundary values mathematically', () => {
    // 1. Zero entropy: homogeneous buffer of identical bytes
    const zeros = new Uint8Array(1024).fill(0x00);
    assert.equal(computeEntropy(zeros), 0.0);

    const singleByte = new Uint8Array(512).fill(0x41); // 'A'
    assert.equal(computeEntropy(singleByte), 0.0);

    // 2. Maximum entropy: uniform distribution across all 256 byte values
    const uniform = new Uint8Array(256 * 10);
    for (let i = 0; i < uniform.length; i++) {
      uniform[i] = i % 256;
    }
    // log2(256) = 8.0000
    assert.equal(computeEntropy(uniform), 8.0);

    // 3. Empty buffer
    assert.equal(computeEntropy(new Uint8Array(0)), 0.0);
  });

  it('detects binary file signatures deterministically without fabrication', () => {
    // PE executable (MZ header with PE at e_lfanew)
    const pe = new Uint8Array(256);
    pe[0] = 0x4d; // 'M'
    pe[1] = 0x5a; // 'Z'
    pe[0x3c] = 0x80; // PE header offset
    pe[0x80] = 0x50; // 'P'
    pe[0x81] = 0x45; // 'E'
    const peSig = detectFileSignature(pe);
    assert.equal(peSig.detectedFormat, 'PE Executable (Windows Binary / DLL / Sys)');
    assert.ok(peSig.subType?.includes('PE32'));

    // ELF executable
    const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
    const elfSig = detectFileSignature(elf);
    assert.equal(elfSig.detectedFormat, 'ELF Binary (64-bit Linux Executable / Shared Object)');

    // PDF document
    const pdf = new Uint8Array(Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'utf-8'));
    const pdfSig = detectFileSignature(pdf);
    assert.equal(pdfSig.detectedFormat, 'PDF Document (Adobe Portable Document v1.7)');

    // 0-byte file
    const empty = new Uint8Array(0);
    const emptySig = detectFileSignature(empty);
    assert.equal(emptySig.detectedFormat, 'Empty File (0 bytes)');
  });
});

describe('Real-World Evidence Validation Audit — Domain Intelligence', () => {
  it('correctly maps all missing security headers from catalog descriptions', () => {
    const mockReport = {
      domain: 'baila.live',
      targetNormalized: 'baila.live',
      riskScore: 25,
      riskLevel: 'Medium',
      analyzedAt: new Date().toISOString(),
      resolvedIps: [
        { ip: '104.21.55.12', version: 4, isCdnOrCloud: true, provider: 'Cloudflare' },
      ],
      dnsRecords: { a: ['104.21.55.12'] },
      httpProbe: {
        statusCode: 200,
        statusText: 'OK',
        probeUrl: 'https://baila.live/',
        finalUrl: 'https://baila.live/',
        redirectChain: [{ url: 'https://baila.live/', statusCode: 308 }],
        redirectCount: 1,
        httpsEnforced: true,
        securityHeaders: {
          'Content Security Policy (CSP)': null,
          'X-Frame-Options (XFO)': null,
          'X-Content-Type-Options': null,
          'Referrer-Policy': null,
          'Permissions-Policy': null,
          'HTTP Strict Transport Security (HSTS)': 'max-age=31536000; includeSubDomains',
        },
        missingSecurityHeaders: [
          'Content Security Policy (CSP)',
          'X-Frame-Options (XFO)',
          'X-Content-Type-Options',
          'Referrer-Policy',
          'Permissions-Policy',
        ],
        headerObservations: [],
        serverBanner: 'cloudflare',
        contentLength: 450,
        provenance: {
          status: 'Retrieved',
          source: 'Safe HTTP Probe',
          timestamp: new Date().toISOString(),
          details: 'HTTP 200',
        },
      },
      tlsCertificate: {
        valid: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'Let\'s Encrypt',
        daysRemaining: 75,
      },
      rdap: {
        status: 'Forbidden',
        httpStatusCode: 403,
        sourceUrl: 'https://rdap.nic.live/domain/baila.live',
        errorDetails: 'Registry returned HTTP 403 Forbidden',
        provenance: {
          status: 'Forbidden',
          source: 'Authoritative TLD RDAP Server',
          timestamp: new Date().toISOString(),
        },
      },
      riskBreakdown: [],
      provenance: {},
    } as unknown as DomainAnalysisReport;

    const analysis = generateDeterministicDomainAnalysis(mockReport);

    // Verify missing headers detected as findings
    const findingIds = analysis.findings.map((f) => f.id);
    assert.ok(findingIds.includes('finding-header-csp'), 'CSP missing finding present');
    assert.ok(findingIds.includes('finding-header-xfo'), 'XFO missing finding present');
    assert.ok(findingIds.includes('finding-header-xcto'), 'XCTO missing finding present');
    assert.ok(findingIds.includes('finding-header-ref'), 'Referrer-Policy missing finding present');
    assert.ok(findingIds.includes('finding-header-perm'), 'Permissions-Policy missing finding present');

    // HSTS is present on this host, so it should NOT be in missing findings
    assert.ok(!findingIds.includes('finding-header-hsts'), 'HSTS is configured, should not be flagged missing');

    // RDAP 403 finding must be Informational
    const rdapFinding = analysis.findings.find((f) => f.id === 'finding-rdap-403');
    assert.ok(rdapFinding, 'RDAP 403 finding present');
    assert.equal(rdapFinding?.severity, 'Informational');

    // Verify 4 pillars exist on all findings
    for (const f of analysis.findings) {
      assert.ok(f.whatObserved.length > 5, `whatObserved populated for ${f.id}`);
      assert.ok(f.whatThisMeans.length > 5, `whatThisMeans populated for ${f.id}`);
      assert.ok(f.potentialRisk.length > 5, `potentialRisk populated for ${f.id}`);
      assert.ok(f.possibleAttackScenario.length > 5, `possibleAttackScenario populated for ${f.id}`);
      assert.ok(f.howToPreventIt.length > 5, `howToPreventIt populated for ${f.id}`);
    }
  });

  it('handles DNS resolution failure edge case with explicit finding and assessment', () => {
    const dnsFailReport = {
      domain: 'nonexistent-nxdomain-test-domain.invalid',
      targetNormalized: 'nonexistent-nxdomain-test-domain.invalid',
      riskScore: 20,
      riskLevel: 'Low',
      analyzedAt: new Date().toISOString(),
      resolvedIps: [],
      dnsRecords: { a: [], aaaa: [] },
      dnsFailed: true,
      httpProbe: undefined,
      tlsCertificate: undefined,
      rdap: undefined,
      riskBreakdown: [],
      provenance: {},
    } as unknown as DomainAnalysisReport;

    const analysis = generateDeterministicDomainAnalysis(dnsFailReport);

    assert.ok(analysis.overallAssessment.includes('DNS resolution failed'), 'Overall assessment explains DNS failure');
    const dnsFinding = analysis.findings.find((f) => f.id === 'finding-dns-resolution-failed');
    assert.ok(dnsFinding, 'DNS failure finding is generated');
    assert.equal(dnsFinding?.severity, 'Medium');
  });

  it('rejects SSRF, internal cloud metadata, and malformed hostnames', () => {
    // Loopback & Private IPs
    assert.equal(isPrivateOrReservedIP('127.0.0.1').isBlocked, true);
    assert.equal(isPrivateOrReservedIP('10.0.0.1').isBlocked, true);
    assert.equal(isPrivateOrReservedIP('192.168.1.1').isBlocked, true);
    assert.equal(isPrivateOrReservedIP('169.254.169.254').isBlocked, true); // AWS/GCP metadata
    assert.equal(isPrivateOrReservedIP('::1').isBlocked, true);

    // Hostname validation
    assert.equal(validateHostname('localhost').isValid, false);
    assert.equal(validateHostname('metadata.google.internal').isValid, false);
    assert.equal(validateHostname('domain..with..dots').isValid, false);
    assert.equal(validateHostname('169.254.169.254').isValid, false);

    // Legitimate public domain
    assert.equal(validateHostname('example.com').isValid, true);
    assert.equal(validateHostname('baila.live').isValid, true);
  });
});

describe('Real-World Evidence Validation Audit — File Forensics', () => {
  it('handles zero-byte empty file with explicit empty finding rather than false healthy claim', () => {
    const emptyResult = {
      fileName: 'zero_byte.dat',
      fileSize: 0,
      fileSizeFormatted: '0 Bytes',
      mimeType: 'application/octet-stream',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      md5: 'd41d8cd98f00b204e9800998ecf8427e',
      magicBytes: 'None (0 bytes)',
      detectedFormat: 'Empty File (0 bytes)',
      expectedExtensions: [],
      formatMismatch: false,
      entropy: 0.0,
      entropyEvaluation: {
        score: 0.0,
        status: 'Normal',
        explanation: 'Zero bytes contain no randomness.',
      },
      entropyBlocks: [],
      printableStrings: { total: 0, preview: [], extracted: [] },
      metadata: { byteLength: 0 },
      unavailableChecks: [],
      timestamp: new Date().toISOString(),
    } as unknown as FileAnalysisResult;

    const report = generateFileForensicsSimpleReport(emptyResult);

    assert.ok(report.overallAssessment.includes('EMPTY ARTIFACT (0 BYTES)'), 'Report highlights 0-byte state');
    const emptyFinding = report.securityConcerns.find((f) => f.id === 'fnd-file-empty');
    assert.ok(emptyFinding, 'Empty finding is generated');
    assert.equal(emptyFinding?.confidence, 'Confirmed');
    assert.equal(emptyFinding?.severity, 'Informational');
    assert.ok(report.prioritizedNextSteps[0].action.includes('Verify artifact acquisition integrity'));
  });

  it('detects format mismatch and flags Critical severity for executable masquerading as document', () => {
    const disguisedFile = {
      fileName: 'invoice_march_2026.pdf',
      fileSize: 1048576,
      fileSizeFormatted: '1.00 MB',
      mimeType: 'application/pdf',
      sha256: 'a'.repeat(64),
      sha1: 'b'.repeat(40),
      md5: 'c'.repeat(32),
      magicBytes: '4D 5A 90 00',
      detectedFormat: 'Windows Executable (PE/MZ)',
      expectedExtensions: ['.exe', '.dll'],
      formatMismatch: true,
      mismatchDescription: 'Declared extension .pdf conflicts with true header: Windows Executable (PE/MZ)',
      entropy: 6.8,
      entropyEvaluation: { score: 6.8, status: 'Normal', explanation: 'Normal entropy' },
      entropyBlocks: [],
      printableStrings: { total: 10, preview: [], extracted: [] },
      metadata: { byteLength: 1048576 },
      unavailableChecks: [],
      timestamp: new Date().toISOString(),
    } as unknown as FileAnalysisResult;

    const report = generateFileForensicsSimpleReport(disguisedFile);

    assert.ok(report.overallAssessment.includes('CRITICAL DECEPTION DETECTED'));
    const mismatchFinding = report.securityConcerns.find((f) => f.id === 'fnd-file-mismatch');
    assert.ok(mismatchFinding);
    assert.equal(mismatchFinding?.severity, 'Critical');
    assert.equal(mismatchFinding?.confidence, 'Confirmed');
  });
});

describe('Real-World Evidence Validation Audit — PCAP Lab', () => {
  it('handles empty packet capture (0 packets) with explicit empty capture finding', () => {
    const emptyPcap = {
      fileName: 'empty_trace.pcap',
      fileSize: 24,
      format: 'PCAP (Standard)',
      totalPackets: 0,
      totalBytes: 24,
      durationSeconds: 0,
      avgPacketRate: 0,
      protocols: {},
      topConversations: [],
      anomalies: [],
      interfaces: [],
      packets: [],
    } as unknown as PcapAnalysisResult;

    const report = generatePcapSimpleReport(emptyPcap);

    assert.ok(report.overallAssessment.includes('EMPTY CAPTURE (0 PACKETS)'));
    const emptyFinding = report.securityConcerns.find((f) => f.id === 'fnd-pcap-empty');
    assert.ok(emptyFinding);
    assert.equal(emptyFinding?.confidence, 'Confirmed');
    assert.equal(emptyFinding?.severity, 'Informational');
  });

  it('detects snaplen truncation and generates informational finding', () => {
    const truncatedPcap = {
      fileName: 'truncated_traffic.pcap',
      fileSize: 3200,
      format: 'PCAP (Standard)',
      totalPackets: 50,
      totalBytes: 3200,
      durationSeconds: 12.5,
      avgPacketRate: 4.0,
      protocols: { TCP: 50 },
      topConversations: [{ pair: '192.168.1.10 <-> 93.184.216.34', src: '192.168.1.10', dst: '93.184.216.34', proto: 'TCP', packets: 50, bytes: 3200 }],
      anomalies: [],
      truncatedPacketsCount: 15,
      packets: [],
    } as unknown as PcapAnalysisResult;

    const report = generatePcapSimpleReport(truncatedPcap);

    const truncFinding = report.securityConcerns.find((f) => f.id === 'fnd-pcap-truncated');
    assert.ok(truncFinding, 'Truncation finding generated');
    assert.ok(truncFinding?.whatObserved.includes('15 packet(s) were truncated'));
  });

  it('translates C2 beaconing anomaly into High severity finding with containment steps', () => {
    const c2Pcap = {
      fileName: 'infected_host_c2.pcap',
      fileSize: 15000,
      format: 'PCAP (Standard)',
      totalPackets: 200,
      totalBytes: 15000,
      durationSeconds: 120,
      avgPacketRate: 1.6,
      protocols: { TCP: 200 },
      topConversations: [{ pair: '10.0.1.55 <-> 198.51.100.4', src: '10.0.1.55', dst: '198.51.100.4', proto: 'TCP', packets: 200, bytes: 15000 }],
      anomalies: [
        {
          id: 'anom-c2-beacon',
          title: 'Suspicious Periodic Outbound C2 Beaconing',
          severity: 'High',
          description: 'Regular interval communication observed every 10.0 seconds to 198.51.100.4:4444',
          evidence: 'Interval delta variance = 0.02s over 12 consecutive flows.',
        },
      ],
      packets: [],
    } as unknown as PcapAnalysisResult;

    const report = generatePcapSimpleReport(c2Pcap);

    assert.ok(report.overallAssessment.includes('SIGNIFICANT NETWORK THREAT DETECTED'));
    const c2Finding = report.securityConcerns.find((f) => f.id.includes('c2'));
    assert.ok(c2Finding);
    assert.equal(c2Finding?.severity, 'High');
    assert.equal(c2Finding?.confidence, 'Confirmed');
    assert.ok(report.prioritizedNextSteps[0].action.includes('Isolate the communicating internal endpoint IP'));
  });
});

describe('Real-World Evidence Validation Audit — Case Management Workspace', () => {
  it('handles empty case gracefully with Intake Phase baseline without throwing', () => {
    const emptyCase = {
      id: 'VY-CASE-EMPTY',
      title: 'Triage Workspace Intake',
      status: 'Open',
      priority: 'Low',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      leadAnalyst: 'Forensic Investigator',
      tags: ['Triage'],
      scope: ['Perimeter Review'],
      evidence: [],
      findings: [],
      auditLog: [],
    } as unknown as CaseRecord;

    const report = generateCaseSimpleReport(emptyCase);

    assert.ok(report.overallAssessment.includes('CASE INITIALIZED'));
    const intakeFinding = report.securityConcerns.find((f) => f.id === 'fnd-case-empty');
    assert.ok(intakeFinding);
    assert.equal(intakeFinding?.severity, 'Informational');
    assert.equal(intakeFinding?.confidence, 'Confirmed');
  });

  it('prioritizes Critical and High findings for containment in executive briefing', () => {
    const activeCase = {
      id: 'VY-CASE-ACTIVE-THREAT',
      title: 'Active Ransomware Staging',
      status: 'Open',
      priority: 'Critical',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      leadAnalyst: 'Senior Incident Responder',
      tags: ['Incident', 'Ransomware'],
      scope: ['Domain Controllers', 'File Shares'],
      evidence: [
        {
          id: 'ev-01',
          name: 'payload.exe',
          type: 'file',
          hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          collectedAt: new Date().toISOString(),
          source: 'Host EDR',
        },
      ],
      findings: [
        {
          id: 'f-ransom-01',
          title: 'Encrypted File Shadow Copy Deletion Script',
          category: 'Malware & Binary',
          severity: 'Critical',
          confidence: 'Confirmed',
          status: 'Investigating',
          targetEntity: 'DC01.corp.internal',
          sourceTool: 'File Forensics',
          collectedAt: new Date().toISOString(),
          description: 'Script executed vssadmin delete shadows command.',
          observedResult: 'Volume shadow copies deleted from storage.',
          severityRationale: 'Shadow copy destruction prevents immediate file restoration.',
          riskImplications: 'Guarantees persistent extortion leverage for adversary.',
        },
      ],
      auditLog: [],
    } as unknown as CaseRecord;

    const report = generateCaseSimpleReport(activeCase);

    assert.ok(report.overallAssessment.includes('INCIDENT ALERT — HIGH-PRIORITY ACTIONS REQUIRED'));
    assert.equal(report.securityConcerns[0].severity, 'Critical');
    assert.ok(report.prioritizedNextSteps[0].action.includes('Execute isolation and firewall blocking'));
  });
});
