import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateFileForensicsSimpleReport } from '../src/utils/fileForensicsAiAnalyst';
import { generatePcapSimpleReport } from '../src/utils/pcapAiAnalyst';
import { generateCaseSimpleReport } from '../src/utils/caseWorkspaceAiAnalyst';
import { convertDomainAnalysisToSimpleReport } from '../src/utils/domainAiAnalyst';
import { FileAnalysisResult, PcapAnalysisResult, CaseRecord, DomainAnalysisReport } from '../src/types';

describe('Veylith Two-Tier Investigation Experience: Simple Results vs Deep Analysis', () => {
  describe('File Forensics Human-Readable Analyst Report', () => {
    it('generates a 4-pillar human explanation for disguised executable payloads', () => {
      const mockResult: FileAnalysisResult = {
        fileName: 'Urgent_Invoice.pdf',
        fileSize: 45056,
        fileSizeFormatted: '44.0 KB',
        mimeType: 'application/pdf',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        md5: 'd41d8cd98f00b204e9800998ecf8427e',
        magicBytes: '4d 5a (MZ)',
        detectedFormat: 'Windows PE Executable (.exe / .dll)',
        formatMismatch: true,
        mismatchDescription: 'File claims to be .pdf but starts with MZ header',
        entropy: 7.34,
        entropyEvaluation: {
          status: 'High',
          explanation: 'Elevated entropy indicates packed machine code',
        },
        printableStrings: {
          total: 120,
          extracted: [
            { value: 'VirtualAlloc', category: 'api' },
            { value: 'CreateRemoteThread', category: 'api' },
            { value: 'WriteProcessMemory', category: 'api' },
            { value: 'https://c2-stager.cc/beacon.bin', category: 'url' },
          ],
        },
        unavailableChecks: [],
        timestamp: new Date().toISOString(),
      };

      const simpleReport = generateFileForensicsSimpleReport(mockResult);

      assert.equal(simpleReport.target, 'Urgent_Invoice.pdf');
      assert.equal(simpleReport.targetType, 'file');
      assert.ok(simpleReport.overallAssessment.includes('CRITICAL DECEPTION DETECTED'));
      assert.ok(simpleReport.overallAssessment.includes('masquerading'));

      // Check format mismatch finding
      const mismatchFinding = simpleReport.securityConcerns.find((f) => f.id === 'fnd-file-mismatch');
      assert.ok(mismatchFinding);
      assert.equal(mismatchFinding.severity, 'Critical');
      assert.ok(mismatchFinding.whatObserved.includes('MZ'));
      assert.ok(mismatchFinding.whatThisMeans.includes('pretending to be something it is not'));
      assert.ok(mismatchFinding.potentialRisk);
      assert.ok(mismatchFinding.possibleAttackScenario.includes('double-clicks'));
      assert.ok(mismatchFinding.howToPreventIt.includes('magic bytes'));

      // Check process injection finding
      const injectionFinding = simpleReport.securityConcerns.find((f) => f.id === 'fnd-file-process-injection');
      assert.ok(injectionFinding);
      assert.ok(injectionFinding.whatThisMeans.includes('inject code'));
      assert.ok(injectionFinding.howToPreventIt.includes('Endpoint Detection and Response'));

      // Check prioritized next steps
      assert.ok(simpleReport.prioritizedNextSteps.length >= 3);
      const immediateStep = simpleReport.prioritizedNextSteps.find((s) => s.priority === 'Immediate');
      assert.ok(immediateStep);
      assert.ok(immediateStep.action.includes('Quarantine'));

      // Check limitations disclosure
      assert.ok(simpleReport.limitations.some((l) => l.includes('Static binary analysis only')));
    });

    it('generates a healthy baseline report for clean documents', () => {
      const cleanDoc: FileAnalysisResult = {
        fileName: 'annual_report.pdf',
        fileSize: 102400,
        fileSizeFormatted: '100.0 KB',
        mimeType: 'application/pdf',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        sha1: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
        md5: '5d41402abc4b2a76b9719d911017c592',
        magicBytes: '25 50 44 46 (%PDF)',
        detectedFormat: 'Adobe PDF Document',
        formatMismatch: false,
        entropy: 5.12,
        entropyEvaluation: {
          status: 'Normal',
          explanation: 'Standard PDF distribution',
        },
        printableStrings: {
          total: 50,
          extracted: [],
        },
        unavailableChecks: [],
        timestamp: new Date().toISOString(),
      };

      const simpleReport = generateFileForensicsSimpleReport(cleanDoc);

      assert.ok(simpleReport.overallAssessment.includes('HEALTHY STATIC PROFILE'));
      assert.equal(simpleReport.securityConcerns[0].severity, 'Informational');
      assert.ok(simpleReport.whatIsWorkingWell.length > 0);
    });
  });

  describe('PCAP Lab Human-Readable Analyst Report', () => {
    it('translates C2 beaconing and DNS tunneling into understandable human terms', () => {
      const mockPcap: PcapAnalysisResult = {
        fileName: 'suspect_c2_capture.pcap',
        fileSize: 154000,
        format: 'PCAP (Standard)',
        totalPackets: 1200,
        totalBytes: 154000,
        durationSeconds: 120.5,
        avgPacketRate: 9.96,
        protocols: { TCP: 1100, UDP: 80, DNS: 80, HTTP: 20 },
        topConversations: [
          {
            pair: '192.168.1.45:49152 <-> 203.0.113.88:4444',
            src: '192.168.1.45',
            dst: '203.0.113.88',
            packets: 950,
            bytes: 120000,
            proto: 'TCP',
          },
        ],
        anomalies: [
          {
            severity: 'High',
            title: 'Periodic C2 Beaconing Detected',
            description: 'Strict 10.0s interval beaconing observed between host and external destination',
            evidence: 'Interval: 10.0s ± 0.1s • Port: 4444',
          },
          {
            severity: 'High',
            title: 'DNS Tunneling & Data Exfiltration Indicator',
            description: 'Subdomain entropy > 4.5 with repetitive TXT lookups',
            evidence: 'Long high-entropy subdomains querying external nameserver',
          },
        ],
        packets: [],
      };

      const simpleReport = generatePcapSimpleReport(mockPcap);

      assert.equal(simpleReport.target, 'suspect_c2_capture.pcap');
      assert.equal(simpleReport.targetType, 'pcap');
      assert.ok(simpleReport.overallAssessment.includes('SIGNIFICANT NETWORK THREAT DETECTED'));

      // Check C2 finding explanation
      const c2Finding = simpleReport.securityConcerns.find((f) => f.title.includes('Command & Control'));
      assert.ok(c2Finding);
      assert.equal(c2Finding.severity, 'High');
      assert.ok(c2Finding.whatThisMeans.includes('walkie-talkie'));
      assert.ok(c2Finding.howToPreventIt.includes('isolate'));

      // Check DNS finding explanation
      const dnsFinding = simpleReport.securityConcerns.find((f) => f.title.includes('DNS'));
      assert.ok(dnsFinding);
      assert.ok(dnsFinding.whatThisMeans.includes('smuggled out'));

      // Check prioritized next steps
      const immediateActions = simpleReport.prioritizedNextSteps.filter((s) => s.priority === 'Immediate');
      assert.ok(immediateActions.length >= 1);
      assert.ok(immediateActions.some((a) => a.action.includes('Isolate')));

      // Check encryption limitations disclosure
      assert.ok(simpleReport.limitations.some((l) => l.includes('Encrypted payload content')));
    });

    it('generates healthy network baseline for normal captures', () => {
      const cleanPcap: PcapAnalysisResult = {
        fileName: 'clean_office_traffic.pcap',
        fileSize: 40000,
        format: 'PCAP (Standard)',
        totalPackets: 350,
        totalBytes: 40000,
        durationSeconds: 30.0,
        avgPacketRate: 11.6,
        protocols: { TCP: 300, UDP: 50, DNS: 50 },
        topConversations: [],
        anomalies: [],
        packets: [],
      };

      const simpleReport = generatePcapSimpleReport(cleanPcap);

      assert.ok(simpleReport.overallAssessment.includes('HEALTHY NETWORK BASELINE'));
      assert.equal(simpleReport.securityConcerns[0].severity, 'Informational');
    });
  });

  describe('Case Workspace Executive Incident Briefing', () => {
    it('synthesizes case findings and evidence into prioritized response roadmap', () => {
      const mockCase: CaseRecord = {
        id: '#VY-2025-0047',
        title: 'Phishing Campaign & Disguised Document Staging',
        description: 'Multi-stage external phishing investigation involving disguised PDF payloads and malicious domains.',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'Alex Carter',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        scope: ['baila.live', '192.0.2.45', 'invoice.exe'],
        tags: ['phishing', 'threat_intel'],
        evidence: [
          {
            id: 'ev-1',
            name: 'baila.live',
            type: 'domain',
            value: 'baila.live',
            confidence: 'Confirmed',
            source: 'Veylith Domain Recon',
            timestamp: new Date().toISOString(),
          },
          {
            id: 'ev-2',
            name: 'payload.exe',
            type: 'file',
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            confidence: 'Confirmed',
            source: 'Veylith File Forensics',
            timestamp: new Date().toISOString(),
          },
        ],
        findings: [
          {
            id: 'FND-0047-01',
            caseId: '#VY-2025-0047',
            title: 'Disguised Executable Masquerading as PDF',
            category: 'Binary & Static Forensics',
            targetEntity: 'invoice.pdf',
            observedResult: 'MZ header on file declared as PDF',
            description: 'File claims to be a PDF invoice but contains Windows x64 machine code.',
            severity: 'High',
            severityRationale: 'High deception factor targeting corporate accounts payable.',
            confidence: 'Confirmed',
            status: 'Unresolved',
            sourceTool: 'File Forensics',
            collectedAt: new Date().toISOString(),
            evidenceIds: ['ev-2'],
          },
        ],
        timeline: [],
        notes: [],
        auditLog: [],
      };

      const simpleReport = generateCaseSimpleReport(mockCase);

      assert.ok(simpleReport.target.includes('#VY-2025-0047'));
      assert.equal(simpleReport.targetType, 'case');
      assert.ok(simpleReport.overallAssessment.includes('INCIDENT ALERT — HIGH-PRIORITY ACTIONS REQUIRED'));
      assert.equal(simpleReport.securityConcerns.length, 1);
      assert.equal(simpleReport.securityConcerns[0].severity, 'High');
      assert.equal(simpleReport.securityConcerns[0].title, 'Disguised Executable Masquerading as PDF');

      // Check prioritized next steps
      const immediate = simpleReport.prioritizedNextSteps.find((s) => s.priority === 'Immediate');
      assert.ok(immediate);
      assert.ok(immediate.action.includes('isolation'));
    });
  });

  describe('Domain Intelligence Simple Report Conversion', () => {
    it('converts domain analysis into universal Simple Results schema with prioritized next steps', () => {
      const mockDomainReport: any = {
        domain: 'baila.live',
        targetNormalized: 'baila.live',
        analysisTimestamp: new Date().toISOString(),
        engineVersion: '3.8.0',
        dataCompleteness: 92,
        resolvedIps: [
          {
            ip: '172.67.182.203',
            version: 4,
            isCdnOrCloud: true,
            provider: 'Cloudflare',
            provenance: {
              source: 'System DNS Resolver',
              method: 'dns.resolve4',
              timestamp: new Date().toISOString(),
              status: 'Retrieved',
            },
          },
        ],
        dnsRecords: {
          a: ['172.67.182.203'],
          mx: [],
          ns: ['ns1.cloudflare.com'],
          txt: [],
          soa: null,
          caa: [],
        },
        tlsCertificate: {
          valid: true,
          protocol: 'TLS 1.3',
          issuer: 'Google Trust Services LLC',
          subject: 'baila.live',
          validFrom: '2025-01-01',
          validTo: '2025-04-01',
          daysRemaining: 45,
          cipher: 'TLS_AES_256_GCM_SHA384',
          sans: ['baila.live'],
          provenance: {
            source: 'TLS Handshake Probe',
            method: 'tls.connect',
            timestamp: new Date().toISOString(),
            status: 'Retrieved',
          },
        },
        httpProbe: {
          statusCode: 200,
          statusText: 'OK',
          finalUrl: 'https://baila.live/',
          redirectChain: [{ url: 'http://baila.live/', statusCode: 308 }],
          securityHeaders: {
            'strict-transport-security': 'max-age=31536000',
          },
          missingSecurityHeaders: [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy',
          ],
          httpsEnforced: true,
          provenance: {
            source: 'HTTP Client Probe',
            method: 'fetch',
            timestamp: new Date().toISOString(),
            status: 'Retrieved',
          },
        },
        rdap: {
          status: 'Forbidden',
          httpStatusCode: 403,
          sourceUrl: 'https://rdap.nic.live/domain/baila.live',
          rawResponseTruncated: 'HTTP 403 Forbidden',
          provenance: {
            source: 'Authoritative TLD RDAP Registry',
            method: 'rdap.fetch',
            timestamp: new Date().toISOString(),
            status: 'Blocked',
          },
        },
        riskScore: 28,
        riskLevel: 'Low',
        scoringRationale: ['Standard baseline security parameters evaluated.'],
      };

      const simpleReport = convertDomainAnalysisToSimpleReport(mockDomainReport as any);

      assert.equal(simpleReport.target, 'baila.live');
      assert.equal(simpleReport.targetType, 'domain');
      assert.ok(simpleReport.overallAssessment.includes('baila.live'));
      assert.ok(simpleReport.overallAssessment.includes('TLS'));
      assert.ok(simpleReport.prioritizedNextSteps.length >= 3);
      assert.equal(simpleReport.prioritizedNextSteps[0].priority, 'Immediate');
      assert.ok(simpleReport.securityConcerns.length > 0);
      assert.ok(simpleReport.limitations.length > 0);
    });
  });
});
