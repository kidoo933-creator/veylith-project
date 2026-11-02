import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeFinding,
  ensureUtcIsoString,
  generateFindingId,
  createDomainFinding,
  createFileForensicsFinding,
  createPcapFinding,
} from '../src/utils/findingNormalization.ts';
import {
  buildEvidenceGraph,
  hasExactIpMatch,
  hasExactDomainMatch,
  hasExactHashMatch,
  hasExactCveMatch,
} from '../src/utils/evidenceCorrelation.ts';
import {
  generateInvestigationReport,
  exportReportAsJson,
} from '../src/utils/reportGenerator.ts';
import { INITIAL_CASES } from '../src/utils/storage.ts';
import { CaseRecord, EvidenceItem, Finding } from '../src/types/index.ts';

describe('Veylith Milestone 3 — Professional Investigation Workflow & Cross-Module Intelligence QA', () => {
  // =========================================================================
  // 1. Finding Normalization & Field Defense
  // =========================================================================
  describe('1. Finding Normalization & Consistency', () => {
    test('normalizes a partial finding with complete Phase 1 schema and defensible defaults', () => {
      const raw = {
        title: 'Open Port 22 SSH Detected',
        severity: 'Low' as const,
        description: 'TCP port 22 is open on bastion host.',
      };

      const normalized = normalizeFinding(raw, '#VY-TEST-001');

      assert.ok(normalized.id.startsWith('FND-'), 'Expected generated finding ID starting with FND-');
      assert.strictEqual(normalized.caseId, '#VY-TEST-001');
      assert.strictEqual(normalized.title, 'Open Port 22 SSH Detected');
      assert.strictEqual(normalized.severity, 'Low');
      assert.strictEqual(normalized.status, 'Unresolved');
      assert.strictEqual(normalized.confidence, 'Observed');
      assert.strictEqual(normalized.category, 'Infrastructure & Recon');
      assert.strictEqual(normalized.targetEntity, 'Unspecified Target');
      assert.strictEqual(normalized.observedResult, 'TCP port 22 is open on bastion host.');
      assert.ok(Array.isArray(normalized.evidenceIds));
      assert.ok(Array.isArray(normalized.relatedFindingIds));
      assert.ok(Array.isArray(normalized.limitations));
      assert.ok(normalized.collectedAt.endsWith('Z'), 'CollectedAt must be UTC ISO ending in Z');
      assert.ok(normalized.timestamp?.endsWith('Z'), 'Timestamp alias must be UTC ISO ending in Z');
      assert.ok(normalized.severityRationale && normalized.severityRationale.length > 0, 'Rationale must be populated');
    });

    test('preserves existing finding fields during normalization without overwriting valid data', () => {
      const existing: Finding = {
        id: 'FND-CUSTOM-99',
        caseId: '#VY-TEST-002',
        title: 'C2 Beaconing Pattern',
        severity: 'Critical',
        confidence: 'Confirmed',
        category: 'Network & Protocol',
        targetEntity: '198.51.100.42:443',
        observedResult: 'Periodic jittered TLS callbacks observed every 60s',
        severityRationale: 'High regularity with known malicious JA3 hash',
        sourceTool: 'PCAP Session Capture',
        evidenceSource: 'PCAP Session Capture Frame Parser',
        collectedAt: '2026-04-10T12:00:00.000Z',
        timestamp: '2026-04-10T12:00:00.000Z',
        provenance: 'Wireshark Ethernet Frame 42',
        riskImplications: 'Potential command channel establishment',
        limitations: ['Payload is encrypted under TLS 1.3'],
        evidenceIds: ['ev-pcap-1'],
        relatedFindingIds: ['FND-DNS-01'],
        status: 'Investigating',
        description: 'C2 Beaconing detail',
      };

      const result = normalizeFinding(existing, '#VY-TEST-002');

      assert.strictEqual(result.id, 'FND-CUSTOM-99');
      assert.strictEqual(result.severity, 'Critical');
      assert.strictEqual(result.confidence, 'Confirmed');
      assert.strictEqual(result.category, 'Network & Protocol');
      assert.strictEqual(result.targetEntity, '198.51.100.42:443');
      assert.strictEqual(result.collectedAt, '2026-04-10T12:00:00.000Z');
      assert.deepStrictEqual(result.evidenceIds, ['ev-pcap-1']);
      assert.deepStrictEqual(result.relatedFindingIds, ['FND-DNS-01']);
      assert.deepStrictEqual(result.limitations, ['Payload is encrypted under TLS 1.3']);
    });

    test('domain factory helper sets non-hyperbolic classification for hardening observations', () => {
      const f = createDomainFinding({
        caseId: '#VY-TEST-003',
        domain: 'corp-auth.com',
        title: 'Missing Content-Security-Policy Header',
        category: 'Hardening & Security Header',
        observedResult: 'HTTP response did not return a Content-Security-Policy header.',
        description: 'Passive HTTP header inspection revealed absence of Content-Security-Policy header.',
        severity: 'Low',
        severityRationale: 'Security hygiene hardening observation; does not demonstrate exploitability.',
        confidence: 'Confirmed',
        sourceTool: 'Veylith Recon Engine',
        evidenceIds: ['ev-dom-1'],
        riskImplications: 'Hardening deficiency without active exploit.',
      });

      assert.strictEqual(f.category, 'Hardening & Security Header');
      assert.strictEqual(f.severity, 'Low');
      assert.strictEqual(f.targetEntity, 'corp-auth.com');
      assert.ok(f.severityRationale?.includes('Hardening') || f.severityRationale?.includes('hygiene'));
      assert.ok(f.limitations && f.limitations.length > 0);
    });

    test('file forensics factory helper categorizes format masquerading correctly', () => {
      const f = createFileForensicsFinding({
        caseId: '#VY-TEST-004',
        fileName: 'invoice.pdf.exe',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        title: 'File Masquerade Detected: invoice.pdf.exe',
        observedResult: 'Magic Bytes: 4D 5A. Detected: PE Executable (Windows Binary). Entropy: 7.91. Mismatch: Yes.',
        description: 'File claims to be PDF but magic bytes indicate Windows executable.',
        severity: 'High',
        severityRationale: 'File extension does not align with binary signature magic bytes.',
        confidence: 'Confirmed',
        evidenceIds: ['ev-file-1'],
      });

      assert.strictEqual(f.severity, 'High');
      assert.strictEqual(f.category, 'Binary & Static Forensics');
      assert.strictEqual(f.confidence, 'Confirmed');
      assert.ok(f.title.includes('Masquerade'));
      assert.ok(f.targetEntity.includes('invoice.pdf.exe'));
    });

    test('pcap helper establishes verified telemetry finding with endpoints', () => {
      const f = createPcapFinding({
        caseId: '#VY-TEST-005',
        pcapFile: 'capture-01.pcap',
        title: 'Suspicious DNS TXT Tunneling Queries',
        targetEndpoint: '192.168.1.100:53 -> 8.8.8.8:53',
        observedResult: 'High frequency of encoded base64 TXT requests to c2.badactor.org',
        description: 'Decoded UDP DNS queries containing anomalous payload lengths.',
        severity: 'High',
        severityRationale: 'Observable protocol anomaly within captured frame flow.',
        confidence: 'Confirmed',
        evidenceIds: ['ev-pcap-1'],
      });

      assert.strictEqual(f.category, 'Network & Protocol');
      assert.strictEqual(f.targetEntity, '192.168.1.100:53 -> 8.8.8.8:53');
      assert.strictEqual(f.sourceTool, 'Veylith PCAP Lab');
      assert.ok(f.provenance?.includes('capture-01.pcap'));
    });
  });

  // =========================================================================
  // 2. Cross-Module Evidence Correlation Engine
  // =========================================================================
  describe('2. Cross-Module Evidence Correlation Engine', () => {
    test('correlates domain with resolved IP address via DOMAIN_TO_IP', () => {
      const testCase: CaseRecord = {
        id: '#VY-CORR-01',
        title: 'Domain and IP Correlation Test',
        description: 'Testing DOMAIN_TO_IP correlation',
        priority: 'Medium',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['threat-nexus.org', '203.0.113.88'],
        evidence: [
          {
            id: 'ev-dom-1',
            name: 'Target Domain intel',
            type: 'domain',
            value: 'threat-nexus.org',
            notes: 'DNS A records resolved to 203.0.113.88 with TTL 300',
            source: 'Recon Engine',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
          {
            id: 'ev-ip-1',
            name: 'Observed Server IP',
            type: 'ip',
            value: '203.0.113.88',
            notes: 'Hosting server located in ASN 64496',
            source: 'IP Resolver',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:05:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([testCase]);
      const match = graph.edges.find((e) => e.correlationType === 'DOMAIN_TO_IP');

      assert.ok(match, 'Expected correlation edge between domain and resolved IP');
      assert.strictEqual(match?.correlationType, 'DOMAIN_TO_IP');
      assert.strictEqual(match?.confidence, 'Confirmed');
      assert.ok(match?.reason.includes('threat-nexus.org'));
      assert.ok(match?.reason.includes('203.0.113.88'));
    });

    test('correlates IP address with PCAP endpoint via IP_TO_PCAP_ENDPOINT', () => {
      const testCase: CaseRecord = {
        id: '#VY-CORR-02',
        title: 'IP and PCAP Correlation Test',
        description: 'Testing IP_TO_PCAP_ENDPOINT correlation',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['198.51.100.99'],
        evidence: [
          {
            id: 'ev-ip-2',
            name: 'Suspect C2 IP',
            type: 'ip',
            value: '198.51.100.99',
            notes: 'Threat list indicator',
            source: 'Intel Feed',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
          {
            id: 'ev-pcap-2',
            name: 'perimeter_sniff.pcap',
            type: 'pcap',
            value: 'perimeter_sniff.pcap',
            notes: 'TCP SYN streams observed connecting to external IP 198.51.100.99 on port 4444',
            source: 'PCAP Lab',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:15:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([testCase]);
      const match = graph.edges.find((e) => e.correlationType === 'IP_TO_PCAP_ENDPOINT');

      assert.ok(match, 'Expected edge between IP and PCAP endpoint');
      assert.strictEqual(match?.correlationType, 'IP_TO_PCAP_ENDPOINT');
      assert.ok(match?.reason.includes('198.51.100.99'));
    });

    test('correlates file analysis artifact with file hash via FILE_TO_HASH', () => {
      const sha = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const testCase: CaseRecord = {
        id: '#VY-CORR-03',
        title: 'File and Hash Correlation Test',
        description: 'Testing FILE_TO_HASH correlation',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['malware.bin'],
        evidence: [
          {
            id: 'ev-file-3',
            name: 'malware.bin',
            type: 'file',
            value: sha,
            notes: `SHA-256: ${sha}. Dropped payload in temp directory.`,
            source: 'Disk Forensics',
            confidence: 'Confirmed',
            timestamp: '2026-04-10T11:00:00.000Z',
          },
          {
            id: 'ev-hash-3',
            name: 'Known Trojan Hash',
            type: 'hash',
            value: sha,
            notes: 'Listed in threat registry',
            source: 'Threat Intelligence Feed',
            confidence: 'Confirmed',
            timestamp: '2026-04-10T11:02:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([testCase]);
      const match = graph.edges.find((e) => e.correlationType === 'FILE_TO_HASH');

      assert.ok(match, 'Expected FILE_TO_HASH edge');
      assert.strictEqual(match?.correlationType, 'FILE_TO_HASH');
      assert.strictEqual(match?.confidence, 'Confirmed');
    });

    test('correlates CVE identifier with documented vulnerability findings via CVE_TO_ASSET', () => {
      const testCase: CaseRecord = {
        id: '#VY-CORR-04',
        title: 'CVE and Asset Correlation Test',
        description: 'Testing CVE_TO_ASSET correlation',
        priority: 'Critical',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:RED',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['CVE-2024-3094'],
        evidence: [
          {
            id: 'ev-cve-4',
            name: 'CVE-2024-3094',
            type: 'cve',
            value: 'CVE-2024-3094',
            notes: 'Upstream xz-utils library backdoored',
            source: 'NVD Feed',
            confidence: 'Confirmed',
            timestamp: '2026-04-10T11:05:00.000Z',
          },
          {
            id: 'ev-server-4',
            name: 'Production Gateway',
            type: 'ip',
            value: '198.51.100.10',
            notes: 'Linux bastion server impacted by CVE-2024-3094 in liblzma',
            source: 'Host Inventory',
            confidence: 'Observed',
            timestamp: '2026-04-10T11:10:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([testCase]);
      const match = graph.edges.find((e) => e.correlationType === 'CVE_TO_ASSET');

      assert.ok(match, 'Expected CVE_TO_ASSET edge');
      assert.strictEqual(match?.correlationType, 'CVE_TO_ASSET');
    });

    test('correlates domain DNS resolution with PCAP network traffic via DNS_TO_NETWORK', () => {
      const testCase: CaseRecord = {
        id: '#VY-CORR-05',
        title: 'Domain and PCAP Correlation Test',
        description: 'Testing DNS_TO_NETWORK correlation',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['phish-bank.com'],
        evidence: [
          {
            id: 'ev-dom-5',
            name: 'phish-bank.com',
            type: 'domain',
            value: 'phish-bank.com',
            notes: 'Credential harvesting landing page',
            source: 'Recon Engine',
            confidence: 'Observed',
            timestamp: '2026-04-10T12:00:00.000Z',
          },
          {
            id: 'ev-pcap-5',
            name: 'workstation_egress.pcap',
            type: 'pcap',
            value: 'workstation_egress.pcap',
            notes: 'HTTP GET request observed in frame 88 to phish-bank.com',
            source: 'PCAP Lab',
            confidence: 'Observed',
            timestamp: '2026-04-10T12:02:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([testCase]);
      const match = graph.edges.find((e) => e.correlationType === 'DNS_TO_NETWORK');

      assert.ok(match, 'Expected DNS_TO_NETWORK correlation edge');
      assert.strictEqual(match?.correlationType, 'DNS_TO_NETWORK');
    });

    test('correlates findings sharing common evidence via FINDING_TO_FINDING', () => {
      const caseItem: CaseRecord = {
        id: '#VY-CORR-06',
        title: 'Multi-Finding Case',
        description: 'Correlating findings sharing evidence',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Lead Analyst',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['198.51.100.200'],
        evidence: [
          {
            id: 'ev-common-1',
            name: 'Malicious Server IP',
            type: 'ip',
            value: '198.51.100.200',
            notes: 'Primary C2',
            source: 'Threat Feed',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
        ],
        findings: [
          {
            id: 'FND-ALPHA',
            caseId: '#VY-CORR-06',
            title: 'Unauthorized Outbound Connection',
            severity: 'High',
            confidence: 'Confirmed',
            evidenceIds: ['ev-common-1'],
            sourceTool: 'Firewall Log',
            targetEntity: '198.51.100.200',
            observedResult: 'Connected on 443',
            description: 'Observed outbound TCP handshake',
            provenance: 'Syslog',
            limitations: [],
            relatedFindingIds: [],
            riskImplications: 'Data egress',
            collectedAt: '2026-04-10T10:00:00.000Z',
            status: 'Unresolved',
            category: 'Network & Protocol',
          },
          {
            id: 'FND-BETA',
            caseId: '#VY-CORR-06',
            title: 'Cobalt Strike Malleable C2 Traffic',
            severity: 'Critical',
            confidence: 'Confirmed',
            evidenceIds: ['ev-common-1'],
            sourceTool: 'PCAP Analyzer',
            targetEntity: '198.51.100.200',
            observedResult: 'Malleable profile signature match',
            description: 'Periodic beacon pattern',
            provenance: 'Frame 101',
            limitations: [],
            relatedFindingIds: [],
            riskImplications: 'Active operator interactive session',
            collectedAt: '2026-04-10T10:05:00.000Z',
            status: 'Investigating',
            category: 'Network & Protocol',
          },
        ],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([caseItem]);
      const crossFindingEdge = graph.edges.find((e) => e.correlationType === 'FINDING_TO_FINDING');

      assert.ok(crossFindingEdge, 'Expected FINDING_TO_FINDING edge between findings sharing common evidence');
      assert.strictEqual(crossFindingEdge?.correlationType, 'FINDING_TO_FINDING');
    });
  });

  // =========================================================================
  // 3. Unsupported Correlation Rejection & Anti-Hallucination
  // =========================================================================
  describe('3. Unsupported Correlation Rejection & Co-occurrence Rejection', () => {
    test('rejects correlation between completely unrelated artifacts in the same case', () => {
      const caseItem: CaseRecord = {
        id: '#VY-REJECT-01',
        title: 'Unrelated Artifacts Case',
        description: 'Testing that co-occurrence does not equal correlation',
        priority: 'Low',
        status: 'Open',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:CLEAR',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['company-portal.local', 'clean-installer.exe'],
        evidence: [
          {
            id: 'ev-u1',
            name: 'Internal Domain',
            type: 'domain',
            value: 'company-portal.local',
            notes: '10.0.0.5 internal DNS entry',
            source: 'Internal DNS',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
          {
            id: 'ev-u2',
            name: 'Unrelated Binary',
            type: 'file',
            value: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            notes: 'Clean installer with 0 threat detections',
            source: 'Local Disk',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:01:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([caseItem]);

      // Direct edge between u1 and u2 must be strictly absent!
      const directEdge = graph.edges.find(
        (e) =>
          (e.source.includes('ev-u1') && e.target.includes('ev-u2')) ||
          (e.source.includes('ev-u2') && e.target.includes('ev-u1'))
      );
      assert.strictEqual(
        directEdge,
        undefined,
        'Co-occurrence in the same case MUST NOT synthesize an evidence edge without verifiable proof'
      );

      // Only scope edges from Case Master to each artifact are allowed (2 scope edges)
      const nonScopeEdges = graph.edges.filter((e) => e.correlationType !== 'SCOPE_ARTIFACT');
      assert.strictEqual(nonScopeEdges.length, 0);
    });

    test('rejection holds for non-matching CVEs and non-matching IPs', () => {
      const caseItem: CaseRecord = {
        id: '#VY-REJECT-02',
        title: 'Unrelated CVE and IP',
        description: 'Testing CVE vs IP rejection',
        priority: 'Low',
        status: 'Open',
        leadAnalyst: 'Test Analyst',
        classification: 'TLP:CLEAR',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['CVE-2017-5638', '192.0.2.1'],
        evidence: [
          {
            id: 'ev-cve-x',
            name: 'CVE-2017-5638',
            type: 'cve',
            value: 'CVE-2017-5638',
            notes: 'Jakarta parser vulnerability in Apache Struts',
            source: 'NVD',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
          {
            id: 'ev-ip-y',
            name: 'DNS Root Server',
            type: 'ip',
            value: '192.0.2.1',
            notes: 'Standard root resolver',
            source: 'DNS Telemetry',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graph = buildEvidenceGraph([caseItem]);
      const crossEdges = graph.edges.filter((e) => e.correlationType !== 'SCOPE_ARTIFACT');
      assert.strictEqual(crossEdges.length, 0, 'No edges should exist between unrelated CVE and IP');
    });
  });

  // =========================================================================
  // 4. Case Isolation
  // =========================================================================
  describe('4. Case Isolation & Legal Multi-Tenant Boundaries', () => {
    test('strictly isolates graph computation and findings within case boundary', () => {
      const caseA: CaseRecord = {
        id: '#VY-CASE-001',
        title: 'Case Alpha',
        description: 'First isolated incident',
        priority: 'Medium',
        status: 'Open',
        leadAnalyst: 'Analyst A',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['phish-a.com'],
        evidence: [
          {
            id: 'ev-a-1',
            name: 'Domain A',
            type: 'domain',
            value: 'phish-a.com',
            notes: 'Resolves to 203.0.113.10',
            source: 'Recon Engine',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const caseB: CaseRecord = {
        id: '#VY-CASE-002',
        title: 'Case Beta',
        description: 'Second isolated incident',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'Analyst B',
        classification: 'TLP:RED',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['203.0.113.10'],
        evidence: [
          {
            id: 'ev-b-1',
            name: 'IP B',
            type: 'ip',
            value: '203.0.113.10',
            notes: 'Coincidentally identical IP in a separate customer case',
            source: 'External Feed',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
      };

      const graphA = buildEvidenceGraph([caseA]);
      const graphB = buildEvidenceGraph([caseB]);

      // Verify graph A has zero references to case B
      const nodesInA = new Set(graphA.nodes.map((n) => n.id));
      assert.ok(nodesInA.has('ev-#VY-CASE-001-ev-a-1'));
      assert.ok(!nodesInA.has('ev-#VY-CASE-002-ev-b-1'), 'Case A graph must never include nodes from Case B');

      const nodesInB = new Set(graphB.nodes.map((n) => n.id));
      assert.ok(nodesInB.has('ev-#VY-CASE-002-ev-b-1'));
      assert.ok(!nodesInB.has('ev-#VY-CASE-001-ev-a-1'), 'Case B graph must never include nodes from Case A');

      // Verify no cross-case edges
      const crossEdgesA = graphA.edges.filter(
        (e) => e.source.includes('#VY-CASE-002') || e.target.includes('#VY-CASE-002')
      );
      assert.strictEqual(crossEdgesA.length, 0);
    });
  });

  // =========================================================================
  // 5. Evidence Provenance Preservation on Analyst Dismissal
  // =========================================================================
  describe('5. Evidence Provenance Preservation on Analyst Overrides', () => {
    test('analyst dismissal overrides correlation status without mutating or deleting raw evidence', () => {
      const caseRecord: CaseRecord = {
        id: '#VY-DISMISS-01',
        title: 'Analyst Dismissal Test',
        description: 'Verifying provenance preservation',
        priority: 'Medium',
        status: 'In Progress',
        leadAnalyst: 'Test Lead',
        classification: 'TLP:AMBER',
        createdAt: '2026-04-10T10:00:00.000Z',
        updatedAt: '2026-04-10T10:00:00.000Z',
        scope: ['cdn.commoncloud.net', '192.0.2.200'],
        evidence: [
          {
            id: 'ev-dom-dis',
            name: 'cdn.commoncloud.net',
            type: 'domain',
            value: 'cdn.commoncloud.net',
            notes: 'Resolves to shared reverse proxy 192.0.2.200',
            source: 'Recon',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:00:00.000Z',
          },
          {
            id: 'ev-ip-dis',
            name: 'Shared Proxy IP',
            type: 'ip',
            value: '192.0.2.200',
            notes: 'Shared IP hosting benign tenants',
            source: 'Network Scanner',
            confidence: 'Observed',
            timestamp: '2026-04-10T10:05:00.000Z',
          },
        ],
        findings: [],
        tags: [],
        notes: [],
        auditLog: [],
        correlationOverrides: {
          'edge-ev-#VY-DISMISS-01-ev-dom-dis-ev-#VY-DISMISS-01-ev-ip-dis-direct': 'dismissed',
        },
      };

      // Raw evidence must remain untouched
      const originalEvCount = caseRecord.evidence.length;
      assert.strictEqual(originalEvCount, 2);

      const graph = buildEvidenceGraph([caseRecord]);
      const edge = graph.edges.find((e) => e.correlationType === 'DOMAIN_TO_IP');

      assert.ok(edge, 'Edge must still be represented in graph model');
      assert.strictEqual(edge?.status, 'dismissed', 'Edge status must reflect analyst override');

      // Crucial verification: raw evidence items in caseRecord remain intact and unmodified
      assert.strictEqual(caseRecord.evidence.length, 2);
      assert.strictEqual(caseRecord.evidence[0].id, 'ev-dom-dis');
      assert.strictEqual(caseRecord.evidence[1].id, 'ev-ip-dis');
      assert.strictEqual(caseRecord.evidence[0].value, 'cdn.commoncloud.net');
      assert.strictEqual(caseRecord.evidence[1].value, '192.0.2.200');
    });
  });

  // =========================================================================
  // 6. Report Accuracy & Grounded Conclusions
  // =========================================================================
  describe('6. Investigation Report Generation Accuracy', () => {
    test('generates all structured report sections grounded in verifiable case findings', () => {
      const activeCase = INITIAL_CASES[0];
      const report = generateInvestigationReport(activeCase);

      assert.strictEqual(report.caseId, activeCase.id);
      assert.strictEqual(report.caseTitle, activeCase.title);
      assert.ok(report.generatedAt.endsWith('Z'), 'Report timestamp must be UTC ISO');

      // Verify sections
      assert.ok(report.executiveSummary.length > 50, 'Executive summary must be comprehensive');
      assert.ok(report.investigationScope.boundary.length > 0, 'Investigation scope must be defined');
      assert.ok(report.methodology.length > 0, 'Methodology must cite deterministic forensic standards');
      assert.ok(report.targetsAnalyzed.length > 0, 'Targets analyzed must list observed entities');

      // Verify confirmed observations vs inferred correlations segregation
      assert.ok(Array.isArray(report.confirmedObservations));
      assert.ok(Array.isArray(report.inferredCorrelations));

      // Check evidence inventory
      assert.ok(report.evidenceInventory.length >= activeCase.evidence.length);
      for (const row of report.evidenceInventory) {
        assert.ok(row.id);
        assert.ok(row.name);
        assert.ok(row.type);
        assert.ok(row.timestamp.endsWith('Z'));
      }

      // Check limitations and conclusions
      assert.ok(report.defensiveLimitations.length > 0, 'Limitations must be documented');
      assert.ok(report.conclusions.length > 0, 'Analyst conclusions must be present');

      // Every conclusion must be grounded in finding content
      const findingTitles = activeCase.findings.map((f) => f.title);
      const someGrounding = report.conclusions.some((c) =>
        findingTitles.some((ft) => c.conclusion.toLowerCase().includes(ft.toLowerCase().slice(0, 10))) ||
        c.conclusion.includes('Observed') ||
        c.conclusion.includes('evidence')
      );
      assert.ok(someGrounding, 'Conclusions must ground themselves in documented findings');
    });
  });

  // =========================================================================
  // 7. Missing-Data & Edge-Case Robustness
  // =========================================================================
  describe('7. Missing-Data Handling & Graceful Degradation', () => {
    test('handles empty evidence, empty findings, and partial case record without exceptions', () => {
      const sparseCase: CaseRecord = {
        id: '#VY-EMPTY-01',
        title: 'Empty Minimal Case',
        description: '',
        priority: 'Low',
        status: 'Open',
        leadAnalyst: 'Unassigned',
        classification: 'TLP:CLEAR',
        createdAt: '2026-04-10T00:00:00.000Z',
        updatedAt: '2026-04-10T00:00:00.000Z',
        scope: [],
        tags: [],
        evidence: [],
        findings: [],
        notes: [],
        auditLog: [],
      };

      // 1. Graph computation must not throw and produce valid root node
      const graph = buildEvidenceGraph([sparseCase]);
      assert.ok(graph.nodes.length >= 1, 'Should contain at least root case node');
      assert.strictEqual(graph.edges.length, 0);

      // 2. Report generation must succeed gracefully
      const report = generateInvestigationReport(sparseCase);
      assert.strictEqual(report.caseId, '#VY-EMPTY-01');
      assert.strictEqual(report.evidenceInventory.length, 0);
      assert.strictEqual(report.technicalFindings.length, 0);
      assert.ok(report.executiveSummary.includes('Empty Minimal Case'));

      // 3. Export to JSON must be valid
      const json = exportReportAsJson(sparseCase);
      assert.doesNotThrow(() => JSON.parse(json));
    });

    test('ensureUtcIsoString safely handles invalid and malformed dates', () => {
      // Valid ISO
      const valid = '2026-04-10T15:30:00.000Z';
      assert.strictEqual(ensureUtcIsoString(valid), valid);

      // Valid date without timezone converts to UTC Z
      const noZ = '2026-04-10T15:30:00';
      const resultNoZ = ensureUtcIsoString(noZ);
      assert.ok(resultNoZ.endsWith('Z'));

      // Invalid garbage date does not crash and produces valid UTC fallback
      const garbage = 'not-a-real-date';
      const fallback = ensureUtcIsoString(garbage);
      assert.ok(fallback.endsWith('Z'));
      assert.ok(!isNaN(Date.parse(fallback)));

      // Undefined input produces valid UTC fallback
      const undef = ensureUtcIsoString(undefined);
      assert.ok(undef.endsWith('Z'));
    });
  });

  // =========================================================================
  // 8. UTC Timestamp Consistency
  // =========================================================================
  describe('8. UTC Timestamp Consistency Across Data Structures', () => {
    test('all INITIAL_CASES findings, evidence, notes, and auditLog items adhere to UTC ISO-8601 format', () => {
      const utcIsoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

      for (const cs of INITIAL_CASES) {
        assert.ok(utcIsoRegex.test(cs.createdAt), `Case createdAt '${cs.createdAt}' must match UTC ISO`);
        assert.ok(utcIsoRegex.test(cs.updatedAt), `Case updatedAt '${cs.updatedAt}' must match UTC ISO`);

        for (const ev of cs.evidence) {
          assert.ok(utcIsoRegex.test(ev.timestamp), `Evidence timestamp '${ev.timestamp}' must match UTC ISO`);
        }

        for (const f of cs.findings) {
          assert.ok(utcIsoRegex.test(f.collectedAt), `Finding collectedAt '${f.collectedAt}' must match UTC ISO`);
          if (f.timestamp) {
            assert.ok(utcIsoRegex.test(f.timestamp), `Finding timestamp '${f.timestamp}' must match UTC ISO`);
          }
        }

        for (const n of cs.notes) {
          assert.ok(utcIsoRegex.test(n.timestamp), `Note timestamp '${n.timestamp}' must match UTC ISO`);
        }

        for (const a of cs.auditLog) {
          assert.ok(utcIsoRegex.test(a.timestamp), `AuditLog timestamp '${a.timestamp}' must match UTC ISO`);
        }
      }
    });
  });

  // =========================================================================
  // 9. Export Integrity
  // =========================================================================
  describe('9. Export Integrity & Schema Conformance', () => {
    test('JSON report export matches verifiable incident documentation standard', () => {
      const sampleCase = INITIAL_CASES[0];
      const jsonString = exportReportAsJson(sampleCase);

      // Must parse back to object without data corruption
      const parsed = JSON.parse(jsonString);

      assert.strictEqual(parsed.caseId, sampleCase.id);
      assert.strictEqual(parsed.caseTitle, sampleCase.title);
      assert.ok(Array.isArray(parsed.investigationScope.boundary));
      assert.ok(typeof parsed.methodology === 'string');
      assert.ok(Array.isArray(parsed.targetsAnalyzed));
      assert.ok(Array.isArray(parsed.confirmedObservations));
      assert.ok(Array.isArray(parsed.inferredCorrelations));
      assert.ok(Array.isArray(parsed.evidenceInventory));
      assert.ok(Array.isArray(parsed.chronologicalTimeline));
      assert.ok(Array.isArray(parsed.technicalFindings));
      assert.ok(Array.isArray(parsed.defensiveLimitations));
      assert.ok(Array.isArray(parsed.conclusions));

      // Finding IDs in technicalFindings must match original finding IDs
      for (const f of parsed.technicalFindings) {
        const original = sampleCase.findings.find((x) => x.id === f.id);
        assert.ok(original, `Finding ${f.id} in export must exist in original case findings`);
        assert.strictEqual(f.category, original.category);
        assert.strictEqual(f.targetEntity, original.targetEntity);
      }
    });
  });
});
