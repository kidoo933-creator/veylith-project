import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CaseRecord, Finding, EvidenceItem } from '../src/types';
import {
  buildEvidenceGraph,
  hasExactIpMatch,
  hasExactDomainMatch,
  hasExactHashMatch,
  hasExactCveMatch,
} from '../src/utils/evidenceCorrelation';
import {
  INITIAL_CASES,
  addFindingToCase,
  dismissCorrelation,
  markCorrelationUnverified,
  restoreCorrelation,
} from '../src/utils/storage';

describe('Veylith Milestone 3 — Unified Investigation Engine & Cross-Module Intelligence', () => {
  describe('Phase 1: Standardized Finding Structure & Normalization', () => {
    it('initializes all baseline findings with standardized, defensible fields', () => {
      INITIAL_CASES.forEach((c) => {
        c.findings.forEach((f) => {
          assert.ok(f.id, `Finding in ${c.id} must have an ID`);
          assert.ok(f.caseId, `Finding ${f.id} must specify caseId`);
          assert.ok(f.category, `Finding ${f.id} must specify FindingCategory`);
          assert.ok(f.targetEntity, `Finding ${f.id} must specify targetEntity`);
          assert.ok(f.observedResult, `Finding ${f.id} must specify observedResult`);
          assert.ok(f.severity, `Finding ${f.id} must specify severity`);
          assert.ok(f.severityRationale, `Finding ${f.id} must specify severityRationale`);
          assert.ok(f.confidence, `Finding ${f.id} must specify confidence`);
          assert.ok(f.provenance, `Finding ${f.id} must declare provenance`);
          assert.ok(f.limitations, `Finding ${f.id} must state defensive limitations`);
          assert.ok(Array.isArray(f.evidenceIds), `Finding ${f.id} must have evidenceIds array`);
        });
      });
    });

    it('distinguishes hardening observations from proof of compromise in rationales', () => {
      const f3 = INITIAL_CASES.find((c) => c.id === '#VY-2025-0048')?.findings[0];
      assert.ok(f3, 'Finding f-3 must exist');
      // Must not use sensationalized jargon like "proven breach" or "total system takeover"
      assert.strictEqual(f3.title.toLowerCase().includes('total takeover'), false);
      assert.ok(f3.severityRationale && f3.severityRationale.length > 10);
    });
  });

  describe('Phase 2: Cross-Module Evidence Intelligence & Correlation', () => {
    it('correlates domain with resolved IP address via exact recorded telemetry', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-01',
        title: 'Network Correlation Test',
        description: 'Test case',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Perimeter'],
        tags: [],
        evidence: [
          {
            id: 'ev-d1',
            caseId: '#TEST-01',
            name: 'c2-relay.org',
            type: 'domain',
            value: 'c2-relay.org',
            confidence: 'Confirmed',
            source: 'DNS Probe',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Resolves to 203.0.113.88 in observed passive DNS telemetry.',
          },
          {
            id: 'ev-ip1',
            caseId: '#TEST-01',
            name: '203.0.113.88',
            type: 'ip',
            value: '203.0.113.88',
            confidence: 'Observed',
            source: 'Firewall',
            timestamp: '2025-01-01T01:05:00Z',
            notes: 'Observed destination for outbound session.',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([caseRecord]);
      const domainIpEdge = edges.find(
        (e) =>
          (e.source.includes('ev-d1') && e.target.includes('ev-ip1')) ||
          (e.source.includes('ev-ip1') && e.target.includes('ev-d1'))
      );

      assert.ok(domainIpEdge, 'Exact DNS resolution between c2-relay.org and 203.0.113.88 must be correlated');
      assert.strictEqual(domainIpEdge.isInferred, false);
      assert.strictEqual(domainIpEdge.confidence, 'Confirmed');
    });

    it('correlates IP address with PCAP packet endpoints', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-02',
        title: 'PCAP Correlation Test',
        description: 'Test case',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['PCAP Flow'],
        tags: [],
        evidence: [
          {
            id: 'ev-pcap',
            caseId: '#TEST-02',
            name: 'traffic_capture.pcapng',
            type: 'pcap',
            value: 'traffic_capture.pcapng',
            confidence: 'Observed',
            source: 'Veylith PCAP Lab',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Captured conversation endpoints: 192.168.1.50 <-> 198.51.100.99 (TCP/443).',
          },
          {
            id: 'ev-ip',
            caseId: '#TEST-02',
            name: '198.51.100.99',
            type: 'ip',
            value: '198.51.100.99',
            confidence: 'Confirmed',
            source: 'Threat Intel',
            timestamp: '2025-01-01T01:10:00Z',
            notes: 'Known external proxy endpoint.',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([caseRecord]);
      const pcapEdge = edges.find(
        (e) =>
          (e.source.includes('ev-pcap') && e.target.includes('ev-ip')) ||
          (e.source.includes('ev-ip') && e.target.includes('ev-pcap'))
      );

      assert.ok(pcapEdge, 'PCAP packet capture must correlate with recorded conversation endpoint IP 198.51.100.99');
      assert.strictEqual(pcapEdge.confidence, 'Confirmed');
    });

    it('correlates file artifact with cryptographic hash verification', () => {
      const sha256 = '4a8d052d9a9b9a9d04082c9e83e582e08e8d8c9e81a029384729104829384719';
      const caseRecord: CaseRecord = {
        id: '#TEST-03',
        title: 'Hash Verification Test',
        description: 'Test case',
        priority: 'High',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Disk'],
        tags: [],
        evidence: [
          {
            id: 'ev-file',
            caseId: '#TEST-03',
            name: 'payload.exe',
            type: 'file',
            value: sha256,
            confidence: 'Observed',
            source: 'Endpoint Agent',
            timestamp: '2025-01-01T01:00:00Z',
          },
          {
            id: 'ev-hash',
            caseId: '#TEST-03',
            name: 'SHA-256 Digest',
            type: 'hash',
            value: sha256,
            confidence: 'Confirmed',
            source: 'VirusTotal Match',
            timestamp: '2025-01-01T01:02:00Z',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([caseRecord]);
      const hashEdge = edges.find(
        (e) =>
          (e.source.includes('ev-file') && e.target.includes('ev-hash')) ||
          (e.source.includes('ev-hash') && e.target.includes('ev-file'))
      );

      assert.ok(hashEdge, 'File and matching cryptographic SHA-256 hash must be correlated');
      assert.strictEqual(hashEdge.confidence, 'Confirmed');
    });

    it('correlates CVE vulnerability identifier with impacted asset', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-04',
        title: 'CVE Impact Test',
        description: 'Test case',
        priority: 'Critical',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Vulnerability Scan'],
        tags: [],
        evidence: [
          {
            id: 'ev-vpn',
            caseId: '#TEST-04',
            name: 'vpn-gateway.corp.com',
            type: 'domain',
            value: 'vpn-gateway.corp.com',
            confidence: 'Confirmed',
            source: 'Asset DB',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Perimeter gateway vulnerable to CVE-2024-3400 unauthenticated command injection.',
          },
          {
            id: 'ev-cve',
            caseId: '#TEST-04',
            name: 'CVE-2024-3400',
            type: 'cve',
            value: 'CVE-2024-3400 (CVSS 10.0)',
            confidence: 'Confirmed',
            source: 'CISA KEV',
            timestamp: '2025-01-01T01:05:00Z',
            notes: 'Command injection in GlobalProtect gateway.',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([caseRecord]);
      const cveEdge = edges.find(
        (e) =>
          (e.source.includes('ev-vpn') && e.target.includes('ev-cve')) ||
          (e.source.includes('ev-cve') && e.target.includes('ev-vpn'))
      );

      assert.ok(cveEdge, 'Vulnerability CVE-2024-3400 must correlate with impacted gateway asset');
    });

    it('strictly rejects negative correlations between unrelated entities in the same case', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-05',
        title: 'Negative Correlation Boundary Test',
        description: 'Test case',
        priority: 'Low',
        status: 'Open',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Perimeter'],
        tags: [],
        evidence: [
          {
            id: 'ev-d-unrelated',
            caseId: '#TEST-05',
            name: 'corporate-portal.com',
            type: 'domain',
            value: 'corporate-portal.com',
            confidence: 'Observed',
            source: 'DNS',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Resolves to 93.184.216.34',
          },
          {
            id: 'ev-ip-unrelated',
            caseId: '#TEST-05',
            name: '10.0.0.15',
            type: 'ip',
            value: '10.0.0.15',
            confidence: 'Observed',
            source: 'DHCP',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Internal workstation lease for HOST-99',
          },
          {
            id: 'ev-ip-substring',
            caseId: '#TEST-05',
            name: '10.0.0.1',
            type: 'ip',
            value: '10.0.0.1',
            confidence: 'Observed',
            source: 'Router',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Default gateway',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([caseRecord]);

      // There should be NO direct edge between corporate-portal.com and 10.0.0.15
      const fakeDomainIpEdge = edges.find(
        (e) =>
          (e.source.includes('ev-d-unrelated') && e.target.includes('ev-ip-unrelated')) ||
          (e.source.includes('ev-ip-unrelated') && e.target.includes('ev-d-unrelated'))
      );
      assert.strictEqual(fakeDomainIpEdge, undefined, 'Unrelated domain and IP must NOT be falsely connected');

      // 10.0.0.1 must not falsely connect to 10.0.0.15 via substring match
      const substringCollisionEdge = edges.find(
        (e) =>
          (e.source.includes('ev-ip-substring') && e.target.includes('ev-ip-unrelated')) ||
          (e.source.includes('ev-ip-unrelated') && e.target.includes('ev-ip-substring'))
      );
      assert.strictEqual(substringCollisionEdge, undefined, 'IP substring 10.0.0.1 must NOT match 10.0.0.15');
    });
  });

  describe('Phase 3: Correlation Dismissal & Evidence Immutability', () => {
    it('dismissing a correlation edge marks it dismissed without altering or deleting raw evidence', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-DISMISS',
        title: 'Dismissal Immutability Test',
        description: 'Test case',
        priority: 'Medium',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Scope A'],
        tags: [],
        evidence: [
          {
            id: 'ev-1',
            caseId: '#TEST-DISMISS',
            name: 'host-a.org',
            type: 'domain',
            value: 'host-a.org',
            confidence: 'Confirmed',
            source: 'DNS',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Resolves to 192.0.2.1',
          },
          {
            id: 'ev-2',
            caseId: '#TEST-DISMISS',
            name: '192.0.2.1',
            type: 'ip',
            value: '192.0.2.1',
            confidence: 'Observed',
            source: 'Firewall',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Target IP',
          },
        ],
        findings: [],
        dismissedCorrelationIds: [],
        unverifiedCorrelationIds: [],
        notes: [],
        auditLog: [],
      };

      // 1. Initial build: correlation is active
      const initialGraph = buildEvidenceGraph([caseRecord]);
      const targetEdge = initialGraph.edges.find((e) => e.id.includes('direct'));
      assert.ok(targetEdge, 'Direct correlation edge must exist initially');

      // 2. Dismiss the correlation edge by ID
      caseRecord.dismissedCorrelationIds = [targetEdge.id];

      // 3. Rebuild active graph: dismissed edge is excluded from active display
      const activeGraph = buildEvidenceGraph([caseRecord]);
      const dismissedEdgeInActive = activeGraph.edges.find((e) => e.id === targetEdge.id);
      assert.strictEqual(dismissedEdgeInActive, undefined, 'Dismissed edge must be filtered from active graph');

      // 4. Rebuild with includeDismissed: true to verify it is retained with status 'dismissed'
      const allGraph = buildEvidenceGraph([caseRecord], { includeDismissed: true });
      const retainedEdge = allGraph.edges.find((e) => e.id === targetEdge.id);
      assert.ok(retainedEdge, 'Dismissed edge must still exist in full intelligence ledger');
      assert.strictEqual(retainedEdge.status, 'dismissed');

      // 5. CRITICAL: Underlying evidence items must remain untouched and completely immutable
      assert.strictEqual(caseRecord.evidence.length, 2, 'Raw evidence must not be deleted or modified');
      assert.strictEqual(caseRecord.evidence[0].id, 'ev-1');
      assert.strictEqual(caseRecord.evidence[1].id, 'ev-2');
    });

    it('marking a correlation unverified flags status without deleting evidence', () => {
      const caseRecord: CaseRecord = {
        id: '#TEST-UNVERIFIED',
        title: 'Unverified Flagging Test',
        description: 'Test case',
        priority: 'Medium',
        status: 'In Progress',
        leadAnalyst: 'Test Analyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Scope B'],
        tags: [],
        evidence: [
          {
            id: 'ev-1',
            caseId: '#TEST-UNVERIFIED',
            name: 'host-b.org',
            type: 'domain',
            value: 'host-b.org',
            confidence: 'Confirmed',
            source: 'DNS',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Resolves to 198.51.100.5',
          },
          {
            id: 'ev-2',
            caseId: '#TEST-UNVERIFIED',
            name: '198.51.100.5',
            type: 'ip',
            value: '198.51.100.5',
            confidence: 'Observed',
            source: 'Firewall',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Target IP',
          },
        ],
        findings: [],
        dismissedCorrelationIds: [],
        unverifiedCorrelationIds: [],
        notes: [],
        auditLog: [],
      };

      const initialGraph = buildEvidenceGraph([caseRecord]);
      const targetEdge = initialGraph.edges.find((e) => e.id.includes('direct'))!;
      assert.ok(targetEdge);

      caseRecord.unverifiedCorrelationIds = [targetEdge.id];
      const updatedGraph = buildEvidenceGraph([caseRecord]);
      const unverifiedEdge = updatedGraph.edges.find((e) => e.id === targetEdge.id);

      assert.ok(unverifiedEdge, 'Unverified edge must remain present in graph');
      assert.strictEqual(unverifiedEdge.status, 'unverified');
      assert.strictEqual(unverifiedEdge.confidence, 'Potential');
      assert.strictEqual(caseRecord.evidence.length, 2, 'Raw evidence must remain immutable');
    });
  });

  describe('Phase 4: Case Isolation & Zero Fake Data', () => {
    it('guarantees entities in Case A are isolated from Case B when scoped to single case', () => {
      const caseA: CaseRecord = {
        id: '#CASE-A',
        title: 'Case A',
        description: 'First case',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'Analyst A',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Network A'],
        tags: [],
        evidence: [
          {
            id: 'ev-a',
            caseId: '#CASE-A',
            name: 'domain-a.com',
            type: 'domain',
            value: 'domain-a.com',
            confidence: 'Confirmed',
            source: 'DNS',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'Resolves to 192.0.2.100',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const caseB: CaseRecord = {
        id: '#CASE-B',
        title: 'Case B',
        description: 'Second case',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'Analyst B',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Network B'],
        tags: [],
        evidence: [
          {
            id: 'ev-b',
            caseId: '#CASE-B',
            name: '192.0.2.100',
            type: 'ip',
            value: '192.0.2.100',
            confidence: 'Observed',
            source: 'Firewall',
            timestamp: '2025-01-01T01:00:00Z',
            notes: 'IP in Case B',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      // In single case active mode for Case A, only Case A nodes are returned
      const graphA = buildEvidenceGraph([caseA]);
      assert.strictEqual(
        graphA.nodes.some((n) => n.id.includes('#CASE-B')),
        false,
        'Case A must NOT contain nodes from Case B'
      );
      assert.strictEqual(graphA.edges.length, 1, 'Only root Case A -> ev-a edge must exist');
    });

    it('handles empty cases gracefully with zero synthetic or fake artifacts', () => {
      const emptyCase: CaseRecord = {
        id: '#CASE-EMPTY',
        title: 'Empty Triage Case',
        description: 'A newly created case with zero artifacts yet',
        priority: 'Low',
        status: 'Open',
        leadAnalyst: 'Alex Carter',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['Perimeter Gateway'],
        tags: [],
        evidence: [],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { nodes, edges } = buildEvidenceGraph([emptyCase]);
      assert.strictEqual(nodes.length, 1, 'Only root case node must exist for empty case');
      assert.strictEqual(nodes[0].id, 'case-#CASE-EMPTY');
      assert.strictEqual(edges.length, 0, 'No edges must be synthesized for empty case');
    });
  });
});
