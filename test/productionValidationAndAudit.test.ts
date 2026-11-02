import { describe, it, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isPrivateOrReservedIP,
  validateHostname,
  parseIPv4AnyFormat,
  parseIPv6Words,
  PERMITTED_WEB_PORTS,
} from '../server/ssrfGuard';
import {
  createCase,
  addEvidenceToCase,
  addFindingToCase,
  deleteCase,
  getStoredCases,
  clearAllCases,
  assertRolePermission,
  assertTenantAccess,
  computeFastAuditHash,
  createChainedAuditEntry,
  verifyCaseAuditTrailIntegrity,
  setAnalystProfile,
  DEFAULT_ANALYST_PROFILE,
  ROLE_PERMISSIONS,
} from '../src/utils/storage';
import {
  auditFactualClaimsAgainstTelemetry,
  deriveFindingConfidenceMetadata,
} from '../src/utils/evidenceGrounding';
import { normalizeFinding } from '../src/utils/findingNormalization';
import { generateInvestigationReport } from '../src/utils/reportGenerator';
import { parsePcapFile } from '../src/utils/pcapParser';
import { detectFileSignature, computeEntropy } from '../src/utils/forensics';
import { CaseRecord } from '../src/types';

describe('Veylith Production Security Audit & Validation', () => {
  describe('1. Advanced SSRF, Cloud Metadata & Port Allowlisting', () => {
    it('blocks Alibaba Cloud metadata endpoint (100.100.100.200)', () => {
      const check = isPrivateOrReservedIP('100.100.100.200');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.includes('metadata'));
    });

    it('blocks AWS IMDSv2 IPv6 metadata endpoint (fd00:ec2::254)', () => {
      const check = isPrivateOrReservedIP('fd00:ec2::254');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.includes('Unique Local'));
    });

    it('blocks IPv4-compatible IPv6 loopback (::127.0.0.1)', () => {
      const check = isPrivateOrReservedIP('::127.0.0.1');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.includes('Loopback'));
    });

    it('parses and blocks multi-part hex notation (0x7f.0x0.0x0.0x1)', () => {
      const octets = parseIPv4AnyFormat('0x7f.0x0.0x0.0x1');
      assert.deepStrictEqual(octets, [127, 0, 0, 1]);
      const check = isPrivateOrReservedIP('0x7f.0x0.0x0.0x1');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.includes('Loopback'));
    });

    it('parses and blocks shorthand notation (127.1 -> 127.0.0.1)', () => {
      const octets = parseIPv4AnyFormat('127.1');
      assert.deepStrictEqual(octets, [127, 0, 0, 1]);
      const check = isPrivateOrReservedIP('127.1');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.includes('Loopback'));
    });

    it('rejects forbidden internal ports for security probes', () => {
      // Forbidden: SSH (22), Redis (6379), MySQL (3306), Kubelet (10250)
      const ssh = validateHostname('https://legitimate-target.com:22/');
      assert.strictEqual(ssh.isValid, false);
      assert.ok(ssh.error?.includes('not permitted'));

      const redis = validateHostname('http://legitimate-target.com:6379/');
      assert.strictEqual(redis.isValid, false);
      assert.ok(redis.error?.includes('not permitted'));

      const mysql = validateHostname('http://legitimate-target.com:3306/');
      assert.strictEqual(mysql.isValid, false);
      assert.ok(mysql.error?.includes('not permitted'));
    });

    it('permits authorized web ports (80, 443, 8080, 8443)', () => {
      assert.ok(PERMITTED_WEB_PORTS.has(''));
      assert.ok(PERMITTED_WEB_PORTS.has('80'));
      assert.ok(PERMITTED_WEB_PORTS.has('443'));
      assert.ok(PERMITTED_WEB_PORTS.has('8080'));
      assert.ok(PERMITTED_WEB_PORTS.has('8443'));

      const https = validateHostname('https://legitimate-target.com:443/');
      assert.strictEqual(https.isValid, true);
      assert.ok(https.port === '' || https.port === '443');

      const webAlt = validateHostname('https://legitimate-target.com:8443/');
      assert.strictEqual(webAlt.isValid, true);
      assert.strictEqual(webAlt.port, '8443');
    });
  });

  describe('2. Multi-Tenant Isolation & Role-Based Access Control (RBAC)', () => {
    it('enforces case isolation between distinct organizational tenants', () => {
      const caseA: CaseRecord = {
        id: '#VY-2025-TENANT-A',
        tenantId: 'tenant-enterprise-alpha',
        title: 'Alpha Incident',
        description: 'Alpha telemetry',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'Analyst Alpha',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        scope: ['alpha.internal'],
        tags: ['alpha'],
        evidence: [],
        findings: [],
        notes: [],
        auditLog: [],
      };

      // Authorized for tenant-enterprise-alpha
      assert.doesNotThrow(() => assertTenantAccess(caseA, 'tenant-enterprise-alpha'));

      // Unauthorized for tenant-enterprise-beta
      assert.throws(
        () => assertTenantAccess(caseA, 'tenant-enterprise-beta'),
        /Tenant Isolation Violation/
      );
    });

    it('enforces RBAC permissions: read_only_auditor cannot create, edit, or delete cases', () => {
      setAnalystProfile({ userRole: 'read_only_auditor' });

      assert.throws(() => assertRolePermission('canCreateCase'), /RBAC Authorization Denied/);
      assert.throws(() => assertRolePermission('canEditCase'), /RBAC Authorization Denied/);
      assert.throws(() => assertRolePermission('canDeleteCase'), /RBAC Authorization Denied/);
      assert.throws(() => assertRolePermission('canAddEvidence'), /RBAC Authorization Denied/);

      // But read_only_auditor CAN export reports
      assert.doesNotThrow(() => assertRolePermission('canExportReport'));

      // Restore default role
      setAnalystProfile({ userRole: 'lead_investigator' });
    });

    it('enforces RBAC permissions: forensics_analyst can investigate but cannot delete cases', () => {
      setAnalystProfile({ userRole: 'forensics_analyst' });

      assert.doesNotThrow(() => assertRolePermission('canCreateCase'));
      assert.doesNotThrow(() => assertRolePermission('canAddEvidence'));
      assert.doesNotThrow(() => assertRolePermission('canLogFinding'));
      assert.throws(() => assertRolePermission('canDeleteCase'), /RBAC Authorization Denied/);

      // Restore default role
      setAnalystProfile({ userRole: 'lead_investigator' });
    });
  });

  describe('3. Cryptographic Tamper-Evident Audit Trail Integrity', () => {
    it('constructs a verifiable SHA-256 hash chain across sequential audit events', () => {
      const auditLog: CaseRecord['auditLog'] = [];

      const entry1 = createChainedAuditEntry(auditLog, 'CASE_CREATED', 'Lead Analyst', 'Case initialized');
      auditLog.push(entry1);
      assert.ok(entry1.hash);
      assert.strictEqual(entry1.prevHash, '0000000000000000000000000000000000000000000000000000000000000000');

      const entry2 = createChainedAuditEntry(auditLog, 'EVIDENCE_ADDED', 'Lead Analyst', 'Added domain observable');
      auditLog.push(entry2);
      assert.strictEqual(entry2.prevHash, entry1.hash);

      const entry3 = createChainedAuditEntry(auditLog, 'FINDING_LOGGED', 'Lead Analyst', 'Logged missing CSP');
      auditLog.push(entry3);
      assert.strictEqual(entry3.prevHash, entry2.hash);

      const mockCase: CaseRecord = {
        id: '#VY-AUDIT-TEST',
        title: 'Audit Test',
        description: 'Testing',
        priority: 'Medium',
        status: 'Open',
        leadAnalyst: 'Lead Analyst',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        scope: [],
        tags: [],
        evidence: [],
        findings: [],
        notes: [],
        auditLog,
      };

      const verification = verifyCaseAuditTrailIntegrity(mockCase);
      assert.strictEqual(verification.isValid, true);
    });

    it('detects tampering if an audit log record detail or timestamp is modified', () => {
      const auditLog: CaseRecord['auditLog'] = [];
      const entry1 = createChainedAuditEntry(auditLog, 'CASE_CREATED', 'Analyst', 'Initial');
      auditLog.push(entry1);
      const entry2 = createChainedAuditEntry(auditLog, 'EVIDENCE_ADDED', 'Analyst', 'Evidence');
      auditLog.push(entry2);

      const mockCase: CaseRecord = {
        id: '#VY-TAMPER-TEST',
        title: 'Tamper Test',
        description: 'Testing',
        priority: 'Medium',
        status: 'Open',
        leadAnalyst: 'Analyst',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        scope: [],
        tags: [],
        evidence: [],
        findings: [],
        notes: [],
        auditLog,
      };

      // Authentically valid before tampering
      assert.strictEqual(verifyCaseAuditTrailIntegrity(mockCase).isValid, true);

      // Malicious actor modifies entry 1's details
      auditLog[0].details = 'Tampered log message trying to conceal action';
      const tamperedCheck = verifyCaseAuditTrailIntegrity(mockCase);
      assert.strictEqual(tamperedCheck.isValid, false);
      assert.strictEqual(tamperedCheck.brokenAtIndex, 0);
      assert.ok(tamperedCheck.reason?.includes('tampered'));
    });
  });

  describe('4. AI Grounding Layer & Finding Verification Engine', () => {
    it('verifies claims grounded directly in collected investigation telemetry', () => {
      const context = {
        resolvedIps: ['93.184.216.34'],
        securityHeaders: {
          'content-security-policy': null,
          'strict-transport-security': 'max-age=31536000',
        },
        missingSecurityHeaders: ['Content-Security-Policy'],
        domain: 'example.com',
      };

      const claimText =
        'Observed domain example.com resolving to 93.184.216.34 with missing content-security-policy header.';
      const audit = auditFactualClaimsAgainstTelemetry(claimText, context);

      assert.strictEqual(audit.verificationStatus, 'VERIFIED');
      assert.strictEqual(audit.isFullyGrounded, true);
      assert.strictEqual(audit.groundingScore, 100);
      assert.strictEqual(audit.unsupportedClaims.length, 0);
    });

    it('flags uncorroborated IP addresses and CVE citations as UNKNOWN or INFERRED', () => {
      const context = {
        resolvedIps: ['93.184.216.34'],
        domain: 'example.com',
      };

      // Hallucinated/invented IP and CVE
      const hallucinatedClaim =
        'Host 198.51.100.99 is actively exploited by CVE-2024-99999.';
      const audit = auditFactualClaimsAgainstTelemetry(hallucinatedClaim, context);

      assert.notStrictEqual(audit.verificationStatus, 'VERIFIED');
      assert.strictEqual(audit.isFullyGrounded, false);
      assert.ok(audit.unsupportedClaims.length >= 2);
      assert.ok(audit.unsupportedClaims.some((c) => c.includes('198.51.100.99')));
      assert.ok(audit.unsupportedClaims.some((c) => c.includes('CVE-2024-99999')));
    });

    it('generates defensible detection method and false-positive context for findings', () => {
      const cspFinding = normalizeFinding({
        title: 'Missing Content-Security-Policy Header',
        category: 'Hardening & Security Header',
        targetEntity: 'secure.corp.local',
      });

      assert.strictEqual(cspFinding.verificationStatus, 'VERIFIED');
      assert.strictEqual(cspFinding.detectionMethod, 'RFC 7230 HTTP Response Header Evaluation');
      assert.ok(cspFinding.falsePositiveExplanation?.includes('API'));
      assert.ok(cspFinding.recommendedNextStep?.includes('Content-Security-Policy'));

      const entropyFinding = normalizeFinding({
        title: 'High Shannon Entropy Detected',
        category: 'Binary & Static Forensics',
        targetEntity: 'payload.bin',
      });

      assert.strictEqual(entropyFinding.verificationStatus, 'INFERRED');
      assert.ok(entropyFinding.detectionMethod?.includes('Shannon'));
      assert.ok(entropyFinding.falsePositiveExplanation?.includes('compressed'));
    });
  });

  describe('5. End-to-End Forensics & Safe Parsing Boundaries', () => {
    it('safely handles truncated PCAP buffers without throwing out-of-bounds exceptions', () => {
      // 24-byte PCAP header + truncated packet header
      const buffer = new ArrayBuffer(32);
      const view = new DataView(buffer);
      view.setUint32(0, 0xd4c3b2a1, true); // PCAP magic
      view.setUint32(20, 1, true); // LinkType Ethernet
      view.setUint32(24, 1600000000, true); // ts_sec
      view.setUint32(28, 0, true); // ts_usec

      const result = parsePcapFile(buffer, 'truncated.pcap');
      assert.ok(result);
      assert.strictEqual(result.packets.length, 0);
    });

    it('computes Shannon entropy deterministically between 0.0 and 8.0', () => {
      // Uniform zero bytes = 0.0 entropy
      const zeroBytes = new Uint8Array(256).fill(0);
      assert.strictEqual(computeEntropy(zeroBytes), 0);

      // Uniform random distribution = ~8.0 entropy
      const uniformBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) uniformBytes[i] = i;
      const uniformEntropy = computeEntropy(uniformBytes);
      assert.ok(uniformEntropy >= 7.9 && uniformEntropy <= 8.0);
    });
  });
});
