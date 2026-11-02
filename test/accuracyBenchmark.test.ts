import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { parsePcapFile, getLinkTypeName } from '../src/utils/pcapParser.ts';
import { computeEntropy, detectFileSignature } from '../src/utils/forensics.ts';
import {
  buildEvidenceGraph,
  hasExactIpMatch,
  hasExactDomainMatch,
  hasExactHashMatch,
  hasExactCveMatch,
} from '../src/utils/evidenceCorrelation.ts';
import { calculateRiskScore } from '../server/domainEngine.ts';
import { CaseRecord } from '../src/types/index.ts';

/**
 * Repeatable Accuracy & Ground-Truth Verification Benchmark
 * Reports Expected vs Actual for all core forensic primitives.
 */
describe('Veylith Forensics — Ground-Truth Accuracy Benchmark', () => {
  // Helper to log structured benchmark comparison
  function assertBenchmark<T>(metric: string, expected: T, actual: T) {
    // Structured equality assertion
    assert.deepStrictEqual(actual, expected, `Benchmark check failed for ${metric}`);
  }

  // 1. SHA-256 Cryptographic Integrity (NIST FIPS 180-4 Vectors)
  describe('1. SHA-256 Hashing Accuracy (Expected vs Actual)', () => {
    test('NIST vector 1: "abc"', async () => {
      const input = Buffer.from('abc', 'utf-8');
      const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const actual = crypto.createHash('sha256').update(input).digest('hex');
      assertBenchmark('SHA256("abc")', expected, actual);
    });

    test('NIST vector 2: empty buffer ""', async () => {
      const input = Buffer.alloc(0);
      const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const actual = crypto.createHash('sha256').update(input).digest('hex');
      assertBenchmark('SHA256("")', expected, actual);
    });
  });

  // 2. File Signature Detection Accuracy
  describe('2. File Signature Detection (Expected vs Actual)', () => {
    test('detects PE Windows Executable (MZ)', () => {
      const pe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...new Array(60).fill(0)]);
      const sig = detectFileSignature(pe);
      assertBenchmark('PE Signature', 'PE Executable (Windows Binary / DLL / Sys)', sig.detectedFormat);
    });

    test('detects Linux ELF Binary (\\x7fELF)', () => {
      const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);
      const sig = detectFileSignature(elf);
      assertBenchmark('ELF Signature', 'ELF Binary (64-bit Linux Executable / Shared Object)', sig.detectedFormat);
    });

    test('detects PDF Document (%PDF-)', () => {
      const pdf = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF', 'utf-8');
      const sig = detectFileSignature(new Uint8Array(pdf));
      assertBenchmark('PDF Signature', 'PDF Document (Adobe Portable Document v1.7)', sig.detectedFormat);
    });

    test('detects ZIP Archive (PK\\x03\\x04)', () => {
      const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(60).fill(0)]);
      const sig = detectFileSignature(zip);
      assertBenchmark('ZIP Signature', 'ZIP Archive / Container (PKZIP, Android APK, JAR, DOCX, XLSX)', sig.detectedFormat);
    });
  });

  // 3. Shannon Entropy Calculation (Expected vs Actual)
  describe('3. Shannon Entropy Bounds (Expected vs Actual)', () => {
    test('Zero entropy for constant byte stream', () => {
      const zeros = new Uint8Array(1024).fill(0xaa);
      const actual = computeEntropy(zeros);
      assertBenchmark('Constant Byte Entropy', 0.0, actual);
    });

    test('Maximum theoretical entropy (8.0000) for uniform 256-symbol distribution', () => {
      const uniform = new Uint8Array(256 * 10);
      for (let i = 0; i < uniform.length; i++) {
        uniform[i] = i % 256;
      }
      const actual = computeEntropy(uniform);
      assertBenchmark('Uniform 256-byte Entropy', 8.0, actual);
    });
  });

  // 4. PCAPNG Timestamp Resolution & IDB Parsing
  describe('4. PCAPNG Timestamp Resolution & IDB Options', () => {
    // Helper to generate a compliant synthetic PCAPNG block
    function buildPcapNgWithIdb(
      tsResolOption?: { isBinary: boolean; value: number },
      tsOffsetOption?: number,
      epbTicks?: { high: number; low: number },
      epbInterfaceId = 0
    ): ArrayBuffer {
      const shbLen = 28;
      // Build IDB
      let idbOptionsLen = 0;
      if (tsResolOption) idbOptionsLen += 8; // 4 header + 1 byte + 3 pad
      if (tsOffsetOption !== undefined) idbOptionsLen += 12; // 4 header + 8 bytes
      if (idbOptionsLen > 0) idbOptionsLen += 4; // opt_endofopt (code 0, len 0)

      const idbLen = 16 + idbOptionsLen + 4; // 16 header + options + 4 trailing len
      const epbPayload = new Uint8Array([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
        0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2, 0x1f, 0x90, 0x00, 53, 0, 0, 0, 0,
        0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]);
      const epbLen = 32 + epbPayload.length;
      const totalLen = shbLen + idbLen + epbLen;
      const buf = new ArrayBuffer(totalLen);
      const dv = new DataView(buf);

      // 1. SHB
      dv.setUint32(0, 0x0a0d0d0a, true);
      dv.setUint32(4, shbLen, true);
      dv.setUint32(8, 0x1a2b3c4d, true); // Little endian
      dv.setUint16(12, 1, true);
      dv.setUint16(14, 0, true);
      dv.setUint32(shbLen - 4, shbLen, true);

      // 2. IDB at offset shbLen
      let off = shbLen;
      dv.setUint32(off, 0x00000001, true);
      dv.setUint32(off + 4, idbLen, true);
      dv.setUint16(off + 8, 1, true); // LinkType = 1 (Ethernet)
      dv.setUint16(off + 10, 0, true);
      dv.setUint32(off + 12, 65535, true); // SnapLen

      let optOff = off + 16;
      if (tsResolOption) {
        dv.setUint16(optOff, 9, true); // if_tsresol
        dv.setUint16(optOff + 2, 1, true); // len = 1
        const rawByte = (tsResolOption.isBinary ? 0x80 : 0x00) | (tsResolOption.value & 0x7f);
        dv.setUint8(optOff + 4, rawByte);
        optOff += 8; // 4 + 1 + 3 pad
      }
      if (tsOffsetOption !== undefined) {
        dv.setUint16(optOff, 14, true); // if_tsoffset
        dv.setUint16(optOff + 2, 8, true); // len = 8
        dv.setBigInt64(optOff + 4, BigInt(tsOffsetOption), true);
        optOff += 12; // 4 + 8
      }
      if (idbOptionsLen > 0) {
        dv.setUint16(optOff, 0, true); // opt_endofopt
        dv.setUint16(optOff + 2, 0, true);
      }
      dv.setUint32(off + idbLen - 4, idbLen, true);

      // 3. EPB at offset off + idbLen
      off += idbLen;
      dv.setUint32(off, 0x00000006, true);
      dv.setUint32(off + 4, epbLen, true);
      dv.setUint32(off + 8, epbInterfaceId, true);
      dv.setUint32(off + 12, epbTicks?.high ?? 0, true);
      dv.setUint32(off + 16, epbTicks?.low ?? 0, true);
      dv.setUint32(off + 20, epbPayload.length, true);
      dv.setUint32(off + 24, epbPayload.length, true);
      new Uint8Array(buf).set(epbPayload, off + 28);
      dv.setUint32(off + epbLen - 4, epbLen, true);

      return buf;
    }

    test('Microsecond Decimal Resolution (default 10^-6s)', () => {
      // 1714000000.250000 seconds = 1714000000250000n ticks
      const ticks = 1714000000250000n;
      const buf = buildPcapNgWithIdb(
        { isBinary: false, value: 6 },
        0,
        { high: Number(ticks >> 32n), low: Number(ticks & 0xffffffffn) }
      );
      const res = parsePcapFile(buf, 'microsecond.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      assertBenchmark('Microsecond timestamp ms', 1714000000250, pkt.timestamp);
      assert.strictEqual(pkt.timestampUnreliable, false);
      assert.strictEqual(pkt.interfaceId, 0);
    });

    test('Nanosecond Decimal Resolution (10^-9s)', () => {
      // 1714000000.123456789 seconds = 1714000000123456789n ticks
      const ticks = 1714000000123456789n;
      const buf = buildPcapNgWithIdb(
        { isBinary: false, value: 9 },
        0,
        { high: Number(ticks >> 32n), low: Number(ticks & 0xffffffffn) }
      );
      const res = parsePcapFile(buf, 'nanosecond.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      // Expected ms: 1714000000123
      assertBenchmark('Nanosecond timestamp ms', 1714000000123, pkt.timestamp);
      assert.strictEqual(pkt.timestampUnreliable, false);
      assert.strictEqual(res.interfaces?.[0].tsResolution, '10^-9 seconds');
    });

    test('Binary Negative Power-of-2 Resolution (2^-10 = 1/1024s)', () => {
      // 2048 ticks at 1/1024s = exactly 2.0 seconds (2000 ms)
      const buf = buildPcapNgWithIdb(
        { isBinary: true, value: 10 },
        0,
        { high: 0, low: 2048 }
      );
      const res = parsePcapFile(buf, 'binary_res.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      assertBenchmark('Binary 2^-10 timestamp ms', 2000, pkt.timestamp);
      assert.strictEqual(res.interfaces?.[0].isBinaryResolution, true);
      assert.strictEqual(res.interfaces?.[0].tsResolution, '2^-10 seconds');
    });

    test('Timestamp Offset (if_tsoffset = 1700000000s + 5.0s ticks)', () => {
      // Offset 1,700,000,000s + 5,000,000 microsecond ticks (5s) = 1,700,000,005s (1700000005000 ms)
      const buf = buildPcapNgWithIdb(
        { isBinary: false, value: 6 },
        1700000000,
        { high: 0, low: 5000000 }
      );
      const res = parsePcapFile(buf, 'offset.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      assertBenchmark('Offset timestamp ms', 1700000005000, pkt.timestamp);
      assert.strictEqual(res.interfaces?.[0].tsOffsetSeconds, 1700000000);
    });

    test('Negative case: Unmatched Interface ID flags timestamp limitation and never returns Date.now()', () => {
      // IDB defines interface 0, EPB specifies interface 7
      const buf = buildPcapNgWithIdb(
        { isBinary: false, value: 6 },
        0,
        { high: 0, low: 5000 },
        7
      );
      const res = parsePcapFile(buf, 'unmatched_interface.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      assert.strictEqual(pkt.timestampUnreliable, true);
      assert.ok(pkt.timeStr.includes('UNVERIFIED'));
      assert.ok(pkt.timestampLimitation?.includes('only 1 interface(s) exist'));
      assert.strictEqual(pkt.timestamp, 0); // Must never be Date.now()
    });

    test('Negative case: Zero ticks recorded in EPB flags missing timestamp explicitly', () => {
      const buf = buildPcapNgWithIdb(
        { isBinary: false, value: 6 },
        0,
        { high: 0, low: 0 },
        0
      );
      const res = parsePcapFile(buf, 'zero_ticks.pcapng');
      assert.strictEqual(res.totalPackets, 1);
      const pkt = res.packets[0];
      assert.strictEqual(pkt.timestampUnreliable, true);
      assert.ok(pkt.timeStr.includes('UNVERIFIED'));
      assert.strictEqual(pkt.timestamp, 0);
    });
  });

  // 5. Evidence Correlation Engine & Boundary Validation
  describe('5. Evidence Correlation Ground-Truth & False-Positive Elimination', () => {
    test('Exact IP matching prevents substring collisions', () => {
      // Positive: exact IP in text
      assert.strictEqual(hasExactIpMatch('Resolved to 10.0.0.1 on port 80', '10.0.0.1'), true);
      assert.strictEqual(hasExactIpMatch('10.0.0.1:443', '10.0.0.1'), true);

      // Negative: substring inside longer IP (10.0.0.1 inside 10.0.0.15 or 110.0.0.1)
      assert.strictEqual(hasExactIpMatch('Resolved to 10.0.0.15 on port 80', '10.0.0.1'), false);
      assert.strictEqual(hasExactIpMatch('Connect 110.0.0.1:443', '10.0.0.1'), false);
    });

    test('Exact Domain matching prevents substring collisions', () => {
      // Positive: exact whole domain
      assert.strictEqual(hasExactDomainMatch('Connecting to evil.com over TLS', 'evil.com'), true);
      assert.strictEqual(hasExactDomainMatch('https://evil.com/payload', 'evil.com'), true);

      // Negative: substring collisions (badevil.com, evil.company.org)
      assert.strictEqual(hasExactDomainMatch('Connecting to badevil.com over TLS', 'evil.com'), false);
      assert.strictEqual(hasExactDomainMatch('Visiting evil.company.org', 'evil.com'), false);
    });

    test('Exact Hash matching prevents prefix collisions', () => {
      const sha256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const md5 = 'ba7816bf8f01cfea414140de5dae2223';
      // Positive: exact SHA-256
      assert.strictEqual(hasExactHashMatch(`Sample hash: ${sha256}`, sha256), true);

      // Negative: md5 prefix of sha256 should NOT match inside the sha256 hex string
      assert.strictEqual(hasExactHashMatch(`Sample hash: ${sha256}`, md5), false);
    });

    test('Exact CVE matching prevents identifier collisions', () => {
      assert.strictEqual(hasExactCveMatch('Exploits CVE-2023-1234 in wild', 'CVE-2023-1234'), true);
      assert.strictEqual(hasExactCveMatch('Exploits CVE-2023-12345 in wild', 'CVE-2023-1234'), false);
    });

    test('Graph Construction: Unrelated entities in same case have ZERO direct edges', () => {
      const mockCase: CaseRecord = {
        id: 'CASE-001',
        title: 'Operation Zero False Positives',
        description: 'Test case with unrelated entities',
        priority: 'High',
        status: 'Open',
        leadAnalyst: 'SecAnalyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: ['evil.com', '192.168.1.1'],
        tags: [],
        evidence: [
          {
            id: 'ev-1',
            name: 'evil.com',
            type: 'domain',
            value: 'evil.com',
            confidence: 'Confirmed',
            source: 'DNS Recon',
            timestamp: '2025-01-01T00:00:00Z',
            notes: 'Resolves to 93.184.216.34',
          },
          {
            id: 'ev-2',
            name: '192.168.1.1',
            type: 'ip',
            value: '192.168.1.1',
            confidence: 'Observed',
            source: 'NetFlow',
            timestamp: '2025-01-01T00:00:00Z',
            notes: 'Internal router gateway on VLAN 10',
          },
        ],
        findings: [],
        notes: [],
        auditLog: [],
      };

      const { nodes, edges } = buildEvidenceGraph([mockCase]);

      // There are 3 nodes: Case, ev-1, ev-2
      assert.strictEqual(nodes.length, 3);

      // Case -> ev-1 (scope link) and Case -> ev-2 (scope link) = 2 edges
      assert.strictEqual(edges.length, 2);

      // Direct edge between ev-1 and ev-2 MUST NOT EXIST
      const directCrossEdge = edges.find(
        (e) => (e.source.includes('ev-1') && e.target.includes('ev-2')) ||
               (e.source.includes('ev-2') && e.target.includes('ev-1'))
      );
      assertBenchmark('Direct Cross Edge Between Unrelated Entities', undefined, directCrossEdge);
    });

    test('Graph Construction: Co-cited evidence items in a Finding are connected with isInferred=true', () => {
      const mockCase: CaseRecord = {
        id: 'CASE-002',
        title: 'C2 Correlated Finding',
        description: 'Finding cites file and domain together',
        priority: 'Critical',
        status: 'Open',
        leadAnalyst: 'SecAnalyst',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
        scope: [],
        tags: [],
        evidence: [
          {
            id: 'ev-file',
            name: 'dropper.exe',
            type: 'file',
            value: 'dropper.exe',
            confidence: 'Confirmed',
            source: 'EDR',
            timestamp: '2025-01-01T01:00:00Z',
          },
          {
            id: 'ev-dom',
            name: 'c2-beacon.org',
            type: 'domain',
            value: 'c2-beacon.org',
            confidence: 'Confirmed',
            source: 'DNS',
            timestamp: '2025-01-01T01:00:00Z',
          },
        ],
        findings: [
          {
            id: 'FIND-42',
            title: 'Dropper initiates C2 communication',
            category: 'Binary & Static Forensics',
            targetEntity: 'dropper.exe',
            observedResult: 'dropper.exe established beacon to c2-beacon.org',
            description: 'dropper.exe established beacon to c2-beacon.org',
            severity: 'Critical',
            confidence: 'Confirmed',
            status: 'Unresolved',
            sourceTool: 'Behavioral Sandbox',
            collectedAt: '2025-01-01T01:05:00Z',
            relevantInput: 'dropper.exe',
            evidenceIds: ['ev-file', 'ev-dom'],
          },
        ],
        notes: [],
        auditLog: [],
      };

      const { edges } = buildEvidenceGraph([mockCase]);

      // Direct citations from Finding to each evidence item (2 edges, isInferred: false)
      const findingEdges = edges.filter((e) => e.source.includes('FIND-42') && !e.isInferred);
      assert.strictEqual(findingEdges.length, 2);
      assert.strictEqual(findingEdges[0].sourceFindingId, 'FIND-42');
      assert.strictEqual(findingEdges[0].isInferred, false);

      // Inferred cross-edge between ev-file and ev-dom
      const crossEdge = edges.find((e) => e.isInferred);
      assert.ok(crossEdge, 'Cross-edge must be created for jointly cited evidence');
      assert.strictEqual(crossEdge.isInferred, true);
      assert.strictEqual(crossEdge.sourceFindingId, 'FIND-42');
      assert.strictEqual(crossEdge.provenance, 'Behavioral Sandbox');
      assert.ok(crossEdge.inferredReason?.includes('FIND-42'));
    });
  });

  // 6. Domain Risk Score Engine Accuracy
  describe('6. Domain Risk Score Engine (Expected vs Actual)', () => {
    test('Calculates zero risk for fully secure, verified domain', () => {
      const res = calculateRiskScore({
        isTlsValid: true,
        daysRemaining: 180,
        missingHsts: false,
        missingCsp: false,
        dnsFailed: false,
        dataCompleteness: 100,
      });

      assertBenchmark('Baseline Secure Domain Score', 0, res.score);
      assertBenchmark('Baseline Risk Level', 'Low', res.level);
      assertBenchmark('Baseline Risk Factors Count', 0, res.factors.length);
    });

    test('Penalizes TLS certificate invalidity with High risk weight (+25)', () => {
      const res = calculateRiskScore({
        isTlsValid: false,
        tlsError: 'CERT_HAS_EXPIRED',
        daysRemaining: 0,
        missingHsts: false,
        missingCsp: false,
        dnsFailed: false,
        dataCompleteness: 100,
      });

      assert.ok(res.score >= 25, `Score must reflect invalid TLS certificate (actual: ${res.score})`);
      assert.ok(res.factors.some((f) => f.includes('Invalid/Untrusted TLS') || f.includes('CERT_HAS_EXPIRED')));
    });
  });
});
