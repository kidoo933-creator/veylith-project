import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeHashes,
  computeEntropy,
  computeEntropyBlocks,
  detectFileSignature,
  extractPrintableStrings,
} from '../src/utils/forensics.ts';
import {
  parsePcapFile,
  generateSamplePcap,
} from '../src/utils/pcapParser.ts';
import {
  isPrivateOrReservedIP,
  validateHostname,
  parseIPv6Words,
  isPrivateIPv4Octets,
  calculateRiskScore,
  parseSecurityHeaders,
} from '../server/domainEngine.ts';
import { INITIAL_CASES } from '../src/utils/storage.ts';

describe('Veylith Defensible Accuracy Regression Suite', () => {
  // 1. NIST / RFC Cryptographic Hash Test Vectors
  describe('Cryptographic Hash Verification (NIST / RFC Vectors)', () => {
    test('SHA-256 matches NIST vector for empty input', async () => {
      const buffer = new ArrayBuffer(0);
      const hashes = await computeHashes(buffer);
      assert.strictEqual(
        hashes.sha256,
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    test('SHA-256 matches NIST vector for "abc"', async () => {
      const buffer = new TextEncoder().encode('abc').buffer;
      const hashes = await computeHashes(buffer);
      assert.strictEqual(
        hashes.sha256,
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      );
    });

    test('SHA-1 matches standard vector for empty input', async () => {
      const buffer = new ArrayBuffer(0);
      const hashes = await computeHashes(buffer);
      assert.strictEqual(hashes.sha1, 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
    });

    test('SHA-1 matches standard vector for "abc"', async () => {
      const buffer = new TextEncoder().encode('abc').buffer;
      const hashes = await computeHashes(buffer);
      assert.strictEqual(hashes.sha1, 'a9993e364706816aba3e25717850c26c9cd0d89d');
    });

    test('MD5 matches RFC 1321 vector for empty input', async () => {
      const buffer = new ArrayBuffer(0);
      const hashes = await computeHashes(buffer);
      assert.strictEqual(hashes.md5, 'd41d8cd98f00b204e9800998ecf8427e');
    });

    test('MD5 matches RFC 1321 vector for "abc"', async () => {
      const buffer = new TextEncoder().encode('abc').buffer;
      const hashes = await computeHashes(buffer);
      assert.strictEqual(hashes.md5, '900150983cd24fb0d6963f7d28e17f72');
    });
  });

  // 2. Shannon Entropy Mathematical Rigor
  describe('Shannon Entropy Mathematical Rigor', () => {
    test('entropy of uniform single byte is exactly 0.0000', () => {
      const bytes = new Uint8Array(512).fill(0x55);
      assert.strictEqual(computeEntropy(bytes), 0.0);
    });

    test('entropy of 2 equiprobable symbols is exactly 1.0000', () => {
      const bytes = new Uint8Array(1000);
      for (let i = 0; i < 1000; i++) {
        bytes[i] = i % 2 === 0 ? 0x00 : 0xff;
      }
      assert.strictEqual(computeEntropy(bytes), 1.0);
    });

    test('entropy of 4 equiprobable symbols is exactly 2.0000', () => {
      const bytes = new Uint8Array(1000);
      for (let i = 0; i < 1000; i++) {
        bytes[i] = i % 4;
      }
      assert.strictEqual(computeEntropy(bytes), 2.0);
    });

    test('entropy of 16 equiprobable symbols is exactly 4.0000', () => {
      const bytes = new Uint8Array(1600);
      for (let i = 0; i < 1600; i++) {
        bytes[i] = i % 16;
      }
      assert.strictEqual(computeEntropy(bytes), 4.0);
    });

    test('entropy of full 256 byte uniform distribution is exactly 8.0000', () => {
      const bytes = new Uint8Array(256 * 20);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = i % 256;
      }
      assert.strictEqual(computeEntropy(bytes), 8.0);
    });
  });

  // 3. PCAP & PCAPNG Dissection Accuracy
  describe('PCAP & PCAPNG Protocol Dissection', () => {
    test('dissects IPv4 TCP packet and extracts genuine payload snippet', () => {
      const pcapBuffer = generateSamplePcap('c2-beacon');
      const result = parsePcapFile(pcapBuffer, 'c2_beacon.pcap');

      assert.strictEqual(result.format, 'PCAP (Standard)');
      assert.strictEqual(result.totalPackets, 24);
      assert.ok(result.packets.length > 0);

      const first = result.packets[0];
      assert.strictEqual(first.protocol, 'TCP');
      assert.strictEqual(first.srcIp, '192.168.1.105');
      assert.strictEqual(first.dstIp, '198.51.100.42');
      assert.strictEqual(first.dstPort, 443);
      assert.ok(first.info.includes('TLS'));
      assert.ok(first.info.includes('Application Data Encrypted Beacon'));
    });

    test('dissects IPv6 datagram and extracts transport information', () => {
      // Build a minimal synthetic PCAP containing an IPv6 TCP frame
      const frame = new Uint8Array(14 + 40 + 20);
      // Ethernet header: EtherType 0x86dd (IPv6)
      frame[12] = 0x86;
      frame[13] = 0xdd;
      // IPv6 header: Version 6, nextHeader = 6 (TCP)
      frame[14] = 0x60;
      frame[14 + 6] = 6; // nextHeader TCP
      // Source IPv6: 2001:db8::1
      frame[22] = 0x20;
      frame[23] = 0x01;
      frame[24] = 0x0d;
      frame[25] = 0xb8;
      frame[37] = 0x01;
      // Destination IPv6: 2001:db8::2
      frame[38] = 0x20;
      frame[39] = 0x01;
      frame[40] = 0x0d;
      frame[41] = 0xb8;
      frame[53] = 0x02;
      // TCP Header at offset 54: srcPort 443, dstPort 54321, SYN+ACK
      frame[54] = 0x01;
      frame[55] = 0xbb; // 443
      frame[56] = 0xd4;
      frame[57] = 0x31; // 54321
      frame[54 + 12] = 5 << 4; // Data offset 5
      frame[54 + 13] = 0x12; // SYN, ACK

      // Wrap in PCAP buffer
      const buf = new ArrayBuffer(24 + 16 + frame.length);
      const dv = new DataView(buf);
      const outBytes = new Uint8Array(buf);
      outBytes[0] = 0xd4;
      outBytes[1] = 0xc3;
      outBytes[2] = 0xb2;
      outBytes[3] = 0xa1;
      dv.setUint16(4, 2, true);
      dv.setUint16(6, 4, true);
      dv.setUint32(16, 65535, true);
      dv.setUint32(20, 1, true); // Ethernet

      dv.setUint32(24, 1700000000, true);
      dv.setUint32(28, 0, true);
      dv.setUint32(32, frame.length, true);
      dv.setUint32(36, frame.length, true);
      new Uint8Array(buf).set(frame, 40);

      const parsed = parsePcapFile(buf, 'ipv6_sample.pcap');
      assert.strictEqual(parsed.totalPackets, 1);
      const pkt = parsed.packets[0];
      assert.strictEqual(pkt.protocol, 'TCP');
      assert.strictEqual(pkt.appProtocol, 'TLS');
      assert.strictEqual(pkt.srcPort, 443);
      assert.strictEqual(pkt.dstPort, 54321);
      assert.ok(pkt.srcIp?.includes('2001:db8:'));
      assert.ok(pkt.dstIp?.includes('2001:db8:'));
    });

    test('parses PCAPNG Enhanced Packet Blocks with accurate timestamps & conversations', () => {
      // Build a synthetic PCAPNG with 1 SHB and 2 EPBs
      const epbPayload = new Uint8Array(14 + 20 + 20);
      epbPayload[12] = 0x08;
      epbPayload[13] = 0x00;
      epbPayload[14] = 0x45;
      epbPayload[23] = 6;
      epbPayload[26] = 10;
      epbPayload[27] = 0;
      epbPayload[28] = 0;
      epbPayload[29] = 1; // 10.0.0.1
      epbPayload[30] = 10;
      epbPayload[31] = 0;
      epbPayload[32] = 0;
      epbPayload[33] = 2; // 10.0.0.2
      epbPayload[34] = 0x00;
      epbPayload[35] = 53;
      epbPayload[36] = 0x1f;
      epbPayload[37] = 0x90; // 8080
      epbPayload[46] = 5 << 4;

      const epbLen = 32 + epbPayload.length;
      const shbLen = 28;
      const totalLen = shbLen + epbLen * 2;
      const buf = new ArrayBuffer(totalLen);
      const dv = new DataView(buf);

      // Section Header Block (SHB)
      dv.setUint32(0, 0x0a0d0d0a, true);
      dv.setUint32(4, shbLen, true);
      dv.setUint32(8, 0x1a2b3c4d, true); // Byte-order magic
      dv.setUint16(12, 1, true);
      dv.setUint16(14, 0, true);
      dv.setUint32(shbLen - 4, shbLen, true);

      // EPB #1 at offset 28
      let off = shbLen;
      dv.setUint32(off, 0x00000006, true);
      dv.setUint32(off + 4, epbLen, true);
      dv.setUint32(off + 8, 0, true); // interface 0
      dv.setUint32(off + 12, 0, true); // ts high
      dv.setUint32(off + 16, 1700000000, true); // ts low (microsecs)
      dv.setUint32(off + 20, epbPayload.length, true);
      dv.setUint32(off + 24, epbPayload.length, true);
      new Uint8Array(buf).set(epbPayload, off + 28);
      dv.setUint32(off + epbLen - 4, epbLen, true);

      // EPB #2
      off += epbLen;
      dv.setUint32(off, 0x00000006, true);
      dv.setUint32(off + 4, epbLen, true);
      dv.setUint32(off + 8, 0, true);
      dv.setUint32(off + 12, 0, true);
      dv.setUint32(off + 16, 1705000000, true);
      dv.setUint32(off + 20, epbPayload.length, true);
      dv.setUint32(off + 24, epbPayload.length, true);
      new Uint8Array(buf).set(epbPayload, off + 28);
      dv.setUint32(off + epbLen - 4, epbLen, true);

      const parsed = parsePcapFile(buf, 'test_ng.pcapng');
      assert.strictEqual(parsed.format, 'PCAPNG (Next Gen)');
      assert.strictEqual(parsed.totalPackets, 2);
      assert.strictEqual(parsed.topConversations.length, 1);
      assert.strictEqual(parsed.topConversations[0].packets, 2);
      assert.ok(parsed.durationSeconds >= 0);
    });
  });

  // 4. SSRF & Hostname Normalization Edge Cases
  describe('SSRF Protection & Hostname Normalization', () => {
    test('blocks hex-encoded loopback (0x7f000001)', () => {
      const check = validateHostname('0x7f000001');
      assert.strictEqual(check.isValid, false);
      assert.ok(check.error?.toLowerCase().includes('loopback'));
    });

    test('blocks integer loopback (2130706433)', () => {
      const check = validateHostname('2130706433');
      assert.strictEqual(check.isValid, false);
      assert.ok(check.error?.toLowerCase().includes('loopback'));
    });

    test('blocks dotted octal loopback (0177.0.0.1)', () => {
      const check = validateHostname('0177.0.0.1');
      assert.strictEqual(check.isValid, false);
      assert.ok(check.error?.toLowerCase().includes('loopback'));
    });

    test('blocks IPv6 bracketed loopback ([::1])', () => {
      const check = validateHostname('[::1]');
      assert.strictEqual(check.isValid, false);
      assert.ok(check.error?.toLowerCase().includes('loopback'));
    });

    test('blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)', () => {
      const check = isPrivateOrReservedIP('::ffff:127.0.0.1');
      assert.strictEqual(check.isBlocked, true);
      assert.ok(check.reason?.toLowerCase().includes('loopback'));
    });

    test('blocks IPv4-compatible IPv6 loopback (::127.0.0.1)', () => {
      const check = isPrivateOrReservedIP('::127.0.0.1');
      assert.strictEqual(check.isBlocked, true);
    });

    test('blocks 6to4 private IPv4 encapsulation (2002:0a00:0001::)', () => {
      const check = isPrivateOrReservedIP('2002:0a00:0001::');
      assert.strictEqual(check.isBlocked, true);
    });

    test('blocks IPv6 Discard prefix (100::1)', () => {
      const check = isPrivateOrReservedIP('100::1');
      assert.strictEqual(check.isBlocked, true);
    });

    test('normalizes complex URL input into clean public FQDN', () => {
      const check = validateHostname('https://portal.secure-subdomain.com:8443/login?redirect=1');
      assert.strictEqual(check.isValid, true);
      assert.strictEqual(check.normalized, 'portal.secure-subdomain.com');
    });

    test('strips trailing FQDN dot safely', () => {
      const check = validateHostname('example.com.');
      assert.strictEqual(check.isValid, true);
      assert.strictEqual(check.normalized, 'example.com');
    });
  });

  // 5. Evidence Correlation Grounding & Defensible Integrity
  describe('Evidence Correlation Grounding', () => {
    test('initial cases have strictly non-empty IDs, scopes, and defensible audit entries', () => {
      for (const cs of INITIAL_CASES) {
        assert.ok(cs.id.startsWith('#VY-'));
        assert.ok(cs.scope.length > 0);
        assert.ok(cs.auditLog.length > 0);
        for (const ev of cs.evidence) {
          assert.strictEqual(ev.caseId, cs.id);
          assert.ok(['Observed', 'Confirmed', 'Inferred', 'Potential', 'Unknown'].includes(ev.confidence));
        }
        for (const finding of cs.findings) {
          assert.ok(finding.evidenceIds.length > 0);
          for (const evId of finding.evidenceIds) {
            assert.ok(cs.evidence.some((e) => e.id === evId), `Finding ${finding.id} cites non-existent evidence ${evId}`);
          }
        }
      }
    });

    test('deterministic risk score never conflates missing hardening header with exploit', () => {
      const result = calculateRiskScore({
        isTlsValid: true,
        missingHsts: true,
        missingCsp: true,
        dnsFailed: false,
        dataCompleteness: 100,
      });

      assert.strictEqual(result.score, 20); // 10 for HSTS + 10 for CSP
      assert.strictEqual(result.level, 'Low');
      assert.ok(result.limitations.some((l) => l.includes('not independently prove technical exploitability')));

      const headerObs = parseSecurityHeaders({ 'x-frame-options': 'DENY' }, true);
      const hsts = headerObs.headerObservations.find((h) => h.header.includes('HSTS'));
      assert.strictEqual(hsts?.isProofOfExploit, false);
      assert.strictEqual(hsts?.status, 'Missing');
    });
  });
});
