import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parsePcapFile } from '../src/utils/pcapParser.ts';

describe('Veylith PCAP Lab Parser Engine', () => {
  // Helper to build a valid synthetic 24-byte PCAP header
  function createPcapHeader(isLittleEndian = true, linkType = 1): Uint8Array {
    const buffer = new ArrayBuffer(24);
    const view = new DataView(buffer);
    view.setUint32(0, 0xa1b2c3d4, isLittleEndian);
    view.setUint16(4, 2, isLittleEndian); // major
    view.setUint16(6, 4, isLittleEndian); // minor
    view.setInt32(8, 0, isLittleEndian); // thiszone
    view.setUint32(12, 0, isLittleEndian); // sigfigs
    view.setUint32(16, 65535, isLittleEndian); // snaplen
    view.setUint32(20, linkType, isLittleEndian); // network / linktype (1 = Ethernet)
    return new Uint8Array(buffer);
  }

  // Helper to create an Ethernet + IPv4 + TCP SYN frame (54 bytes)
  function createTcpPacket(srcIp = [192, 168, 1, 10], dstIp = [93, 184, 216, 34], srcPort = 44444, dstPort = 443): Uint8Array {
    const frame = new Uint8Array(54);
    // Ethernet II (14 bytes)
    frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0); // dst MAC
    frame.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6); // src MAC
    frame[12] = 0x08;
    frame[13] = 0x00; // EtherType = IPv4 (0x0800)

    // IPv4 header (20 bytes, offset 14)
    frame[14] = 0x45; // Version 4, IHL 5 (20 bytes)
    frame[15] = 0x00;
    frame[23] = 0x06; // Protocol = TCP (6)
    frame.set(srcIp, 26);
    frame.set(dstIp, 30);

    // TCP header (20 bytes, offset 34)
    frame[34] = (srcPort >> 8) & 0xff;
    frame[35] = srcPort & 0xff;
    frame[36] = (dstPort >> 8) & 0xff;
    frame[37] = dstPort & 0xff;
    frame[46] = 0x50; // Data offset 5 (20 bytes)
    frame[47] = 0x02; // Flags: SYN (0x02)

    return frame;
  }

  test('rejects buffers smaller than 24-byte PCAP header threshold', () => {
    const tiny = new Uint8Array(16);
    assert.throws(
      () => parsePcapFile(tiny.buffer, 'corrupt.pcap'),
      /minimum 24 bytes required/i
    );
  });

  test('parses empty PCAP file containing only 24-byte header without errors', () => {
    const header = createPcapHeader(true, 1);
    const result = parsePcapFile(header.buffer, 'empty.pcap');
    assert.strictEqual(result.totalPackets, 0);
    assert.strictEqual(result.totalBytes, 0);
    assert.strictEqual(result.format, 'PCAP (Standard)');
    assert.strictEqual(result.linkTypeName, 'Ethernet (10Mb/100Mb/1Gb/10Gb)');
  });

  test('parses packets, protocols, and conversations from valid PCAP frame', () => {
    const header = createPcapHeader(true, 1);
    const packet = createTcpPacket([10, 0, 0, 15], [198, 51, 100, 1], 51234, 80);

    // Build PCAP packet header (16 bytes)
    const pcapPktHeader = new ArrayBuffer(16);
    const pktView = new DataView(pcapPktHeader);
    pktView.setUint32(0, 1714000000, true); // ts_sec
    pktView.setUint32(4, 500000, true); // ts_usec
    pktView.setUint32(8, packet.length, true); // incl_len
    pktView.setUint32(12, packet.length, true); // orig_len

    const fullPcap = new Uint8Array(header.length + 16 + packet.length);
    fullPcap.set(header, 0);
    fullPcap.set(new Uint8Array(pcapPktHeader), header.length);
    fullPcap.set(packet, header.length + 16);

    const result = parsePcapFile(fullPcap.buffer, 'sample.pcap');
    assert.strictEqual(result.totalPackets, 1);
    assert.strictEqual(result.protocols['TCP'], 1);
    assert.strictEqual(result.packets[0].srcIp, '10.0.0.15');
    assert.strictEqual(result.packets[0].dstIp, '198.51.100.1');
    assert.strictEqual(result.packets[0].srcPort, 51234);
    assert.strictEqual(result.packets[0].dstPort, 80);
    assert.ok(result.packets[0].info.includes('[SYN]'));

    // Verify conversation pairing
    assert.strictEqual(result.topConversations.length, 1);
    assert.strictEqual(result.topConversations[0].packets, 1);
  });

  test('detects and flags truncated packet captures', () => {
    const header = createPcapHeader(true, 1);

    // Header says packet is 100 bytes, but we only supply 20 bytes
    const pcapPktHeader = new ArrayBuffer(16);
    const pktView = new DataView(pcapPktHeader);
    pktView.setUint32(0, 1714000000, true);
    pktView.setUint32(4, 0, true);
    pktView.setUint32(8, 100, true); // claims 100 bytes
    pktView.setUint32(12, 100, true);

    const truncatedBytes = new Uint8Array(header.length + 16 + 20); // only 20 bytes present!
    truncatedBytes.set(header, 0);
    truncatedBytes.set(new Uint8Array(pcapPktHeader), header.length);

    const result = parsePcapFile(truncatedBytes.buffer, 'truncated.pcap');
    assert.strictEqual(result.truncatedPacketsCount, 1);
    assert.ok(result.anomalies.some((a) => a.title.includes('Truncated Packet Capture')));
  });

  test('detects and flags unsupported/non-Ethernet datalink types', () => {
    // LinkType 113 = Linux Cooked Capture (SLL)
    const header = createPcapHeader(true, 113);
    const result = parsePcapFile(header.buffer, 'linux_sll.pcap');
    assert.strictEqual(result.unsupportedLinkType, true);
    assert.strictEqual(result.linkType, 113);
    assert.ok(result.anomalies.some((a) => a.title.includes('Non-Ethernet Datalink Type')));
  });
});
