import { PcapAnalysisResult, PcapInterfaceInfo, PcapPacket, SeverityLevel } from '../types';

export function getLinkTypeName(lt: number): string {
  if (lt === 1) return 'Ethernet (10Mb/100Mb/1Gb/10Gb)';
  if (lt === 0) return 'Null / Loopback (0)';
  if (lt === 101) return 'Raw IP (101)';
  if (lt === 113) return 'Linux Cooked Capture v1 (SLL)';
  if (lt === 276) return 'Linux Cooked Capture v2 (SLL2)';
  return `LinkType ${lt}`;
}

export const MAX_PCAP_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB safety ceiling against memory exhaustion

export function parsePcapFile(buffer: ArrayBuffer | ArrayBufferLike, fileName: string): PcapAnalysisResult {
  const bytes = new Uint8Array(buffer);
  const dataView = new DataView(buffer);

  if (bytes.length > MAX_PCAP_SIZE_BYTES) {
    throw new Error(`File exceeds maximum permitted PCAP analysis size of 50 MB (${(bytes.length / (1024 * 1024)).toFixed(1)} MB provided).`);
  }

  if (bytes.length < 24) {
    throw new Error('File too small to be a valid PCAP file (minimum 24 bytes required).');
  }

  // Detect PCAP format & endianness
  let isLittleEndian = true;
  let isPcapNg = false;
  let magic = dataView.getUint32(0, false);

  if (magic === 0xa1b2c3d4) {
    isLittleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    isLittleEndian = true;
  } else if (magic === 0x4d3cb2a1 || magic === 0xa1b23c4d) {
    // Nanosecond resolution
    isLittleEndian = magic === 0x4d3cb2a1;
  } else if (magic === 0x0a0d0d0a) {
    // PCAPNG Section Header Block
    isPcapNg = true;
    isLittleEndian = true;
  } else {
    throw new Error(`Invalid PCAP magic number (0x${magic.toString(16)}). Supported formats: PCAP, PCAPNG.`);
  }

  const packets: PcapPacket[] = [];
  const protocolCounts: Record<string, number> = {
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    ARP: 0,
    DNS: 0,
    HTTP: 0,
    TLS: 0,
    Other: 0,
  };

  const conversationsMap = new Map<string, { pair: string; src: string; dst: string; proto: string; packets: number; bytes: number }>();
  let totalBytes = 0;
  let minTime = Infinity;
  let maxTime = -Infinity;

  const anomalies: { severity: SeverityLevel; title: string; description: string; evidence: string }[] = [];
  let synCount = 0;
  let totalTcp = 0;
  const dnsQueries: string[] = [];
  let cleartextCredFound = false;

  let linkType = 1;
  let linkTypeName = 'Ethernet (1)';
  let unsupportedLinkType = false;
  let truncatedPacketsCount = 0;
  let pcapNgInterfaces: PcapInterfaceInfo[] | undefined;

  if (!isPcapNg) {
    // Extract Datalink Type from PCAP global header (offset 20)
    linkType = dataView.getUint32(20, isLittleEndian);
    if (linkType === 1) linkTypeName = 'Ethernet (10Mb/100Mb/1Gb/10Gb)';
    else if (linkType === 0) linkTypeName = 'Null / Loopback (0)';
    else if (linkType === 101) linkTypeName = 'Raw IP (101)';
    else if (linkType === 113) linkTypeName = 'Linux Cooked Capture v1 (SLL)';
    else if (linkType === 276) linkTypeName = 'Linux Cooked Capture v2 (SLL2)';
    else linkTypeName = `LinkType ${linkType}`;

    if (linkType !== 1) {
      unsupportedLinkType = true;
      anomalies.push({
        severity: 'Medium',
        title: `Non-Ethernet Datalink Type (${linkTypeName})`,
        description: `This capture was recorded with LinkType ${linkType} rather than standard Ethernet (LINKTYPE_ETHERNET = 1). Frame headers may be non-standard.`,
        evidence: `Datalink header network value = ${linkType} (${linkTypeName})`,
      });
    }

    // Standard PCAP parsing
    let offset = 24; // Skip 24-byte global header

    let packetIndex = 1;
    while (offset + 16 <= bytes.length && packetIndex <= 2000) {
      const tsSec = dataView.getUint32(offset, isLittleEndian);
      const tsUsec = dataView.getUint32(offset + 4, isLittleEndian);
      const inclLen = dataView.getUint32(offset + 8, isLittleEndian);
      const origLen = dataView.getUint32(offset + 12, isLittleEndian);
      offset += 16;

      if (offset + inclLen > bytes.length) {
        truncatedPacketsCount++;
        anomalies.push({
          severity: 'High',
          title: 'Truncated Packet Capture Data',
          description: `Packet #${packetIndex} specifies capture length of ${inclLen} bytes, but only ${bytes.length - offset} bytes remain in file buffer.`,
          evidence: `File offset: ${offset}, Required length: ${inclLen}, Available bytes: ${bytes.length - offset}`,
        });
        break;
      }

      totalBytes += origLen;
      const timeMs = tsSec * 1000 + Math.floor(tsUsec / 1000);
      if (timeMs < minTime) minTime = timeMs;
      if (timeMs > maxTime) maxTime = timeMs;

      const packetBytes = bytes.slice(offset, offset + inclLen);
      offset += inclLen;

      // Decode packet
      const decoded = decodeFrame(packetBytes, packetIndex, timeMs);
      if (decoded) {
        packets.push(decoded);

        // Protocol stats
        protocolCounts[decoded.protocol] = (protocolCounts[decoded.protocol] || 0) + 1;
        if (decoded.appProtocol) {
          protocolCounts[decoded.appProtocol] = (protocolCounts[decoded.appProtocol] || 0) + 1;
        }

        // Conversation pairing
        if (decoded.srcIp && decoded.dstIp) {
          const pairKey = [decoded.srcIp, decoded.dstIp].sort().join(' <-> ');
          const conv = conversationsMap.get(pairKey) || {
            pair: pairKey,
            src: decoded.srcIp,
            dst: decoded.dstIp,
            proto: decoded.appProtocol || decoded.protocol,
            packets: 0,
            bytes: 0,
          };
          conv.packets++;
          conv.bytes += inclLen;
          conversationsMap.set(pairKey, conv);
        }

        // Anomaly tracking
        if (decoded.protocol === 'TCP') {
          totalTcp++;
          if (decoded.info.includes('[SYN]')) synCount++;
        }
        if (decoded.appProtocol === 'DNS' && decoded.info.includes('Query:')) {
          const qName = decoded.info.split('Query: ')[1] || '';
          if (qName) dnsQueries.push(qName);
        }

        // Cleartext inspection
        if (decoded.info.includes('USER ') || decoded.info.includes('PASS ') || decoded.info.includes('Authorization: Basic')) {
          cleartextCredFound = true;
          anomalies.push({
            severity: 'High',
            title: 'Cleartext Authentication Credentials Observed',
            description: 'Packet contains plain-text credentials or basic authentication tokens over unencrypted channel.',
            evidence: `Frame #${decoded.index} (${decoded.srcIp}:${decoded.srcPort} -> ${decoded.dstIp}:${decoded.dstPort}) ${decoded.info}`,
          });
        }
      }

      packetIndex++;
    }
  } else {
    // Accurate PCAPNG Block Parsing (SHB, IDB, EPB, SPB)
    interface InternalPcapNgInterface {
      id: number;
      linkType: number;
      linkTypeName: string;
      snapLen: number;
      name?: string;
      tsResol: { isBinary: boolean; value: number };
      tsOffsetSeconds: number;
      optionsParsed: boolean;
      malformedOptions?: boolean;
    }

    const interfaces: InternalPcapNgInterface[] = [];
    let offset = 0;
    let packetIndex = 1;

    while (offset + 12 <= bytes.length && packetIndex <= 2000) {
      const blockType = dataView.getUint32(offset, isLittleEndian);
      const blockLen = dataView.getUint32(offset + 4, isLittleEndian);
      if (blockLen < 12 || offset + blockLen > bytes.length) break;

      // Section Header Block (0x0A0D0D0A)
      if (blockType === 0x0a0d0d0a && blockLen >= 16) {
        const bom = dataView.getUint32(offset + 8, false);
        if (bom === 0x1a2b3c4d) {
          isLittleEndian = false;
        } else if (bom === 0x4d3c2b1a) {
          isLittleEndian = true;
        }
      }

      // Interface Description Block (0x00000001)
      else if (blockType === 0x00000001 && blockLen >= 16) {
        const idbLinkType = dataView.getUint16(offset + 8, isLittleEndian);
        const idbSnapLen = dataView.getUint32(offset + 12, isLittleEndian);

        let tsResol = { isBinary: false, value: 6 }; // Default: 10^-6 s (1 microsecond)
        let tsOffsetSeconds = 0;
        let ifName: string | undefined;
        let malformedOptions = false;

        let optOffset = offset + 16;
        const optEnd = offset + blockLen - 4;

        while (optOffset + 4 <= optEnd) {
          const optCode = dataView.getUint16(optOffset, isLittleEndian);
          const optLen = dataView.getUint16(optOffset + 2, isLittleEndian);
          if (optCode === 0) break; // opt_endofopt

          const valOffset = optOffset + 4;
          if (valOffset + optLen > optEnd) {
            malformedOptions = true;
            anomalies.push({
              severity: 'Medium',
              title: 'Malformed PCAPNG IDB Option',
              description: `Option code ${optCode} specifies length ${optLen} which overflows IDB boundary.`,
              evidence: `Interface #${interfaces.length}, block offset ${offset}, optOffset ${optOffset}`,
            });
            break;
          }

          if (optCode === 9) {
            // if_tsresol (1 byte)
            if (optLen >= 1) {
              const rawByte = dataView.getUint8(valOffset);
              const isBinary = (rawByte & 0x80) !== 0;
              const value = rawByte & 0x7f;
              tsResol = { isBinary, value };
            }
          } else if (optCode === 14) {
            // if_tsoffset (8 bytes, signed 64-bit integer)
            if (optLen >= 8) {
              try {
                const rawSec = dataView.getBigInt64(valOffset, isLittleEndian);
                tsOffsetSeconds = Number(rawSec);
              } catch {
                const low = dataView.getUint32(valOffset + (isLittleEndian ? 0 : 4), isLittleEndian);
                const high = dataView.getInt32(valOffset + (isLittleEndian ? 4 : 0), isLittleEndian);
                tsOffsetSeconds = high * 4294967296 + low;
              }
            }
          } else if (optCode === 2) {
            // if_name (UTF-8 string)
            try {
              const nameBytes = bytes.slice(valOffset, valOffset + optLen);
              ifName = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes).replace(/\0+$/, '');
            } catch {
              // ignore string decoding errors
            }
          }

          const padding = (4 - (optLen % 4)) % 4;
          optOffset += 4 + optLen + padding;
        }

        const ifaceId = interfaces.length;
        const ifaceLinkTypeName = getLinkTypeName(idbLinkType);
        if (ifaceId === 0) {
          linkType = idbLinkType;
          linkTypeName = ifaceLinkTypeName;
        }

        if (idbLinkType !== 1 && !unsupportedLinkType) {
          unsupportedLinkType = true;
          anomalies.push({
            severity: 'Medium',
            title: `Non-Ethernet PCAPNG Interface Datalink Type (${ifaceLinkTypeName})`,
            description: `Interface #${ifaceId} specifies LinkType ${idbLinkType} rather than standard Ethernet (1).`,
            evidence: `Interface ID: ${ifaceId}, LinkType: ${idbLinkType} (${ifaceLinkTypeName})`,
          });
        }

        interfaces.push({
          id: ifaceId,
          linkType: idbLinkType,
          linkTypeName: ifaceLinkTypeName,
          snapLen: idbSnapLen,
          name: ifName,
          tsResol,
          tsOffsetSeconds,
          optionsParsed: true,
          malformedOptions,
        });
      }

      // Enhanced Packet Block (0x00000006)
      else if (blockType === 0x00000006 && blockLen >= 32) {
        const interfaceId = dataView.getUint32(offset + 8, isLittleEndian);
        const tsHigh = dataView.getUint32(offset + 12, isLittleEndian);
        const tsLow = dataView.getUint32(offset + 16, isLittleEndian);
        const capLen = dataView.getUint32(offset + 20, isLittleEndian);
        const origLen = dataView.getUint32(offset + 24, isLittleEndian);

        if (offset + 28 + capLen <= bytes.length) {
          totalBytes += origLen || capLen;

          let iface = interfaces[interfaceId];
          if (!iface && interfaceId === 0 && interfaces.length === 0) {
            // Implicit interface 0 fallback for minimal synthetic captures without IDB
            iface = {
              id: 0,
              linkType: 1,
              linkTypeName: 'Ethernet (1)',
              snapLen: 65535,
              tsResol: { isBinary: false, value: 6 },
              tsOffsetSeconds: 0,
              optionsParsed: false,
            };
            interfaces.push(iface);
            anomalies.push({
              severity: 'Low',
              title: 'Implicit Interface Description in PCAPNG',
              description: 'EPB referenced Interface 0 before any IDB was defined; using default PCAPNG microsecond resolution.',
              evidence: `Block offset ${offset}, Interface ID: 0`,
            });
          }

          let timeMs = 0;
          let timestampUnreliable = false;
          let timestampLimitation: string | undefined;

          const rawTicks = (BigInt(tsHigh) << 32n) | BigInt(tsLow);

          if (!iface) {
            timestampUnreliable = true;
            timestampLimitation = `EPB specifies Interface ID ${interfaceId}, but only ${interfaces.length} interface(s) exist.`;
            anomalies.push({
              severity: 'Medium',
              title: 'Unmatched PCAPNG Interface ID',
              description: timestampLimitation,
              evidence: `Frame #${packetIndex}, Block offset ${offset}, InterfaceID: ${interfaceId}`,
            });
          } else if (rawTicks === 0n && tsHigh === 0 && tsLow === 0) {
            timestampUnreliable = true;
            timestampLimitation = 'Capture timestamp ticks are zero (unrecorded).';
          } else {
            let seconds: number;
            if (iface.tsResol.isBinary) {
              const divisor = Math.pow(2, iface.tsResol.value);
              seconds = Number(rawTicks) / divisor + iface.tsOffsetSeconds;
            } else {
              const b = iface.tsResol.value;
              if (b === 6) {
                seconds = Number(rawTicks / 1000000n) + Number(rawTicks % 1000000n) / 1000000 + iface.tsOffsetSeconds;
              } else if (b === 9) {
                seconds = Number(rawTicks / 1000000000n) + Number(rawTicks % 1000000000n) / 1000000000 + iface.tsOffsetSeconds;
              } else {
                const divisor = Math.pow(10, b);
                seconds = Number(rawTicks) / divisor + iface.tsOffsetSeconds;
              }
            }

            timeMs = Math.round(seconds * 1000);

            if (!Number.isFinite(timeMs) || timeMs < 0 || timeMs > 4102444800000) {
              timestampUnreliable = true;
              timestampLimitation = `Calculated timestamp out of bounds (${seconds}s).`;
            }
          }

          if (!timestampUnreliable) {
            if (timeMs < minTime) minTime = timeMs;
            if (timeMs > maxTime) maxTime = timeMs;
          }

          const packetBytes = bytes.slice(offset + 28, offset + 28 + capLen);
          const decoded = decodeFrame(packetBytes, packetIndex, timeMs, interfaceId, timestampUnreliable, timestampLimitation);

          if (decoded) {
            packets.push(decoded);
            protocolCounts[decoded.protocol] = (protocolCounts[decoded.protocol] || 0) + 1;
            if (decoded.appProtocol) {
              protocolCounts[decoded.appProtocol] = (protocolCounts[decoded.appProtocol] || 0) + 1;
            }

            // Conversation pairing
            if (decoded.srcIp && decoded.dstIp) {
              const pairKey = [decoded.srcIp, decoded.dstIp].sort().join(' <-> ');
              const conv = conversationsMap.get(pairKey) || {
                pair: pairKey,
                src: decoded.srcIp,
                dst: decoded.dstIp,
                proto: decoded.appProtocol || decoded.protocol,
                packets: 0,
                bytes: 0,
              };
              conv.packets++;
              conv.bytes += capLen;
              conversationsMap.set(pairKey, conv);
            }

            // Anomaly tracking
            if (decoded.protocol === 'TCP') {
              totalTcp++;
              if (decoded.info.includes('[SYN]')) synCount++;
            }
            if (decoded.appProtocol === 'DNS' && decoded.info.includes('Query:')) {
              const qName = decoded.info.split('Query: ')[1] || '';
              if (qName) dnsQueries.push(qName);
            }
            if (decoded.info.includes('USER ') || decoded.info.includes('PASS ') || decoded.info.includes('Authorization: Basic')) {
              cleartextCredFound = true;
              anomalies.push({
                severity: 'High',
                title: 'Cleartext Authentication Credentials Observed',
                description: 'Packet contains plain-text credentials or basic authentication tokens over unencrypted channel.',
                evidence: `Frame #${decoded.index} (${decoded.srcIp}:${decoded.srcPort} -> ${decoded.dstIp}:${decoded.dstPort}) ${decoded.info}`,
              });
            }
          }
          packetIndex++;
        }
      } else if (blockType === 0x00000003 && blockLen >= 16) {
        // Simple Packet Block (0x00000003) - Note: SPB has NO timestamps by spec
        const capLen = blockLen - 12;
        if (offset + 8 + capLen <= bytes.length) {
          totalBytes += capLen;
          const timestampUnreliable = true;
          const timestampLimitation = 'Simple Packet Blocks (SPB) do not record timestamps.';

          const packetBytes = bytes.slice(offset + 8, offset + 8 + capLen);
          const decoded = decodeFrame(packetBytes, packetIndex, 0, 0, timestampUnreliable, timestampLimitation);
          if (decoded) {
            packets.push(decoded);
            protocolCounts[decoded.protocol] = (protocolCounts[decoded.protocol] || 0) + 1;
          }
          packetIndex++;
        }
      }

      offset += blockLen;
    }

    pcapNgInterfaces = interfaces.map((i) => ({
      id: i.id,
      linkType: i.linkType,
      linkTypeName: i.linkTypeName,
      name: i.name,
      tsResolution: i.tsResol.isBinary ? `2^-${i.tsResol.value} seconds` : `10^-${i.tsResol.value} seconds`,
      tsOffsetSeconds: i.tsOffsetSeconds,
      isBinaryResolution: i.tsResol.isBinary,
      malformedOptions: i.malformedOptions,
    }));
  }

  // Assess heuristics & anomalies
  if (totalTcp > 20 && synCount / totalTcp > 0.65) {
    anomalies.push({
      severity: 'Critical',
      title: 'Potential TCP SYN Port Scan / Flood Detected',
      description: `Excessive TCP SYN flags observed (${synCount} SYN packets out of ${totalTcp} TCP frames, ${(synCount / totalTcp * 100).toFixed(1)}%). Indicates automated reconnaissance or denial-of-service attempt.`,
      evidence: `Ratio: ${(synCount / totalTcp * 100).toFixed(1)}% SYN frames without full handshakes.`,
    });
  }

  // Check for DNS tunneling (queries with long subdomains > 35 chars)
  const suspiciousDns = dnsQueries.filter((q) => q.length > 40 || /[0-9a-f]{20,}/i.test(q));
  if (suspiciousDns.length > 0) {
    anomalies.push({
      severity: 'High',
      title: 'Suspicious High-Entropy DNS Query (Potential DNS Tunneling / Exfiltration)',
      description: `Detected DNS queries with anomalous length and encoded character patterns characteristic of iodine, dnscat2, or Cobalt Strike DNS stagers.`,
      evidence: `Sample query: ${suspiciousDns[0]} (${suspiciousDns.length} matching frames)`,
    });
  }

  const durationSeconds = maxTime > minTime ? Number(((maxTime - minTime) / 1000).toFixed(2)) : 1;
  const avgPacketRate = Number((packets.length / Math.max(durationSeconds, 1)).toFixed(2));

  const topConversations = Array.from(conversationsMap.values())
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  return {
    fileName,
    fileSize: bytes.length,
    format: isPcapNg ? 'PCAPNG (Next Gen)' : 'PCAP (Standard)',
    totalPackets: packets.length,
    totalBytes,
    durationSeconds,
    avgPacketRate,
    protocols: protocolCounts,
    topConversations,
    anomalies,
    packets,
    interfaces: pcapNgInterfaces,
    linkType,
    linkTypeName,
    truncatedPacketsCount,
    unsupportedLinkType,
  };
}

function decodeFrame(
  frameBytes: Uint8Array,
  index: number,
  timeMs: number,
  interfaceId = 0,
  timestampUnreliable = false,
  timestampLimitation?: string
): PcapPacket | null {
  if (frameBytes.length < 14) return null;

  // Ethernet II header (14 bytes)
  // EtherType at offset 12-13
  const etherType = (frameBytes[12] << 8) | frameBytes[13];

  let protocol: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'IPv6' | 'Other' = 'Other';
  let appProtocol: string | undefined;
  let srcIp: string | undefined;
  let dstIp: string | undefined;
  let srcPort: number | undefined;
  let dstPort: number | undefined;
  let info = '';

  let timeStr: string;
  if (timestampUnreliable) {
    timeStr = `UNVERIFIED (${timestampLimitation || 'Unreliable timestamp'})`;
  } else if (timeMs > 0) {
    const d = new Date(timeMs);
    timeStr = !isNaN(d.getTime())
      ? d.toISOString().replace('T', ' ').replace('Z', '')
      : `EPOCH_${timeMs}ms`;
  } else {
    timeStr = `UNVERIFIED (Zero or unrecorded timestamp)`;
  }

  if (etherType === 0x0800) {
    // IPv4
    const ipOffset = 14;
    if (frameBytes.length < ipOffset + 20) return null;

    const ipHeaderLen = (frameBytes[ipOffset] & 0x0f) * 4;
    const ipProto = frameBytes[ipOffset + 9];

    srcIp = `${frameBytes[ipOffset + 12]}.${frameBytes[ipOffset + 13]}.${frameBytes[ipOffset + 14]}.${frameBytes[ipOffset + 15]}`;
    dstIp = `${frameBytes[ipOffset + 16]}.${frameBytes[ipOffset + 17]}.${frameBytes[ipOffset + 18]}.${frameBytes[ipOffset + 19]}`;

    const transportOffset = ipOffset + ipHeaderLen;

    if (ipProto === 6 && frameBytes.length >= transportOffset + 20) {
      // TCP
      protocol = 'TCP';
      srcPort = (frameBytes[transportOffset] << 8) | frameBytes[transportOffset + 1];
      dstPort = (frameBytes[transportOffset + 2] << 8) | frameBytes[transportOffset + 3];
      const flags = frameBytes[transportOffset + 13];

      const flagParts: string[] = [];
      if (flags & 0x02) flagParts.push('SYN');
      if (flags & 0x10) flagParts.push('ACK');
      if (flags & 0x01) flagParts.push('FIN');
      if (flags & 0x04) flagParts.push('RST');
      if (flags & 0x08) flagParts.push('PSH');

      // Application identification
      if (srcPort === 80 || dstPort === 80 || srcPort === 8080 || dstPort === 8080) appProtocol = 'HTTP';
      else if (srcPort === 443 || dstPort === 443) appProtocol = 'TLS';
      else if (srcPort === 22 || dstPort === 22) appProtocol = 'SSH';
      else if (srcPort === 21 || dstPort === 21) appProtocol = 'FTP';
      else if (srcPort === 23 || dstPort === 23) appProtocol = 'Telnet';
      else if (srcPort === 445 || dstPort === 445) appProtocol = 'SMB';

      // Check payload for HTTP/FTP/Telnet strings
      const tcpHeaderLen = ((frameBytes[transportOffset + 12] >> 4) & 0x0f) * 4;
      const payloadOffset = transportOffset + tcpHeaderLen;
      let payloadSnippet = '';
      if (payloadOffset < frameBytes.length) {
        const pLen = Math.min(frameBytes.length - payloadOffset, 80);
        payloadSnippet = String.fromCharCode(...frameBytes.slice(payloadOffset, payloadOffset + pLen)).replace(/[^\x20-\x7E]/g, ' ');
      }

      info = `${appProtocol || 'TCP'} [${flagParts.join(', ')}] ${srcPort} -> ${dstPort} ${payloadSnippet ? `| ${payloadSnippet.slice(0, 80).trim()}` : ''}`;
    } else if (ipProto === 17 && frameBytes.length >= transportOffset + 8) {
      // UDP
      protocol = 'UDP';
      srcPort = (frameBytes[transportOffset] << 8) | frameBytes[transportOffset + 1];
      dstPort = (frameBytes[transportOffset + 2] << 8) | frameBytes[transportOffset + 3];

      if (srcPort === 53 || dstPort === 53) {
        appProtocol = 'DNS';
        // Extract basic DNS query if present
        const dnsOffset = transportOffset + 8;
        let dnsQuery = '';
        if (dnsOffset + 12 < frameBytes.length) {
          let curr = dnsOffset + 12;
          const labels: string[] = [];
          while (curr < frameBytes.length && frameBytes[curr] !== 0 && labels.length < 5) {
            const labelLen = frameBytes[curr];
            curr++;
            if (curr + labelLen <= frameBytes.length) {
              const label = String.fromCharCode(...frameBytes.slice(curr, curr + labelLen));
              labels.push(label);
              curr += labelLen;
            } else break;
          }
          dnsQuery = labels.join('.');
        }
        info = `DNS ${srcPort} -> ${dstPort} ${dnsQuery ? `Query: ${dnsQuery}` : ''}`;
      } else {
        info = `UDP ${srcPort} -> ${dstPort} len=${frameBytes.length - transportOffset}`;
      }
    } else if (ipProto === 1) {
      protocol = 'ICMP';
      const icmpType = frameBytes[transportOffset];
      info = `ICMP Type ${icmpType} (${icmpType === 8 ? 'Echo Request' : icmpType === 0 ? 'Echo Reply' : 'Status'})`;
    } else {
      info = `IPv4 Proto ${ipProto}`;
    }
  } else if (etherType === 0x0806) {
    protocol = 'ARP';
    if (frameBytes.length >= 14 + 28) {
      const op = (frameBytes[20] << 8) | frameBytes[21];
      srcIp = `${frameBytes[28]}.${frameBytes[29]}.${frameBytes[30]}.${frameBytes[31]}`;
      dstIp = `${frameBytes[38]}.${frameBytes[39]}.${frameBytes[40]}.${frameBytes[41]}`;
      info = op === 1 ? `ARP Who has ${dstIp}? Tell ${srcIp}` : `ARP Reply ${srcIp} is at ${dstIp}`;
    } else {
      info = 'ARP Request / Reply';
    }
  } else if (etherType === 0x86dd) {
    // IPv6 Header (40 bytes starting at offset 14)
    if (frameBytes.length >= 54) {
      const formatV6 = (offset: number) => {
        const words: string[] = [];
        for (let i = 0; i < 16; i += 2) {
          words.push(((frameBytes[offset + i] << 8) | frameBytes[offset + i + 1]).toString(16));
        }
        return words.join(':');
      };

      srcIp = formatV6(14 + 8);
      dstIp = formatV6(14 + 24);
      const nextHeader = frameBytes[14 + 6];
      const transportOffset = 54;

      if (nextHeader === 6 && frameBytes.length >= transportOffset + 20) {
        protocol = 'TCP';
        srcPort = (frameBytes[transportOffset] << 8) | frameBytes[transportOffset + 1];
        dstPort = (frameBytes[transportOffset + 2] << 8) | frameBytes[transportOffset + 3];
        const flags = frameBytes[transportOffset + 13];
        const flagParts: string[] = [];
        if (flags & 0x02) flagParts.push('SYN');
        if (flags & 0x10) flagParts.push('ACK');
        if (flags & 0x01) flagParts.push('FIN');
        if (flags & 0x04) flagParts.push('RST');
        if (flags & 0x08) flagParts.push('PSH');

        if (srcPort === 80 || dstPort === 80 || srcPort === 8080 || dstPort === 8080) appProtocol = 'HTTP';
        else if (srcPort === 443 || dstPort === 443) appProtocol = 'TLS';
        else if (srcPort === 22 || dstPort === 22) appProtocol = 'SSH';
        else if (srcPort === 21 || dstPort === 21) appProtocol = 'FTP';

        info = `${appProtocol || 'TCP'} [${flagParts.join(', ')}] ${srcPort} -> ${dstPort}`;
      } else if (nextHeader === 17 && frameBytes.length >= transportOffset + 8) {
        protocol = 'UDP';
        srcPort = (frameBytes[transportOffset] << 8) | frameBytes[transportOffset + 1];
        dstPort = (frameBytes[transportOffset + 2] << 8) | frameBytes[transportOffset + 3];
        if (srcPort === 53 || dstPort === 53) {
          appProtocol = 'DNS';
          info = `DNS ${srcPort} -> ${dstPort} (IPv6)`;
        } else {
          info = `UDP ${srcPort} -> ${dstPort} (IPv6)`;
        }
      } else if (nextHeader === 58) {
        protocol = 'ICMP';
        info = `ICMPv6 Type ${frameBytes[transportOffset]}`;
      } else {
        protocol = 'IPv6';
        info = `IPv6 NextHeader ${nextHeader}`;
      }
    } else {
      protocol = 'IPv6';
      info = 'IPv6 Datagram (Truncated)';
    }
  } else {
    info = `EtherType 0x${etherType.toString(16)}`;
  }

  return {
    index,
    timestamp: timestampUnreliable ? 0 : timeMs,
    timeStr,
    length: frameBytes.length,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    protocol,
    appProtocol,
    info,
    interfaceId,
    timestampUnreliable,
    timestampLimitation,
  };
}

// Generate realistic synthetic PCAP files for instant in-browser testing
export function generateSamplePcap(type: 'c2-beacon' | 'dns-tunnel' | 'web-traffic'): ArrayBuffer {
  // Build a valid 24-byte PCAP header + realistic frames
  const packets: Uint8Array[] = [];

  if (type === 'c2-beacon') {
    // Cobalt Strike / Mythic periodic beaconing
    for (let i = 0; i < 24; i++) {
      packets.push(createSyntheticTcpPacket('192.168.1.105', '198.51.100.42', 49152 + i, 443, 'TLS [PSH, ACK] Application Data Encrypted Beacon (256 bytes)'));
    }
  } else if (type === 'dns-tunnel') {
    // High-entropy DNS TXT staging
    const payloads = [
      'Query: a8f93c0192e4b3.c2stage.malicious-network.org',
      'Query: 8812bf0092c10398f.c2stage.malicious-network.org',
      'Query: f70912ab00c3de458.c2stage.malicious-network.org',
      'Query: 99120489acbd78104.c2stage.malicious-network.org',
      'Query: b890f3319803caef1.c2stage.malicious-network.org',
    ];
    for (let i = 0; i < 20; i++) {
      packets.push(createSyntheticUdpDnsPacket('192.168.1.45', '8.8.8.8', payloads[i % payloads.length]));
    }
  } else {
    // Normal HTTP/HTTPS
    for (let i = 0; i < 15; i++) {
      packets.push(createSyntheticTcpPacket('10.0.0.12', '93.184.216.34', 52310 + i, 443, 'TLS Client Hello / Server Hello [ACK]'));
    }
  }

  // Calculate buffer size: 24 byte global header + (16 + p.length) per packet
  const totalLen = 24 + packets.reduce((acc, p) => acc + 16 + p.length, 0);
  const outBuf = new ArrayBuffer(totalLen);
  const dv = new DataView(outBuf);
  const outBytes = new Uint8Array(outBuf);

  // Global header: 0xd4c3b2a1 (little-endian libpcap magic)
  outBytes[0] = 0xd4;
  outBytes[1] = 0xc3;
  outBytes[2] = 0xb2;
  outBytes[3] = 0xa1;
  dv.setUint16(4, 2, true);
  dv.setUint16(6, 4, true);
  dv.setInt32(8, 0, true);
  dv.setUint32(12, 0, true);
  dv.setUint32(16, 65535, true);
  dv.setUint32(20, 1, true);

  let offset = 24;
  const now = Math.floor(Date.now() / 1000);

  packets.forEach((pkt, idx) => {
    dv.setUint32(offset, now - (packets.length - idx), true); // ts_sec
    dv.setUint32(offset + 4, idx * 50000, true); // ts_usec
    dv.setUint32(offset + 8, pkt.length, true); // incl_len
    dv.setUint32(offset + 12, pkt.length, true); // orig_len
    offset += 16;
    outBytes.set(pkt, offset);
    offset += pkt.length;
  });

  return outBuf;
}

function createSyntheticTcpPacket(srcIp: string, dstIp: string, srcPort: number, dstPort: number, info: string): Uint8Array {
  const enc = new TextEncoder().encode(info);
  const pkt = new Uint8Array(54 + enc.length);
  // Eth
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  // IPv4
  pkt[14] = 0x45;
  const totalIpLen = 40 + enc.length;
  pkt[16] = (totalIpLen >> 8) & 0xff;
  pkt[17] = totalIpLen & 0xff;
  pkt[23] = 6; // TCP
  const src = srcIp.split('.').map(Number);
  const dst = dstIp.split('.').map(Number);
  pkt.set(src, 26);
  pkt.set(dst, 30);
  // TCP
  pkt[34] = (srcPort >> 8) & 0xff;
  pkt[35] = srcPort & 0xff;
  pkt[36] = (dstPort >> 8) & 0xff;
  pkt[37] = dstPort & 0xff;
  pkt[46] = (5 << 4); // Data offset 5 (20 bytes)
  pkt[47] = 0x18; // PSH, ACK
  // Copy payload
  pkt.set(enc, 54);
  return pkt;
}

function createSyntheticUdpDnsPacket(srcIp: string, dstIp: string, queryStr: string): Uint8Array {
  const pkt = new Uint8Array(72);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[23] = 17; // UDP
  const src = srcIp.split('.').map(Number);
  const dst = dstIp.split('.').map(Number);
  pkt.set(src, 26);
  pkt.set(dst, 30);
  // UDP port 53
  pkt[34] = 0xc0;
  pkt[35] = 0x01;
  pkt[36] = 0x00;
  pkt[37] = 0x35; // 53
  // DNS Header
  pkt[42] = 0x01; // 1 Question
  // Encode query into packet
  const parts = queryStr.replace('Query: ', '').split('.');
  let curr = 54;
  for (const part of parts) {
    if (curr + part.length + 1 >= pkt.length) break;
    pkt[curr++] = part.length;
    for (let c = 0; c < part.length; c++) {
      pkt[curr++] = part.charCodeAt(c);
    }
  }
  return pkt;
}
