import { ExtractedIoc, IocType, IocValidationStatus, ConfidenceLevel, CaseRecord, FileAnalysisResult, PcapAnalysisResult } from '../types';

// Regex patterns for indicator extraction
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g;
const URL_REGEX = /\bhttps?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_+.~#?&//=]*/gi;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b/g;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const FILEPATH_REGEX = /(?:[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+|\/(?:bin|etc|tmp|var|usr|home|opt|root|sys|proc|data)\/[a-zA-Z0-9_.-]+)/g;

// Benign / Common Noise Whitelist (prevent false positives on standard schemas and dev hosts)
const COMMON_BENIGN_DOMAINS = new Set([
  'w3.org',
  'schema.org',
  'xml.org',
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'google.com',
  'cloudflare.com',
  'microsoft.com',
  'github.com',
  'mozilla.org',
]);

/**
 * Defangs an indicator to ensure safe copy-pasting into tickets or reports without triggering auto-links.
 */
export function defangIoc(value: string, type: IocType): string {
  if (!value) return '';
  switch (type) {
    case 'url':
      return value.replace(/^http:\/\//i, 'hxxp://').replace(/^https:\/\//i, 'hxxps://').replace(/\./g, '[.]');
    case 'domain':
      return value.replace(/\./g, '[.]');
    case 'ipv4':
      return value.replace(/\./g, '[.]');
    case 'ipv6':
      return value.replace(/:/g, '[:]');
    case 'email':
      return value.replace('@', '[at]').replace(/\./g, '[.]');
    default:
      return value;
  }
}

/**
 * Refangs a defanged indicator for intentional operational pivots.
 */
export function refangIoc(value: string): string {
  if (!value) return '';
  return value
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[at\]/g, '@');
}

/**
 * Determines whether an IPv4 address belongs to private or reserved RFC ranges.
 */
export function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // Loopback 127.0.0.0/8
  if (a === 169 && b === 254) return true; // Link-local / IMDS
  if (a === 0 || a >= 224) return true; // Broadcast / Multicast
  return false;
}

/**
 * Evaluates contextual validation status for an indicator.
 */
function evaluateValidationStatus(value: string, type: IocType, context: string): { status: IocValidationStatus; rationale: string } {
  const lowerVal = value.toLowerCase();
  const lowerCtx = context.toLowerCase();

  if (type === 'ipv4') {
    if (isPrivateOrReservedIpv4(value)) {
      return { status: 'Internal', rationale: 'Private RFC 1918 / Loopback / Link-Local IP address range.' };
    }
  }

  if (type === 'domain') {
    if (COMMON_BENIGN_DOMAINS.has(lowerVal) || lowerVal.endsWith('.local') || lowerVal.endsWith('.internal')) {
      return { status: 'Benign', rationale: 'Recognized public standard schema or benign corporate domain.' };
    }
    if (lowerCtx.includes('c2') || lowerCtx.includes('tunnel') || lowerCtx.includes('malicious') || lowerCtx.includes('beacon')) {
      return { status: 'Suspicious', rationale: 'Observed within context of suspicious network telemetry or high-entropy queries.' };
    }
  }

  if (type === 'url') {
    if (lowerVal.includes('admin') || lowerCtx.includes('unencrypted') || lowerCtx.includes('cleartext') || lowerCtx.includes('c2stage')) {
      return { status: 'Suspicious', rationale: 'Direct unencrypted authentication endpoint or staged command channel.' };
    }
    if (lowerVal.includes('schema.org') || lowerVal.includes('w3.org')) {
      return { status: 'Benign', rationale: 'Standard XML namespace / schema definition.' };
    }
  }

  if (type === 'hash_sha256' || type === 'hash_md5' || type === 'hash_sha1') {
    if (lowerCtx.includes('masquerad') || lowerCtx.includes('packed') || lowerCtx.includes('zip slip')) {
      return { status: 'Suspicious', rationale: 'Cryptographic hash of an artifact exhibiting structural format anomalies.' };
    }
  }

  if (type === 'filepath') {
    if (lowerVal.includes('..') || lowerVal.includes('etc/shadow') || lowerVal.includes('system32')) {
      return { status: 'Suspicious', rationale: 'Path traversal sequence or critical operating system target.' };
    }
  }

  return { status: 'Unverified', rationale: 'Extracted from raw evidence; requires correlation against external threat telemetry.' };
}

/**
 * Extracts and normalizes indicators from arbitrary text strings with deduplication and provenance tracking.
 */
export function extractIocsFromText(
  text: string,
  source: string,
  sourceId: string,
  confidence: ConfidenceLevel = 'Confirmed'
): ExtractedIoc[] {
  if (!text || typeof text !== 'string') return [];

  const map = new Map<string, ExtractedIoc>();
  const now = new Date().toISOString();

  // Helper to register IOC
  const add = (raw: string, type: IocType) => {
    const normalized = type === 'domain' || type === 'email' ? raw.toLowerCase().trim() : raw.trim();
    if (!normalized) return;

    // Filter out common false-positive extensions or version numbers falsely matching domains
    if (type === 'domain') {
      if (normalized.endsWith('.png') || normalized.endsWith('.jpg') || normalized.endsWith('.exe') || normalized.endsWith('.zip')) {
        return;
      }
      if (/^\d+\.\d+\.\d+$/.test(normalized)) return; // Version strings like 1.24.0
    }

    const key = `${type}:${normalized}`;
    if (!map.has(key)) {
      const isPrivate = type === 'ipv4' ? isPrivateOrReservedIpv4(normalized) : undefined;
      const { status, rationale } = evaluateValidationStatus(normalized, type, text);
      map.set(key, {
        id: `IOC-${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
        type,
        rawValue: raw,
        normalizedValue: normalized,
        defangedValue: defangIoc(normalized, type),
        confidence,
        validationStatus: status,
        statusRationale: rationale,
        source,
        sourceId,
        extractedAt: now,
        contextSnippet: text.length > 120 ? text.slice(0, 120) + '...' : text,
        isPrivateOrReserved: isPrivate,
      });
    }
  };

  // 1. URLs
  const urls = text.match(URL_REGEX) || [];
  urls.forEach((u) => add(u, 'url'));

  // 2. Emails
  const emails = text.match(EMAIL_REGEX) || [];
  emails.forEach((e) => add(e, 'email'));

  // 3. IPv4
  const ips = text.match(IPV4_REGEX) || [];
  ips.forEach((ip) => add(ip, 'ipv4'));

  // 4. Domains (exclude if already captured in URLs)
  const domains = text.match(DOMAIN_REGEX) || [];
  domains.forEach((d) => {
    if (!urls.some((u) => u.includes(d))) {
      add(d, 'domain');
    }
  });

  // 5. SHA-256
  const sha256s = text.match(SHA256_REGEX) || [];
  sha256s.forEach((h) => add(h, 'hash_sha256'));

  // 6. SHA-1 (only if not part of SHA-256)
  const sha1s = text.match(SHA1_REGEX) || [];
  sha1s.forEach((h) => {
    if (!sha256s.some((s) => s.includes(h))) {
      add(h, 'hash_sha1');
    }
  });

  // 7. MD5 (only if not part of SHA-1/256)
  const md5s = text.match(MD5_REGEX) || [];
  md5s.forEach((h) => {
    if (!sha256s.some((s) => s.includes(h)) && !sha1s.some((s) => s.includes(h))) {
      add(h, 'hash_md5');
    }
  });

  // 8. Filepaths
  const paths = text.match(FILEPATH_REGEX) || [];
  paths.forEach((p) => add(p, 'filepath'));

  return Array.from(map.values());
}

/**
 * Extracts all indicators across an entire CaseRecord.
 */
export function extractIocsFromCase(caseRecord: CaseRecord): ExtractedIoc[] {
  const allIocs: ExtractedIoc[] = [];
  const seenKeys = new Set<string>();

  const register = (iocs: ExtractedIoc[]) => {
    for (const ioc of iocs) {
      const k = `${ioc.type}:${ioc.normalizedValue}`;
      if (!seenKeys.has(k)) {
        seenKeys.add(k);
        allIocs.push(ioc);
      }
    }
  };

  // Case Scope
  (caseRecord.scope || []).forEach((scopeItem) => {
    register(extractIocsFromText(scopeItem, `Case Scope: ${caseRecord.id}`, caseRecord.id, 'Confirmed'));
  });

  // Evidence Items
  (caseRecord.evidence || []).forEach((ev) => {
    register(extractIocsFromText(ev.value, `Evidence [${ev.id}]: ${ev.name}`, ev.id, ev.confidence || 'Confirmed'));
    if (ev.notes) {
      register(extractIocsFromText(ev.notes, `Evidence Notes [${ev.id}]`, ev.id, 'Inferred'));
    }
  });

  // Findings
  (caseRecord.findings || []).forEach((f) => {
    const txt = `${f.targetEntity} ${f.observedResult} ${f.description}`;
    register(extractIocsFromText(txt, `Finding [${f.id}]: ${f.title}`, f.id, f.confidence || 'Confirmed'));
  });

  return allIocs;
}

/**
 * Extracts indicators from File Forensics result.
 */
export function extractIocsFromFileAnalysis(fileResult: FileAnalysisResult): ExtractedIoc[] {
  const iocs: ExtractedIoc[] = [];
  const now = new Date().toISOString();

  // Cryptographic Hashes
  if (fileResult.sha256) {
    iocs.push({
      id: `IOC-FILE-SHA256`,
      type: 'hash_sha256',
      rawValue: fileResult.sha256,
      normalizedValue: fileResult.sha256.toLowerCase(),
      defangedValue: fileResult.sha256.toLowerCase(),
      confidence: 'Confirmed',
      validationStatus: fileResult.formatMismatch ? 'Suspicious' : 'Unverified',
      statusRationale: fileResult.formatMismatch ? 'Hash of file exhibiting format masquerading.' : 'Cryptographic hash calculated via SubtleCrypto SHA-256.',
      source: `File Forensics: ${fileResult.fileName}`,
      sourceId: fileResult.sha256.slice(0, 8),
      extractedAt: now,
    });
  }

  // Printable Strings IOCs
  if (fileResult.printableStrings?.extracted) {
    const textBlob = fileResult.printableStrings.extracted.map((s) => s.value).join('\n');
    const fromStrings = extractIocsFromText(textBlob, `File Strings: ${fileResult.fileName}`, fileResult.sha256 || 'file-hash', 'Inferred');
    iocs.push(...fromStrings);
  }

  return iocs;
}

/**
 * Extracts indicators from PCAP analysis result.
 */
export function extractIocsFromPcapAnalysis(pcapResult: PcapAnalysisResult): ExtractedIoc[] {
  const iocs: ExtractedIoc[] = [];
  const seen = new Set<string>();

  // Extract endpoints and DNS queries
  pcapResult.packets.forEach((pkt) => {
    if (pkt.srcIp) {
      const k = `ipv4:${pkt.srcIp}`;
      if (!seen.has(k)) {
        seen.add(k);
        iocs.push(...extractIocsFromText(pkt.srcIp, `PCAP Packet #${pkt.index}`, `pkt-${pkt.index}`, 'Confirmed'));
      }
    }
    if (pkt.dstIp) {
      const k = `ipv4:${pkt.dstIp}`;
      if (!seen.has(k)) {
        seen.add(k);
        iocs.push(...extractIocsFromText(pkt.dstIp, `PCAP Packet #${pkt.index}`, `pkt-${pkt.index}`, 'Confirmed'));
      }
    }
    if (pkt.info) {
      const fromInfo = extractIocsFromText(pkt.info, `PCAP Frame #${pkt.index} Telemetry`, `pkt-${pkt.index}`, 'Confirmed');
      fromInfo.forEach((item) => {
        const k = `${item.type}:${item.normalizedValue}`;
        if (!seen.has(k)) {
          seen.add(k);
          iocs.push(item);
        }
      });
    }
  });

  return iocs;
}

/**
 * Formats a list of IOCs as CSV text.
 */
export function exportIocsAsCsv(iocs: ExtractedIoc[]): string {
  const headers = ['Type', 'Normalized Value', 'Defanged Value', 'Confidence', 'Status', 'Rationale', 'Source', 'Extracted At'];
  const rows = iocs.map((i) => [
    `"${i.type}"`,
    `"${i.normalizedValue}"`,
    `"${i.defangedValue}"`,
    `"${i.confidence}"`,
    `"${i.validationStatus}"`,
    `"${i.statusRationale.replace(/"/g, '""')}"`,
    `"${i.source.replace(/"/g, '""')}"`,
    `"${i.extractedAt}"`,
  ]);
  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}
