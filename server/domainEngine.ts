import dns from 'node:dns/promises';
import { lookup as callbackLookup } from 'node:dns';
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import { URL } from 'node:url';
import {
  DomainAnalysisReport,
  FieldProvenance,
  SecurityHeaderObservation,
  RiskFactorItem,
} from '../src/types';
import { generateDeterministicDomainAnalysis } from '../src/utils/domainAiAnalyst.ts';

export const ENGINE_VERSION = '2.4.0';

// Helper to parse IPv6 into 8 16-bit words (RFC 4291)
export function parseIPv6Words(ip: string): number[] | null {
  let clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // Handle embedded IPv4 dot-decimal at end (e.g. ::ffff:127.0.0.1)
  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = v4Part.split('.').map(Number);
    if (v4Octets.length !== 4 || v4Octets.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
    const high = ((v4Octets[0] << 8) | v4Octets[1]).toString(16);
    const low = ((v4Octets[2] << 8) | v4Octets[3]).toString(16);
    clean = clean.slice(0, lastColon) + ':' + high + ':' + low;
  }

  const parts = clean.split('::');
  if (parts.length > 2) return null;

  const head = parts[0] ? parts[0].split(':').map((h) => parseInt(h, 16)) : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':').map((h) => parseInt(h, 16)) : [];

  if (head.some(isNaN) || tail.some(isNaN)) return null;
  const missing = 8 - (head.length + tail.length);
  if (missing < 0) return null;
  const words = [...head, ...new Array(missing).fill(0), ...tail];
  return words.length === 8 ? words : null;
}

// Helper to safely parse IPv4 in any standard representation:
// - Dotted-decimal (127.0.0.1)
// - Dotted octal (0177.0.0.1)
// - Dotted hex (0x7f.0.0.1)
// - 32-bit single integer (decimal 2130706433, hex 0x7f000001, octal 017700000001)
// - Two-part (127.1) or three-part (127.0.1) Class-based notation
export function parseIPv4ToOctets(str: string): [number, number, number, number] | null {
  const clean = str.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // 1. Single 32-bit integer (decimal, hex, octal) without dots
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(clean) && !clean.includes('.')) {
    let num: number;
    if (clean.startsWith('0x')) {
      num = parseInt(clean, 16);
    } else if (clean.startsWith('0') && clean.length > 1 && !clean.includes('8') && !clean.includes('9')) {
      num = parseInt(clean, 8);
    } else {
      num = parseInt(clean, 10);
    }
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      const b0 = (num >>> 24) & 0xff;
      const b1 = (num >>> 16) & 0xff;
      const b2 = (num >>> 8) & 0xff;
      const b3 = num & 0xff;
      return [b0, b1, b2, b3];
    }
  }

  // 2. Dotted notation (1 to 4 parts)
  if (clean.includes('.')) {
    const rawParts = clean.split('.');
    if (rawParts.length >= 1 && rawParts.length <= 4) {
      const parsedParts: number[] = [];
      for (const p of rawParts) {
        if (!p) return null;
        let val: number;
        if (p.startsWith('0x') || p.startsWith('0x')) {
          val = parseInt(p, 16);
        } else if (p.startsWith('0') && p.length > 1 && !p.includes('8') && !p.includes('9')) {
          val = parseInt(p, 8);
        } else if (/^\d+$/.test(p)) {
          val = parseInt(p, 10);
        } else {
          return null;
        }
        if (isNaN(val) || val < 0) return null;
        parsedParts.push(val);
      }

      if (parsedParts.length === 4) {
        if (parsedParts.every((p) => p <= 255)) {
          return [parsedParts[0], parsedParts[1], parsedParts[2], parsedParts[3]];
        }
      } else if (parsedParts.length === 3) {
        // a.b.c -> a.b. (c is 16-bit)
        if (parsedParts[0] <= 255 && parsedParts[1] <= 255 && parsedParts[2] <= 0xffff) {
          return [parsedParts[0], parsedParts[1], (parsedParts[2] >>> 8) & 0xff, parsedParts[2] & 0xff];
        }
      } else if (parsedParts.length === 2) {
        // a.b -> a. (b is 24-bit)
        if (parsedParts[0] <= 255 && parsedParts[1] <= 0xffffff) {
          return [parsedParts[0], (parsedParts[1] >>> 16) & 0xff, (parsedParts[1] >>> 8) & 0xff, parsedParts[1] & 0xff];
        }
      } else if (parsedParts.length === 1) {
        if (parsedParts[0] <= 0xffffffff) {
          return [
            (parsedParts[0] >>> 24) & 0xff,
            (parsedParts[0] >>> 16) & 0xff,
            (parsedParts[0] >>> 8) & 0xff,
            parsedParts[0] & 0xff,
          ];
        }
      }
    }
  }

  return null;
}

// Helper to check IPv4 octets against RFC special-use ranges
export function isPrivateIPv4Octets(b0: number, b1: number, b2: number, b3: number): { isBlocked: boolean; reason?: string } {
  if (b0 === 0) return { isBlocked: true, reason: 'Current network (0.0.0.0/8) is restricted' };
  if (b0 === 10) return { isBlocked: true, reason: 'Private Class A address (10.0.0.0/8) is restricted' };
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return { isBlocked: true, reason: 'Carrier-grade NAT (100.64.0.0/10) is restricted' };
  if (b0 === 127) return { isBlocked: true, reason: 'Loopback address (127.0.0.0/8) is restricted' };
  if (b0 === 169 && b1 === 254) return { isBlocked: true, reason: 'Link-local / Cloud Metadata (169.254.0.0/16) is restricted' };
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return { isBlocked: true, reason: 'Private Class B address (172.16.0.0/12) is restricted' };
  if (b0 === 192 && b1 === 0 && b2 === 0) return { isBlocked: true, reason: 'IETF Protocol Assignments (192.0.0.0/24) is restricted' };
  if (b0 === 192 && b1 === 0 && b2 === 2) return { isBlocked: true, reason: 'TEST-NET-1 (192.0.2.0/24) is restricted' };
  if (b0 === 192 && b1 === 88 && b2 === 99) return { isBlocked: true, reason: '6to4 relay anycast (192.88.99.0/24) is restricted' };
  if (b0 === 192 && b1 === 168) return { isBlocked: true, reason: 'Private Class C address (192.168.0.0/16) is restricted' };
  if (b0 === 198 && b1 >= 18 && b1 <= 19) return { isBlocked: true, reason: 'Network benchmark testing (198.18.0.0/15) is restricted' };
  if (b0 === 198 && b1 === 51 && b2 === 100) return { isBlocked: true, reason: 'TEST-NET-2 (198.51.100.0/24) is restricted' };
  if (b0 === 203 && b1 === 0 && b2 === 113) return { isBlocked: true, reason: 'TEST-NET-3 (203.0.113.0/24) is restricted' };
  if (b0 >= 224 && b0 <= 239) return { isBlocked: true, reason: 'Multicast address range (224.0.0.0/4) is restricted' };
  if (b0 >= 240) return { isBlocked: true, reason: 'Reserved address range (240.0.0.0/4) is restricted' };
  if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return { isBlocked: true, reason: 'Limited broadcast (255.255.255.255) is restricted' };
  // Cloud Metadata Protection
  if (b0 === 168 && b1 === 63 && b2 === 129 && b3 === 16) return { isBlocked: true, reason: 'Azure Metadata Wire Server (168.63.129.16) is restricted' };
  if (b0 === 100 && b1 === 100 && b2 === 100 && b3 === 200) return { isBlocked: true, reason: 'Alibaba Cloud Metadata Server (100.100.100.200) is restricted' };
  return { isBlocked: false };
}

// 1. SSRF and Network Safety IP Validation with Bitwise CIDR Matching
export function isPrivateOrReservedIP(ip: string): { isBlocked: boolean; reason?: string } {
  const trimmed = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // 1. IPv4 representation parsing (standard dotted-decimal, hex, octal, single integer, 2/3 part)
  const v4Octets = parseIPv4ToOctets(trimmed);
  if (v4Octets) {
    return isPrivateIPv4Octets(v4Octets[0], v4Octets[1], v4Octets[2], v4Octets[3]);
  }

  // 2. IPv6 CIDR / Word Inspection
  const words = parseIPv6Words(trimmed);
  if (words) {
    const [w0, w1, w2, w3, w4, w5, w6, w7] = words;

    // Loopback ::1/128
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) {
      return { isBlocked: true, reason: 'IPv6 loopback address (::1/128) is restricted' };
    }

    // Unspecified ::/128
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 0) {
      return { isBlocked: true, reason: 'IPv6 unspecified address (::/128) is restricted' };
    }

    // Unique Local Address fc00::/7 (fc00:: to fdff:ffff:...)
    // Top 7 bits of w0 must match 1111110 (0x7e)
    if ((w0 >> 9) === 0x7e) {
      return { isBlocked: true, reason: `IPv6 Unique Local Address space fc00::/7 (${trimmed}) is restricted` };
    }

    // Link-Local unicast fe80::/10 (fe80:: to febf:ffff:...)
    // Top 10 bits of w0 must match 1111111010 (0x3fa)
    if ((w0 >> 6) === 0x3fa) {
      return { isBlocked: true, reason: `IPv6 Link-Local address space fe80::/10 (${trimmed}) is restricted` };
    }

    // Multicast ff00::/8
    if ((w0 >> 8) === 0xff) {
      return { isBlocked: true, reason: `IPv6 Multicast address space ff00::/8 (${trimmed}) is restricted` };
    }

    // IPv4-mapped IPv6 ::ffff:0:0/96 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff) {
      const b0 = w6 >> 8;
      const b1 = w6 & 0xff;
      const b2 = w7 >> 8;
      const b3 = w7 & 0xff;
      const v4Check = isPrivateIPv4Octets(b0, b1, b2, b3);
      if (v4Check.isBlocked) {
        return { isBlocked: true, reason: `IPv4-mapped IPv6 restricted destination (${b0}.${b1}.${b2}.${b3}): ${v4Check.reason}` };
      }
    }

    // IPv4-compatible IPv6 ::/96 (deprecated)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && !(w6 === 0 && w7 === 1)) {
      const b0 = w6 >> 8;
      const b1 = w6 & 0xff;
      const b2 = w7 >> 8;
      const b3 = w7 & 0xff;
      const v4Check = isPrivateIPv4Octets(b0, b1, b2, b3);
      if (v4Check.isBlocked) {
        return { isBlocked: true, reason: `IPv4-compatible IPv6 restricted destination (${b0}.${b1}.${b2}.${b3}): ${v4Check.reason}` };
      }
    }

    // 64:ff9b::/96 (IPv4/IPv6 translation)
    if (w0 === 0x0064 && w1 === 0xff9b && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) {
      const b0 = w6 >> 8;
      const b1 = w6 & 0xff;
      const b2 = w7 >> 8;
      const b3 = w7 & 0xff;
      const v4Check = isPrivateIPv4Octets(b0, b1, b2, b3);
      if (v4Check.isBlocked) {
        return { isBlocked: true, reason: `IPv4/IPv6 translated restricted destination (${b0}.${b1}.${b2}.${b3}): ${v4Check.reason}` };
      }
    }

    // 6to4 2002::/16
    if (w0 === 0x2002) {
      const b0 = w1 >> 8;
      const b1 = w1 & 0xff;
      const b2 = w2 >> 8;
      const b3 = w2 & 0xff;
      const v4Check = isPrivateIPv4Octets(b0, b1, b2, b3);
      if (v4Check.isBlocked) {
        return { isBlocked: true, reason: `6to4 encapsulated restricted destination (${b0}.${b1}.${b2}.${b3}): ${v4Check.reason}` };
      }
    }

    // Discard-only prefix 100::/64
    if (w0 === 0x0100 && w1 === 0 && w2 === 0 && w3 === 0) {
      return { isBlocked: true, reason: 'IPv6 Discard-only prefix 100::/64 is restricted' };
    }
  }

  return { isBlocked: false };
}

// Hostname validation
export function validateHostname(input: string): { isValid: boolean; normalized?: string; error?: string } {
  let hostname = input.trim();
  if (!hostname) {
    return { isValid: false, error: 'Target hostname or URL cannot be empty' };
  }

  // Canonicalize URLs or raw decimal/hex/octal representations
  try {
    const toParse = hostname.includes('://') ? hostname : `http://${hostname}`;
    const parsed = new URL(toParse);
    if (hostname.includes('://') && parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { isValid: false, error: `Disallowed URL scheme: ${parsed.protocol} (only HTTP/HTTPS permitted)` };
    }
    // WHATWG canonicalizes alternative IP encodings (0x7f000001, 2130706433, 0177.0.0.1) into dotted decimal
    hostname = parsed.hostname;
  } catch {
    // If not parseable as URL, proceed with raw hostname check
  }

  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Strip trailing dot if present for FQDN
  const withoutTrailingDot = clean.endsWith('.') ? clean.slice(0, -1) : clean;

  if (
    withoutTrailingDot === 'localhost' ||
    withoutTrailingDot === 'localhost.localdomain' ||
    withoutTrailingDot.endsWith('.localhost') ||
    withoutTrailingDot.endsWith('.local') ||
    withoutTrailingDot.endsWith('.internal') ||
    withoutTrailingDot.endsWith('.arpa') ||
    withoutTrailingDot === 'instance-data' ||
    withoutTrailingDot === 'metadata' ||
    withoutTrailingDot.includes('metadata.google') ||
    withoutTrailingDot.includes('169.254.169.254') ||
    withoutTrailingDot.includes('168.63.129.16') ||
    withoutTrailingDot.includes('100.100.100.200')
  ) {
    return { isValid: false, error: 'Restricted destination domain (localhost / private cloud metadata)' };
  }

  // Check if raw IP or parsed IP was passed (covers 2130706433, 0177.0.0.1, 0x7f000001, 127.1, etc.)
  const parsedOctets = parseIPv4ToOctets(withoutTrailingDot);
  if (parsedOctets) {
    const v4Check = isPrivateIPv4Octets(parsedOctets[0], parsedOctets[1], parsedOctets[2], parsedOctets[3]);
    if (v4Check.isBlocked) {
      return { isValid: false, error: v4Check.reason };
    }
  }

  const ipCheck = isPrivateOrReservedIP(withoutTrailingDot);
  if (ipCheck.isBlocked) {
    return { isValid: false, error: ipCheck.reason };
  }

  // Regex check for domain name syntax (if not IP)
  if (!withoutTrailingDot.includes(':') && !/^[0-9.]+$/.test(withoutTrailingDot)) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(withoutTrailingDot)) {
      return { isValid: false, error: 'Invalid hostname format or forbidden characters' };
    }
  }

  if (withoutTrailingDot.length > 253) {
    return { isValid: false, error: 'Hostname exceeds maximum RFC length of 253 characters' };
  }

  return { isValid: true, normalized: withoutTrailingDot };
}

// Socket-level DNS resolution guard preventing DNS Rebinding (TOCTOU attacks)
export function safeDnsLookup(
  hostname: string,
  options: any,
  callback: (err: any, address: any, family?: number) => void
): void {
  const cb = typeof options === 'function' ? options : callback;
  const opts = typeof options === 'function' ? {} : options;

  const hostCheck = validateHostname(hostname);
  if (!hostCheck.isValid) {
    return cb(new Error(`SSRF Block: Hostname ${hostname} is restricted (${hostCheck.error})`), null, 4);
  }

  callbackLookup(hostname, opts, (err: any, address: any, family: any) => {
    if (err) return cb(err, address, family);

    if (Array.isArray(address)) {
      for (const item of address) {
        const ip = typeof item === 'string' ? item : item.address;
        const check = isPrivateOrReservedIP(ip);
        if (check.isBlocked) {
          return cb(new Error(`SSRF / DNS Rebinding Block: Hostname ${hostname} resolved to restricted IP ${ip} (${check.reason})`), null, 4);
        }
      }
      return cb(null, address, family);
    }

    const ip = typeof address === 'string' ? address : (address as any)?.address;
    if (ip) {
      const check = isPrivateOrReservedIP(ip);
      if (check.isBlocked) {
        return cb(new Error(`SSRF / DNS Rebinding Block: Hostname ${hostname} resolved to restricted IP ${ip} (${check.reason})`), null, 4);
      }
    }

    return cb(null, address, family);
  });
}

// Cloud / CDN Heuristic Helper
export function detectCdnOrCloud(ips: string[], nsRecords: string[]): { isDetected: boolean; provider?: string } {
  const nsJoined = nsRecords.join(' ').toLowerCase();
  if (nsJoined.includes('cloudflare.com')) return { isDetected: true, provider: 'Cloudflare' };
  if (nsJoined.includes('awsdns') || nsJoined.includes('cloudfront.net')) return { isDetected: true, provider: 'Amazon Web Services (Route53 / CloudFront)' };
  if (nsJoined.includes('azure-dns')) return { isDetected: true, provider: 'Microsoft Azure DNS' };
  if (nsJoined.includes('googledomains.com')) return { isDetected: true, provider: 'Google Cloud DNS' };
  if (nsJoined.includes('fastly.net')) return { isDetected: true, provider: 'Fastly CDN' };
  if (nsJoined.includes('akamai')) return { isDetected: true, provider: 'Akamai Technologies' };

  for (const ip of ips) {
    if (ip.startsWith('104.') || ip.startsWith('172.64.') || ip.startsWith('172.66.')) {
      return { isDetected: true, provider: 'Cloudflare IP Space' };
    }
  }

  return { isDetected: false };
}

// 2. Security Headers Case-Insensitive Parsing & Hardening Evaluation
export function parseSecurityHeaders(
  rawHeaders: Record<string, string | string[] | undefined> | undefined,
  wasResponseReceived: boolean
): {
  securityHeaders: Record<string, string | null>;
  missingSecurityHeaders: string[];
  headerObservations: SecurityHeaderObservation[];
} {
  const catalog: Array<{
    key: string;
    description: string;
    hardeningRole: string;
  }> = [
    {
      key: 'strict-transport-security',
      description: 'HTTP Strict Transport Security (HSTS)',
      hardeningRole: 'Enforces HTTPS encryption and protects against SSL stripping / downgrade attacks.',
    },
    {
      key: 'content-security-policy',
      description: 'Content Security Policy (CSP)',
      hardeningRole: 'Restricts sources of executable scripts, stylesheets, and images to mitigate XSS and injection.',
    },
    {
      key: 'x-frame-options',
      description: 'X-Frame-Options (XFO)',
      hardeningRole: 'Prevents clickjacking by controlling if the site can be rendered inside <frame>, <iframe>, or <embed>.',
    },
    {
      key: 'x-content-type-options',
      description: 'X-Content-Type-Options',
      hardeningRole: 'Disables MIME-type sniffing, preventing executable content from masquerading as benign media.',
    },
    {
      key: 'referrer-policy',
      description: 'Referrer-Policy',
      hardeningRole: 'Limits the amount of referrer data included with outbound requests to protect user privacy.',
    },
    {
      key: 'permissions-policy',
      description: 'Permissions-Policy',
      hardeningRole: 'Explicitly restricts browser hardware features (camera, microphone, geolocation) accessible to the origin.',
    },
  ];

  // Lowercase keys lookup map
  const normalized: Record<string, string> = {};
  if (rawHeaders) {
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (v !== undefined) {
        normalized[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
      }
    }
  }

  const securityHeaders: Record<string, string | null> = {};
  const missingSecurityHeaders: string[] = [];
  const headerObservations: SecurityHeaderObservation[] = [];

  for (const item of catalog) {
    const val = normalized[item.key] || null;
    securityHeaders[item.description] = val;
    securityHeaders[item.key] = val;

    let status: 'Present' | 'Missing' | 'Unobserved' = 'Unobserved';
    if (wasResponseReceived) {
      status = val ? 'Present' : 'Missing';
      if (!val) {
        missingSecurityHeaders.push(item.description);
      }
    }

    headerObservations.push({
      header: item.description,
      value: val,
      observed: wasResponseReceived && Boolean(val),
      status,
      description: item.description,
      hardeningRole: item.hardeningRole,
      isProofOfExploit: false, // Core requirement: hardening observation != exploitability proof
    });
  }

  return {
    securityHeaders,
    missingSecurityHeaders,
    headerObservations,
  };
}

// 3. Deterministic Documented Risk Scoring Formula
export function calculateRiskScore(params: {
  isTlsValid: boolean | undefined;
  tlsError?: string;
  daysRemaining?: number;
  missingHsts: boolean;
  missingCsp: boolean;
  outdatedBanner?: string;
  rdapStatus?: string;
  dnsFailed: boolean;
  dataCompleteness: number;
}): {
  score: number;
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  factors: string[];
  details: RiskFactorItem[];
  limitations: string[];
} {
  let score = 0;
  const factors: string[] = [];
  const details: RiskFactorItem[] = [];

  // Factor 1: TLS Validity & Trust (+25 pts)
  if (params.isTlsValid === false) {
    const pts = 25;
    score += pts;
    const msg = `Invalid or untrusted TLS certificate (${params.tlsError || 'Handshake / Chain Verification Failed'})`;
    factors.push(msg);
    details.push({
      id: 'tls_invalid',
      category: 'Cryptographic Security',
      title: 'Invalid or Untrusted TLS Certificate',
      weight: pts,
      observedValue: params.tlsError || 'Invalid Certificate',
      rationale: 'Absence of a valid CA trust chain exposes communications to active adversary interception and MITM.',
      mitigation: 'Provision and bind a valid, publicly trusted certificate from an automated CA (e.g., Let\'s Encrypt).',
    });
  }

  // Factor 2: Certificate Impending Expiration (+10 pts)
  if (params.daysRemaining !== undefined && params.daysRemaining > 0 && params.daysRemaining <= 14) {
    const pts = 10;
    score += pts;
    const msg = `TLS certificate expiring soon (${params.daysRemaining} days remaining)`;
    factors.push(msg);
    details.push({
      id: 'tls_expiring',
      category: 'Operational Hygiene',
      title: 'Impending Certificate Expiration',
      weight: pts,
      observedValue: `${params.daysRemaining} days`,
      rationale: 'Certificates expiring within 14 days indicate potential automated renewal failure or unmonitored infrastructure.',
      mitigation: 'Verify automated ACME certificate renewal cron jobs or manually install renewed certificate.',
    });
  }

  // Factor 3: Missing HSTS Header (+10 pts)
  if (params.missingHsts) {
    const pts = 10;
    score += pts;
    const msg = 'Missing Strict-Transport-Security (HSTS) hardening header';
    factors.push(msg);
    details.push({
      id: 'missing_hsts',
      category: 'HTTP Transport Hardening',
      title: 'Missing HSTS Hardening Header',
      weight: pts,
      observedValue: 'Not observed in HTTP response headers',
      rationale: 'HSTS instructs browsers to strictly use HTTPS, mitigating SSL stripping and insecure HTTP initial requests.',
      mitigation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
    });
  }

  // Factor 4: Missing CSP Header (+10 pts)
  if (params.missingCsp) {
    const pts = 10;
    score += pts;
    const msg = 'Missing Content-Security-Policy (CSP) injection defense header';
    factors.push(msg);
    details.push({
      id: 'missing_csp',
      category: 'Application Boundary Defense',
      title: 'Missing Content-Security-Policy (CSP)',
      weight: pts,
      observedValue: 'Not observed in HTTP response headers',
      rationale: 'Absence of CSP increases exposure to cross-site scripting (XSS) and unauthorized dynamic script loading.',
      mitigation: 'Configure a restrictive Content-Security-Policy header defining trusted script and resource origins.',
    });
  }

  // Factor 5: Obsolete / Disclosed Server Banner (+20 pts)
  if (params.outdatedBanner && /(apache\/2\.2|nginx\/1\.0|iis\/6\.0|openssl\/0\.9)/i.test(params.outdatedBanner)) {
    const pts = 20;
    score += pts;
    const msg = `Obsolete or legacy server banner identified: ${params.outdatedBanner}`;
    factors.push(msg);
    details.push({
      id: 'outdated_banner',
      category: 'Software Currency & Fingerprinting',
      title: 'Outdated Server Software Banner Disclosed',
      weight: pts,
      observedValue: params.outdatedBanner,
      rationale: 'Disclosing legacy server versions facilitates automated reconnaissance against end-of-life vulnerabilities.',
      mitigation: 'Upgrade web server package to a supported release and suppress version banners in server tokens.',
    });
  }

  // Factor 6: DNS Failure Inconclusive Condition
  if (params.dnsFailed) {
    factors.push('DNS resolution failed: Domain infrastructure could not be reached');
  }

  // Clamp score between 0 and 100
  const finalScore = Math.min(Math.max(score, 0), 100);

  let level: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
  if (finalScore >= 75) level = 'Critical';
  else if (finalScore >= 50) level = 'High';
  else if (finalScore >= 25) level = 'Medium';

  const limitations = [
    'Deterministic scoring reflects observable perimeter hardening and exposure factors, NOT probability of active compromise.',
    'Missing headers are configuration hardening observations and do not independently prove technical exploitability.',
    'Absence of findings does NOT imply a target is safe (reflects only checks that were technically observable).',
    `Data completeness for this assessment is ${params.dataCompleteness}%.`,
  ];

  return {
    score: finalScore,
    level,
    factors,
    details,
    limitations,
  };
}

// 4. Safe HTTP Probe with SSRF Redirect Checking
export async function performSafeHttpProbe(
  hostname: string,
  options: { timeoutMs?: number; maxRedirects?: number } = {}
): Promise<{
  statusCode?: number;
  statusText?: string;
  probeUrl: string;
  finalUrl: string;
  redirectChain: Array<{ url: string; statusCode?: number }>;
  redirectCount: number;
  httpsEnforced: boolean;
  securityHeaders: Record<string, string | null>;
  missingSecurityHeaders: string[];
  headerObservations: SecurityHeaderObservation[];
  serverBanner?: string;
  contentLength?: number;
  provenance: FieldProvenance;
}> {
  const timeoutMs = options.timeoutMs ?? 3500;
  const maxRedirects = options.maxRedirects ?? 5;
  const initialUrl = `https://${hostname}/`;

  let currentUrl = initialUrl;
  const redirectChain: Array<{ url: string; statusCode?: number }> = [];
  let redirectsFollowed = 0;
  const startTime = new Date().toISOString();

  // Helper for one request step
  const executeStep = (urlStr: string): Promise<{
    statusCode?: number;
    statusText?: string;
    headers: Record<string, string | string[] | undefined>;
    dataLen: number;
    redirectLocation?: string;
  }> => {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (val: any) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(val);
        }
      };
      const fail = (err: any) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      };

      let parsed: URL;
      try {
        parsed = new URL(urlStr);
      } catch (err) {
        return fail(new Error(`Invalid URL structure: ${urlStr}`));
      }

      // Scheme allowlist
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return fail(new Error(`Prohibited URL scheme: ${parsed.protocol}`));
      }

      // SSRF check on target host
      const hostCheck = validateHostname(parsed.hostname);
      if (!hostCheck.isValid) {
        return fail(new Error(`SSRF Block: Redirect target ${parsed.hostname} is restricted (${hostCheck.error})`));
      }

      const isHttps = parsed.protocol === 'https:';
      const transport = isHttps ? https : http;

      const timer = setTimeout(() => {
        try {
          req.destroy();
        } catch {}
        fail(new Error(`HTTP probe timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const req = transport.get(
        parsed,
        {
          lookup: safeDnsLookup,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; VeylithSecurityProbe/2.4; +https://veylith.local)',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        },
        (res) => {
          let dataLen = 0;
          const isRedirect = res.statusCode && [301, 302, 303, 307, 308].includes(res.statusCode);
          const redirectLocation = isRedirect && res.headers.location ? res.headers.location : undefined;

          res.on('data', (chunk) => {
            dataLen += chunk.length;
            // 256KB max response limit
            if (dataLen > 262144) {
              res.destroy();
            }
          });

          const complete = () => {
            finish({
              statusCode: res.statusCode,
              statusText: res.statusMessage,
              headers: res.headers,
              dataLen,
              redirectLocation,
            });
          };

          res.on('end', complete);
          res.on('close', complete);
        }
      );

      req.on('error', (err) => {
        fail(err);
      });
    });
  };

  try {
    let lastStepResult: any;

    while (redirectsFollowed <= maxRedirects) {
      redirectChain.push({ url: currentUrl });
      const step = await executeStep(currentUrl);
      redirectChain[redirectChain.length - 1].statusCode = step.statusCode;
      lastStepResult = step;

      if (step.redirectLocation) {
        redirectsFollowed++;
        if (redirectsFollowed > maxRedirects) {
          throw new Error(`Exceeded maximum redirect limit (${maxRedirects})`);
        }

        // Resolve relative redirects safely
        const nextUrl = new URL(step.redirectLocation, currentUrl).toString();
        // SSRF check on resolved redirect destination
        const nextParsed = new URL(nextUrl);
        const hostCheck = validateHostname(nextParsed.hostname);
        if (!hostCheck.isValid) {
          throw new Error(`SSRF Block: Redirect target ${nextParsed.hostname} is restricted (${hostCheck.error})`);
        }

        currentUrl = nextUrl;
      } else {
        // Final response reached
        break;
      }
    }

    const parsedHeaders = parseSecurityHeaders(lastStepResult?.headers, true);
    const finalUrlObj = new URL(currentUrl);

    return {
      statusCode: lastStepResult?.statusCode,
      statusText: lastStepResult?.statusText,
      probeUrl: initialUrl,
      finalUrl: currentUrl,
      redirectChain,
      redirectCount: redirectsFollowed,
      httpsEnforced: finalUrlObj.protocol === 'https:',
      securityHeaders: parsedHeaders.securityHeaders,
      missingSecurityHeaders: parsedHeaders.missingSecurityHeaders,
      headerObservations: parsedHeaders.headerObservations,
      serverBanner: lastStepResult?.headers ? (lastStepResult.headers['server'] as string) || undefined : undefined,
      contentLength: lastStepResult?.dataLen || 0,
      provenance: {
        status: 'Retrieved',
        source: `Safe HTTP Probe (${currentUrl})`,
        timestamp: startTime,
        details: `Final status HTTP ${lastStepResult?.statusCode} with ${redirectsFollowed} redirects followed.`,
      },
    };
  } catch (err: any) {
    const isTimeout = String(err.message).toLowerCase().includes('timed out');
    const isSsrf = String(err.message).toLowerCase().includes('ssrf block');

    const emptyHeaders = parseSecurityHeaders(undefined, false);

    return {
      probeUrl: initialUrl,
      finalUrl: currentUrl,
      redirectChain,
      redirectCount: redirectsFollowed,
      httpsEnforced: false,
      securityHeaders: emptyHeaders.securityHeaders,
      missingSecurityHeaders: [],
      headerObservations: emptyHeaders.headerObservations,
      provenance: {
        status: isSsrf ? 'Blocked' : isTimeout ? 'TimedOut' : 'Unavailable',
        source: `Safe HTTP Probe (${initialUrl})`,
        timestamp: startTime,
        details: err.message,
      },
    };
  }
}

// 5. TLS Handshake & Certificate Inspection
export async function performTlsInspection(
  hostname: string,
  timeoutMs = 3500
): Promise<{
  valid: boolean;
  hostnameMatched: boolean;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  protocol?: string;
  cipher?: string;
  error?: string;
  provenance: FieldProvenance;
}> {
  const startTime = new Date().toISOString();

  return new Promise((resolve) => {
    let finished = false;
    const finish = (result: any) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        resolve(result);
      }
    };

    const timer = setTimeout(() => {
      try {
        socket.destroy();
      } catch {}
      finish({
        valid: false,
        hostnameMatched: false,
        error: `TLS handshake connection timed out after ${timeoutMs}ms`,
        provenance: {
          status: 'TimedOut',
          source: `TLS Handshake (Port 443 ${hostname})`,
          timestamp: startTime,
          details: `Connection to port 443 exceeded timeout of ${timeoutMs}ms`,
        },
      });
    }, timeoutMs);

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        lookup: safeDnsLookup,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();

          if (cert && Object.keys(cert).length > 0) {
            const validTo = new Date(cert.valid_to);
            const now = new Date();
            const daysRemaining = Math.round((validTo.getTime() - now.getTime()) / (1000 * 3600 * 24));
            const isAuthorized = socket.authorized;
            const isValid = daysRemaining > 0 && isAuthorized;

            const formatCertField = (field: any): string => {
              if (!field) return '';
              if (Array.isArray(field)) return field.join(', ');
              if (typeof field === 'object') return Object.entries(field).map(([k, v]) => `${k}=${v}`).join(', ');
              return String(field);
            };

            const subjectStr = typeof cert.subject === 'object' ? formatCertField(cert.subject.CN || cert.subject) : String(cert.subject);
            const issuerStr = typeof cert.issuer === 'object' ? formatCertField(cert.issuer.O || cert.issuer.CN || cert.issuer) : String(cert.issuer);

            // Check if hostname matches certificate SAN or CN
            let hostnameMatched = false;
            if (cert.subjectaltname) {
              const sans = cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/i, '').toLowerCase());
              hostnameMatched = sans.some((san) => {
                if (san.startsWith('*.')) {
                  const root = san.slice(2);
                  return hostname.endsWith(root) || hostname === root;
                }
                return san === hostname.toLowerCase();
              });
            } else if (cert.subject?.CN) {
              const cn = String(cert.subject.CN).toLowerCase();
              hostnameMatched = cn === hostname.toLowerCase();
            }

            try {
              socket.destroy();
            } catch {}

            return finish({
              valid: isValid,
              hostnameMatched,
              subject: subjectStr,
              issuer: issuerStr,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              protocol: protocol || 'Unknown',
              cipher: cipher?.name,
              provenance: {
                status: 'Retrieved',
                source: `TLS Handshake (Port 443 SNI: ${hostname})`,
                timestamp: startTime,
                details: isValid ? 'Valid TLS certificate chain verified.' : `Authorization error: ${socket.authorizationError || 'Untrusted chain'}`,
              },
            });
          }
        } catch (e: any) {
          try {
            socket.destroy();
          } catch {}
          return finish({
            valid: false,
            hostnameMatched: false,
            error: `Certificate parsing error: ${e.message}`,
            provenance: {
              status: 'Unavailable',
              source: `TLS Handshake (Port 443 ${hostname})`,
              timestamp: startTime,
              details: e.message,
            },
          });
        }

        try {
          socket.destroy();
        } catch {}
        finish({
          valid: false,
          hostnameMatched: false,
          error: 'No peer certificate presented by remote host',
          provenance: {
            status: 'Unavailable',
            source: `TLS Handshake (Port 443 ${hostname})`,
            timestamp: startTime,
            details: 'Empty peer certificate',
          },
        });
      }
    );

    socket.on('error', (err) => {
      try {
        socket.destroy();
      } catch {}
      finish({
        valid: false,
        hostnameMatched: false,
        error: `Port 443 TLS handshake failed: ${err.message}`,
        provenance: {
          status: 'Unavailable',
          source: `TLS Handshake (Port 443 ${hostname})`,
          timestamp: startTime,
          details: err.message,
        },
      });
    });
  });
}

// 6. RDAP Public Registry Lookup with strict error preservation and rate limit handling
export async function performRdapLookup(
  hostname: string,
  timeoutMs = 3000
): Promise<{
  status: 'Retrieved' | 'Unavailable' | 'RateLimited' | 'Forbidden' | 'TimedOut';
  sourceUrl: string;
  httpStatusCode?: number;
  handle?: string;
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastChangedDate?: string;
  domainStatus?: string[];
  entities?: Array<{ handle?: string; roles?: string[]; name?: string }>;
  rawHandle?: string;
  errorDetails?: string;
  provenance: FieldProvenance;
}> {
  const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(hostname)}`;
  const startTime = new Date().toISOString();

  try {
    const res = await fetch(rdapUrl, {
      headers: {
        'User-Agent': 'Veylith-DFIR-Recon/2.4 (+https://veylith.local)',
        Accept: 'application/rdap+json, application/json',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (res.ok) {
      const data = await res.json();

      let regDate: string | undefined;
      let expDate: string | undefined;
      let changeDate: string | undefined;

      if (Array.isArray(data.events)) {
        for (const ev of data.events) {
          if (ev.eventAction === 'registration') regDate = ev.eventDate;
          else if (ev.eventAction === 'expiration') expDate = ev.eventDate;
          else if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') changeDate = ev.eventDate;
        }
      }

      // Extract registrar entity accurately without guessing
      let registrarName: string | undefined;
      if (Array.isArray(data.entities)) {
        const registrarEntity = data.entities.find((ent: any) =>
          Array.isArray(ent.roles) && ent.roles.includes('registrar')
        );
        if (registrarEntity) {
          registrarName = registrarEntity.vcardArray?.[1]?.find((f: any) => f[0] === 'fn')?.[3] || registrarEntity.handle;
        }
      }

      return {
        status: 'Retrieved',
        sourceUrl: rdapUrl,
        httpStatusCode: res.status,
        handle: data.handle,
        registrar: registrarName || 'Registrar role not declared in RDAP record',
        registrationDate: regDate,
        expirationDate: expDate,
        lastChangedDate: changeDate,
        domainStatus: Array.isArray(data.status) ? data.status : [],
        entities: data.entities?.map((e: any) => ({
          roles: e.roles,
          handle: e.handle,
          name: e.vcardArray?.[1]?.find((f: any) => f[0] === 'fn')?.[3],
        })),
        rawHandle: data.handle,
        provenance: {
          status: 'Retrieved',
          source: `RDAP Registry (${rdapUrl})`,
          timestamp: startTime,
          details: `RDAP record successfully fetched (HTTP ${res.status}).`,
        },
      };
    }

    // Handle HTTP error statuses explicitly per requirement 2
    let status: 'Unavailable' | 'RateLimited' | 'Forbidden' | 'TimedOut' = 'Unavailable';
    let errorMsg = `RDAP registry query returned HTTP ${res.status} (${res.statusText})`;

    if (res.status === 403) {
      status = 'Forbidden';
      errorMsg = 'RDAP registry access forbidden (HTTP 403). Registration data cannot be inferred without authenticated authority.';
    } else if (res.status === 429) {
      status = 'RateLimited';
      errorMsg = 'RDAP query rate-limited by upstream registry server (HTTP 429).';
    }

    return {
      status,
      sourceUrl: rdapUrl,
      httpStatusCode: res.status,
      errorDetails: errorMsg,
      provenance: {
        status: status === 'Forbidden' ? 'Blocked' : 'Unavailable',
        source: `RDAP Registry (${rdapUrl})`,
        timestamp: startTime,
        details: errorMsg,
      },
    };
  } catch (err: any) {
    const isTimeout = String(err.name === 'TimeoutError' || err.message?.includes('timed out'));
    const status = isTimeout ? 'TimedOut' : 'Unavailable';
    const errorMsg = `RDAP lookup unavailable: ${err.message}`;

    return {
      status,
      sourceUrl: rdapUrl,
      errorDetails: errorMsg,
      provenance: {
        status: isTimeout ? 'TimedOut' : 'Unavailable',
        source: `RDAP Registry (${rdapUrl})`,
        timestamp: startTime,
        details: errorMsg,
      },
    };
  }
}

// 7. Complete Domain Investigation Coordinator
export async function runDomainInvestigation(target: string): Promise<
  | { success: true; report: DomainAnalysisReport }
  | { success: false; error: string; securityBlocked: boolean; target: string; resolvedProhibitedIp?: string }
> {
  const hostVal = validateHostname(target);
  if (!hostVal.isValid || !hostVal.normalized) {
    return {
      success: false,
      error: `SSRF Policy Violation: ${hostVal.error}`,
      securityBlocked: true,
      target,
    };
  }

  const hostname = hostVal.normalized;
  const analysisTimestamp = new Date().toISOString();
  const uncompletedChecks: Array<{ check: string; reason: string; category: string }> = [];

  const checkedAddresses: string[] = [];

  // Step 1: DNS Resolution with Strict SSRF Verification on all resolved IP addresses
  const resolvedIps: { ip: string; version: number; resolver?: string; isCdnOrCloud?: boolean }[] = [];
  const dnsRecords: DomainAnalysisReport['dnsRecords'] = {
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
  };

  let dnsFailed = false;

  try {
    const [aRes, aaaaRes, mxRes, txtRes, nsRes, cnameRes] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
      dns.resolveMx(hostname),
      dns.resolveTxt(hostname),
      dns.resolveNs(hostname),
      dns.resolveCname(hostname),
    ]);

    // Handle A records
    if (aRes.status === 'fulfilled') {
      dnsRecords.a = aRes.value;
      for (const ip of aRes.value) {
        checkedAddresses.push(ip);
        const check = isPrivateOrReservedIP(ip);
        if (check.isBlocked) {
          return {
            success: false,
            error: `SSRF Block: Domain ${hostname} resolves to prohibited IPv4 ${ip} (${check.reason})`,
            securityBlocked: true,
            target: hostname,
            resolvedProhibitedIp: ip,
          };
        }
        resolvedIps.push({ ip, version: 4, resolver: 'System / Local Resolv.conf' });
      }
    } else {
      uncompletedChecks.push({
        check: 'DNS A (IPv4)',
        reason: (aRes as PromiseRejectedResult).reason?.message || 'No A records returned',
        category: 'DNS',
      });
    }

    // Handle AAAA records
    if (aaaaRes.status === 'fulfilled') {
      dnsRecords.aaaa = aaaaRes.value;
      for (const ip of aaaaRes.value) {
        checkedAddresses.push(ip);
        const check = isPrivateOrReservedIP(ip);
        if (check.isBlocked) {
          return {
            success: false,
            error: `SSRF Block: Domain ${hostname} resolves to prohibited IPv6 ${ip} (${check.reason})`,
            securityBlocked: true,
            target: hostname,
            resolvedProhibitedIp: ip,
          };
        }
        resolvedIps.push({ ip, version: 6, resolver: 'System / Local Resolv.conf' });
      }
    }

    if (resolvedIps.length === 0) {
      dnsFailed = true;
      uncompletedChecks.push({
        check: 'DNS Host Resolution',
        reason: 'Zero valid A or AAAA records resolved for target',
        category: 'DNS',
      });
    }

    // MX
    if (mxRes.status === 'fulfilled') {
      dnsRecords.mx = mxRes.value;
    } else {
      uncompletedChecks.push({
        check: 'DNS MX Records',
        reason: 'No mail exchanger records configured',
        category: 'DNS',
      });
    }

    // TXT
    if (txtRes.status === 'fulfilled') {
      dnsRecords.txt = txtRes.value;
    } else {
      uncompletedChecks.push({
        check: 'DNS TXT Records',
        reason: 'No TXT or SPF records found',
        category: 'DNS',
      });
    }

    // NS
    if (nsRes.status === 'fulfilled') {
      dnsRecords.ns = nsRes.value;
    } else {
      uncompletedChecks.push({
        check: 'DNS Nameservers',
        reason: 'Nameserver lookup query unfulfilled',
        category: 'DNS',
      });
    }

    // CNAME
    if (cnameRes.status === 'fulfilled') {
      dnsRecords.cname = cnameRes.value;
    }
  } catch (err: any) {
    dnsFailed = true;
    uncompletedChecks.push({
      check: 'DNS Query Suite',
      reason: err.message || 'DNS resolution failed',
      category: 'DNS',
    });
  }

  // Detect CDN / Cloud Infrastructure
  const cdn = detectCdnOrCloud(dnsRecords.a, dnsRecords.ns);
  if (cdn.isDetected) {
    resolvedIps.forEach((r) => {
      r.isCdnOrCloud = true;
    });
  }

  const dnsProvenance: FieldProvenance = {
    status: dnsFailed ? 'Unavailable' : 'Retrieved',
    source: 'Node.js DNS Asynchronous Resolver (node:dns/promises)',
    timestamp: analysisTimestamp,
    details: dnsFailed ? 'DNS resolution failed for hostname' : `Resolved ${resolvedIps.length} IP address(es) across ${dnsRecords.a.length} A and ${dnsRecords.aaaa.length} AAAA records.`,
  };

  // Step 2 & 3: Run TLS and HTTP Probes in parallel if DNS succeeded
  let tlsResult: any = undefined;
  let httpResult: any = undefined;

  if (!dnsFailed) {
    const [tlsSettled, httpSettled] = await Promise.allSettled([
      performTlsInspection(hostname, 3500),
      performSafeHttpProbe(hostname, { timeoutMs: 3500 }),
    ]);

    if (tlsSettled.status === 'fulfilled') {
      tlsResult = tlsSettled.value;
      if (tlsResult.error) {
        uncompletedChecks.push({
          check: 'TLS Certificate Handshake',
          reason: tlsResult.error,
          category: 'TLS',
        });
      }
    } else {
      uncompletedChecks.push({
        check: 'TLS Port 443 Handshake',
        reason: tlsSettled.reason?.message || 'Handshake failed',
        category: 'TLS',
      });
    }

    if (httpSettled.status === 'fulfilled') {
      httpResult = httpSettled.value;
      if (httpResult.provenance.status !== 'Retrieved') {
        uncompletedChecks.push({
          check: 'HTTP Security Headers Probe',
          reason: httpResult.provenance.details || 'HTTP probe incomplete',
          category: 'HTTP',
        });
      }
    } else {
      uncompletedChecks.push({
        check: 'HTTP Probe',
        reason: httpSettled.reason?.message || 'Connection failed',
        category: 'HTTP',
      });
    }
  } else {
    uncompletedChecks.push({
      check: 'TLS & HTTP Probes',
      reason: 'Probes skipped because target DNS could not be resolved',
      category: 'Network',
    });
  }

  // Step 4: RDAP Lookup
  const rdapResult = await performRdapLookup(hostname, 3000);
  if (rdapResult.status !== 'Retrieved') {
    uncompletedChecks.push({
      check: 'RDAP Domain Registration Registry',
      reason: rdapResult.errorDetails || `Query status: ${rdapResult.status}`,
      category: 'RDAP',
    });
  }

  // Calculate Data Completeness Percentage
  const totalProbeComponents = 4; // DNS, TLS, HTTP, RDAP
  let successfulComponents = 0;
  if (!dnsFailed) successfulComponents++;
  if (tlsResult && tlsResult.valid !== undefined && !tlsResult.error) successfulComponents++;
  if (httpResult && httpResult.statusCode) successfulComponents++;
  if (rdapResult && rdapResult.status === 'Retrieved') successfulComponents++;
  const dataCompleteness = Math.round((successfulComponents / totalProbeComponents) * 100);

  // Calculate Risk Scoring
  const isTlsValid = tlsResult ? tlsResult.valid : undefined;
  const daysRemaining = tlsResult ? tlsResult.daysRemaining : undefined;
  const missingHsts = httpResult ? httpResult.missingSecurityHeaders.includes('HTTP Strict Transport Security (HSTS)') : false;
  const missingCsp = httpResult ? httpResult.missingSecurityHeaders.includes('Content Security Policy (CSP)') : false;
  const outdatedBanner = httpResult?.serverBanner;

  const riskAssessment = calculateRiskScore({
    isTlsValid,
    tlsError: tlsResult?.error,
    daysRemaining,
    missingHsts,
    missingCsp,
    outdatedBanner,
    rdapStatus: rdapResult.status,
    dnsFailed,
    dataCompleteness,
  });

  const report: DomainAnalysisReport = {
    domain: hostname,
    targetNormalized: hostname,
    analysisTimestamp,
    engineVersion: ENGINE_VERSION,
    provenance: {
      dns: dnsProvenance,
      tls: tlsResult?.provenance || {
        status: 'NotChecked',
        source: 'TLS Handshake',
        timestamp: analysisTimestamp,
        details: 'TLS check not executed',
      },
      http: httpResult?.provenance || {
        status: 'NotChecked',
        source: 'Safe HTTP Probe',
        timestamp: analysisTimestamp,
        details: 'HTTP check not executed',
      },
      rdap: rdapResult.provenance,
    },
    resolvedIps,
    dnsRecords,
    tlsCertificate: tlsResult
      ? {
          valid: tlsResult.valid,
          hostnameMatched: tlsResult.hostnameMatched,
          subject: tlsResult.subject,
          issuer: tlsResult.issuer,
          validFrom: tlsResult.validFrom,
          validTo: tlsResult.validTo,
          daysRemaining: tlsResult.daysRemaining,
          protocol: tlsResult.protocol,
          cipher: tlsResult.cipher,
          error: tlsResult.error,
          provenance: tlsResult.provenance,
        }
      : undefined,
    httpProbe: httpResult
      ? {
          statusCode: httpResult.statusCode,
          statusText: httpResult.statusText,
          probeUrl: httpResult.probeUrl,
          finalUrl: httpResult.finalUrl,
          redirectChain: httpResult.redirectChain,
          redirectCount: httpResult.redirectCount,
          httpsEnforced: httpResult.httpsEnforced,
          securityHeaders: httpResult.securityHeaders,
          missingSecurityHeaders: httpResult.missingSecurityHeaders,
          headerObservations: httpResult.headerObservations,
          serverBanner: httpResult.serverBanner,
          contentLength: httpResult.contentLength,
          provenance: httpResult.provenance,
        }
      : undefined,
    rdap: {
      status: rdapResult.status,
      sourceUrl: rdapResult.sourceUrl,
      httpStatusCode: rdapResult.httpStatusCode,
      handle: rdapResult.handle,
      registrar: rdapResult.registrar,
      registrationDate: rdapResult.registrationDate,
      expirationDate: rdapResult.expirationDate,
      lastChangedDate: rdapResult.lastChangedDate,
      domainStatus: rdapResult.domainStatus,
      entities: rdapResult.entities,
      rawHandle: rdapResult.rawHandle,
      errorDetails: rdapResult.errorDetails,
      provenance: rdapResult.provenance,
    },
    uncompletedChecks,
    riskScore: riskAssessment.score,
    riskLevel: riskAssessment.level,
    riskFactors: riskAssessment.factors,
    riskFactorDetails: riskAssessment.details,
    scoringLimitations: riskAssessment.limitations,
    dataCompleteness,
    ssrfGuards: {
      passed: true,
      checkedAddresses,
    },
  };

  report.aiSecurityAnalysis = generateDeterministicDomainAnalysis(report);

  return { success: true, report };
}
