import { lookup as callbackLookup } from 'node:dns';
import { URL } from 'node:url';

export const PERMITTED_WEB_PORTS = new Set(['', '80', '443', '8080', '8443']);

/**
 * Checks IPv4 octets against IETF RFC special-use & private ranges,
 * plus major cloud provider metadata addresses.
 */
export function isPrivateIPv4Octets(
  b0: number,
  b1: number,
  b2: number,
  b3: number
): { isBlocked: boolean; reason?: string } {
  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return { isBlocked: true, reason: 'Current network (0.0.0.0/8) is restricted' };

  // 10.0.0.0/8 (Private Class A - RFC 1918)
  if (b0 === 10) return { isBlocked: true, reason: 'Private Class A address (10.0.0.0/8) is restricted' };

  // 100.100.100.200 (Alibaba Cloud internal metadata server)
  if (b0 === 100 && b1 === 100 && b2 === 100 && b3 === 200) {
    return { isBlocked: true, reason: 'Cloud instance metadata service (100.100.100.200) is restricted' };
  }

  // 100.64.0.0/10 (Carrier-grade NAT - RFC 6598)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) {
    return { isBlocked: true, reason: 'Carrier-grade NAT (100.64.0.0/10) is restricted' };
  }

  // 127.0.0.0/8 (Loopback - RFC 1122)
  if (b0 === 127) return { isBlocked: true, reason: 'Loopback address (127.0.0.0/8) is restricted' };

  // 169.254.0.0/16 (Link-local & AWS/GCP/Azure metadata 169.254.169.254 - RFC 3927)
  if (b0 === 169 && b1 === 254) {
    return { isBlocked: true, reason: 'Link-local / Cloud Metadata (169.254.0.0/16) is restricted' };
  }

  // 172.16.0.0/12 (Private Class B - RFC 1918)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) {
    return { isBlocked: true, reason: 'Private Class B address (172.16.0.0/12) is restricted' };
  }

  // 192.0.0.0/24 (IETF Protocol Assignments - RFC 6890)
  if (b0 === 192 && b1 === 0 && b2 === 0) {
    return { isBlocked: true, reason: 'IETF Protocol Assignments (192.0.0.0/24) is restricted' };
  }

  // 192.0.2.0/24 (TEST-NET-1 - RFC 5737)
  if (b0 === 192 && b1 === 0 && b2 === 2) {
    return { isBlocked: true, reason: 'TEST-NET-1 (192.0.2.0/24) documentation range is restricted' };
  }

  // 192.88.99.0/24 (6to4 relay anycast - RFC 3068 / RFC 7526)
  if (b0 === 192 && b1 === 88 && b2 === 99) {
    return { isBlocked: true, reason: '6to4 relay anycast (192.88.99.0/24) is restricted' };
  }

  // 192.168.0.0/16 (Private Class C - RFC 1918)
  if (b0 === 192 && b1 === 168) {
    return { isBlocked: true, reason: 'Private Class C address (192.168.0.0/16) is restricted' };
  }

  // 198.18.0.0/15 (Network benchmark testing - RFC 2544)
  if (b0 === 198 && b1 >= 18 && b1 <= 19) {
    return { isBlocked: true, reason: 'Network benchmark testing (198.18.0.0/15) is restricted' };
  }

  // 198.51.100.0/24 (TEST-NET-2 - RFC 5737)
  if (b0 === 198 && b1 === 51 && b2 === 100) {
    return { isBlocked: true, reason: 'TEST-NET-2 (198.51.100.0/24) documentation range is restricted' };
  }

  // 203.0.113.0/24 (TEST-NET-3 - RFC 5737)
  if (b0 === 203 && b1 === 0 && b2 === 113) {
    return { isBlocked: true, reason: 'TEST-NET-3 (203.0.113.0/24) documentation range is restricted' };
  }

  // 224.0.0.0/4 (Multicast - RFC 5771)
  if (b0 >= 224 && b0 <= 239) {
    return { isBlocked: true, reason: 'Multicast address range (224.0.0.0/4) is restricted' };
  }

  // 240.0.0.0/4 (Reserved / Future Use - RFC 1112)
  if (b0 >= 240) {
    return { isBlocked: true, reason: 'Reserved address range (240.0.0.0/4) is restricted' };
  }

  // 255.255.255.255 (Limited Broadcast)
  if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) {
    return { isBlocked: true, reason: 'Limited broadcast (255.255.255.255) is restricted' };
  }

  return { isBlocked: false };
}

/**
 * Parses any valid IPv4 representation (dot-decimal, octal, hex, or 32-bit integer)
 * into 4 numerical octets [b0, b1, b2, b3], or returns null if not an IPv4 string.
 */
export function parseIPv4AnyFormat(input: string): [number, number, number, number] | null {
  const clean = input.trim();

  // 1. Single 32-bit integer representation (e.g. 2130706433 or 0)
  if (/^\d+$/.test(clean)) {
    const num = Number(clean);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      const b0 = (num >>> 24) & 0xff;
      const b1 = (num >>> 16) & 0xff;
      const b2 = (num >>> 8) & 0xff;
      const b3 = num & 0xff;
      return [b0, b1, b2, b3];
    }
    return null;
  }

  // 2. Single hex integer (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(clean)) {
    const num = parseInt(clean, 16);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      const b0 = (num >>> 24) & 0xff;
      const b1 = (num >>> 16) & 0xff;
      const b2 = (num >>> 8) & 0xff;
      const b3 = num & 0xff;
      return [b0, b1, b2, b3];
    }
    return null;
  }

  // 3. Dot-separated notation (1 to 4 parts)
  if (clean.includes('.')) {
    const parts = clean.split('.');
    if (parts.length > 4 || parts.length === 0) return null;

    const parsedParts: number[] = [];
    for (const part of parts) {
      let val: number;
      if (/^0x[0-9a-f]+$/i.test(part)) {
        val = parseInt(part, 16);
      } else if (/^0[0-7]+$/.test(part)) {
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return null;
      }
      if (isNaN(val) || val < 0) return null;
      parsedParts.push(val);
    }

    if (parsedParts.length === 4) {
      if (parsedParts.some((p) => p > 255)) return null;
      return [parsedParts[0], parsedParts[1], parsedParts[2], parsedParts[3]];
    }

    // Shorthand notation (e.g. 127.1 -> 127.0.0.1)
    if (parsedParts.length === 2) {
      const b0 = parsedParts[0];
      const remainder = parsedParts[1];
      if (b0 > 255 || remainder > 0xffffff) return null;
      return [b0, (remainder >>> 16) & 0xff, (remainder >>> 8) & 0xff, remainder & 0xff];
    }

    if (parsedParts.length === 3) {
      const b0 = parsedParts[0];
      const b1 = parsedParts[1];
      const remainder = parsedParts[2];
      if (b0 > 255 || b1 > 255 || remainder > 0xffff) return null;
      return [b0, b1, (remainder >>> 8) & 0xff, remainder & 0xff];
    }
  }

  return null;
}

/**
 * Parses an IPv6 address string into 8 16-bit words (RFC 4291).
 * Handles embedded IPv4 dot-decimal representations.
 */
export function parseIPv6Words(ip: string): number[] | null {
  let clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // Handle embedded IPv4 dot-decimal at end (e.g. ::ffff:127.0.0.1)
  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = parseIPv4AnyFormat(v4Part);
    if (!v4Octets) return null;
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

/**
 * Comprehensive SSRF and Network Safety IP Validation with bitwise CIDR matching.
 * Validates both IPv4 (all formats) and IPv6 against private, reserved, and metadata ranges.
 */
export function isPrivateOrReservedIP(ip: string): { isBlocked: boolean; reason?: string } {
  const trimmed = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // 1. Check if input is IPv4 in any supported notation
  const v4Octets = parseIPv4AnyFormat(trimmed);
  if (v4Octets) {
    return isPrivateIPv4Octets(v4Octets[0], v4Octets[1], v4Octets[2], v4Octets[3]);
  }

  // 2. Check if input is IPv6
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

    // Unique Local Address fc00::/7 (covers fc00:: through fdff:ffff:... including AWS metadata fd00:ec2::254)
    if ((w0 >> 9) === 0x7e) {
      return { isBlocked: true, reason: `IPv6 Unique Local Address space fc00::/7 (${trimmed}) is restricted` };
    }

    // Link-Local unicast fe80::/10 (fe80:: to febf:ffff:...)
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

    // 64:ff9b::/96 (IPv4/IPv6 translation - RFC 6052)
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

/**
 * Validates a target hostname or URL before initiation of network actions.
 * Enforces protocol allowlists, port restrictions, metadata endpoints, and RFC hostname syntax.
 */
export function validateHostname(input: string): {
  isValid: boolean;
  normalized?: string;
  port?: string;
  error?: string;
} {
  let hostname = input.trim();
  if (!hostname) {
    return { isValid: false, error: 'Target hostname or URL cannot be empty' };
  }

  let extractedPort = '';

  // Canonicalize URLs or raw decimal/hex/octal representations
  try {
    const toParse = hostname.includes('://') ? hostname : `http://${hostname}`;
    const parsed = new URL(toParse);

    if (hostname.includes('://') && parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { isValid: false, error: `Disallowed URL scheme: ${parsed.protocol} (only HTTP/HTTPS permitted)` };
    }

    if (parsed.port && !PERMITTED_WEB_PORTS.has(parsed.port)) {
      return {
        isValid: false,
        error: `Port ${parsed.port} is not permitted for security probing (only standard web ports 80, 443, 8080, 8443 allowed)`,
      };
    }
    extractedPort = parsed.port;
    hostname = parsed.hostname;
  } catch {
    // If not parseable as URL, proceed with raw string checks
  }

  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const withoutTrailingDot = clean.endsWith('.') ? clean.slice(0, -1) : clean;

  // Check if raw IP or parsed IP was passed
  const ipCheck = isPrivateOrReservedIP(withoutTrailingDot);
  if (ipCheck.isBlocked) {
    return { isValid: false, error: ipCheck.reason };
  }

  // Cloud metadata and private hostname indicators
  if (
    withoutTrailingDot === 'localhost' ||
    withoutTrailingDot.endsWith('.localhost')
  ) {
    return { isValid: false, error: 'Restricted destination domain (localhost / loopback)' };
  }

  if (
    withoutTrailingDot.endsWith('.local') ||
    withoutTrailingDot.endsWith('.internal') ||
    withoutTrailingDot.endsWith('.arpa') ||
    withoutTrailingDot.includes('metadata.google') ||
    withoutTrailingDot.includes('metadata.internal') ||
    withoutTrailingDot.includes('instance-data')
  ) {
    return { isValid: false, error: 'Restricted destination domain (cloud internal / metadata)' };
  }

  // Domain name syntax regex (RFC 1035 compliant)
  if (!withoutTrailingDot.includes(':') && !/^[0-9.]+$/.test(withoutTrailingDot)) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(withoutTrailingDot)) {
      return { isValid: false, error: 'Invalid hostname format or forbidden characters' };
    }
  }

  if (withoutTrailingDot.length > 253) {
    return { isValid: false, error: 'Hostname exceeds maximum RFC length of 253 characters' };
  }

  return { isValid: true, normalized: withoutTrailingDot, port: extractedPort };
}

/**
 * Socket-level DNS resolution guard preventing DNS Rebinding (TOCTOU attacks).
 * Intercepts every socket connection immediately before connect() executes.
 */
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
          return cb(
            new Error(`SSRF / DNS Rebinding Block: Hostname ${hostname} resolved to restricted IP ${ip} (${check.reason})`),
            null,
            4
          );
        }
      }
      return cb(null, address, family);
    }

    const ip = typeof address === 'string' ? address : (address as any)?.address;
    if (ip) {
      const check = isPrivateOrReservedIP(ip);
      if (check.isBlocked) {
        return cb(
          new Error(`SSRF / DNS Rebinding Block: Hostname ${hostname} resolved to restricted IP ${ip} (${check.reason})`),
          null,
          4
        );
      }
    }

    return cb(null, address, family);
  });
}
