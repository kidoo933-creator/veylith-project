import {
  DomainAnalysisReport,
  DomainAiSecurityAnalysis,
  DomainSecurityFindingAnalysis,
  PrioritizedNextStep,
  InvestigationSimpleReport,
  FindingRemediationGuide,
} from '../types';
import { classifyFindingConfidence } from './aiEvidenceGrounding';

export const AI_ANALYST_DISCLAIMER =
  'This analysis is based on observed scan results. Potential risks are not proof of exploitability. Further authorized testing may be required.';

export type DetectedServerTech = 'nginx' | 'apache' | 'cloudflare' | 'express' | 'caddy' | 'generic';

/**
 * Detects the web server or hosting technology from the HTTP Server header or banner.
 */
export function detectServerTechnology(serverBanner?: string): DetectedServerTech {
  if (!serverBanner) return 'generic';
  const s = serverBanner.toLowerCase();
  if (s.includes('nginx')) return 'nginx';
  if (s.includes('apache')) return 'apache';
  if (s.includes('cloudflare')) return 'cloudflare';
  if (s.includes('express') || s.includes('node')) return 'express';
  if (s.includes('caddy')) return 'caddy';
  return 'generic';
}

/**
 * Builds actionable, concrete technology-specific remediation snippets,
 * exact configuration locations, curl verification commands, and documentation links.
 */
export function buildHeaderRemediationGuide(
  headerKey: 'csp' | 'xfo' | 'xcto' | 'hsts' | 'referrer' | 'permissions',
  domain: string,
  serverBanner?: string
): FindingRemediationGuide {
  const tech = detectServerTechnology(serverBanner);
  const targetDomain = domain || 'example.com';

  switch (headerKey) {
    case 'csp':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express (helmet)\nconst helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    styleSrc: ["'self'", "'unsafe-inline'"],\n    imgSrc: ["'self'", 'data:', 'https:'],\n    objectSrc: ["'none'"],\n    baseUri: ["'self'"]\n  }\n}));`
            : tech === 'caddy'
            ? `header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self';"`
            : `# Nginx Web Server Directive\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/conf-available/security.conf (or .htaccess)'
            : tech === 'express'
            ? 'src/server.ts or app.js (Express Middleware Pipeline)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/security.conf (or /etc/nginx/sites-available/default)',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "content-security-policy"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
        thirdPartyHostedNote:
          'If hosted behind Cloudflare, navigate to Rules > Transform Rules > Modify Response Header. Add header "Content-Security-Policy" with value "default-src \'self\'; script-src \'self\'; object-src \'none\';". On AWS CloudFront, attach a Response Headers Policy.',
        alternativeConfigs: [
          {
            technology: 'Nginx',
            snippet: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self';" always;`,
            location: '/etc/nginx/conf.d/security.conf',
          },
          {
            technology: 'Apache',
            snippet: `<IfModule mod_headers.c>\n  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"\n</IfModule>`,
            location: '/etc/apache2/conf-available/security.conf',
          },
          {
            technology: 'Node.js / Express',
            snippet: `const helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy());`,
            location: 'server.js (Middleware)',
          },
        ],
      };

    case 'xfo':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set X-Frame-Options "SAMEORIGIN"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express\napp.use((req, res, next) => {\n  res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n  next();\n});`
            : tech === 'caddy'
            ? `header X-Frame-Options "SAMEORIGIN"`
            : `# Nginx Web Server Directive\nadd_header X-Frame-Options "SAMEORIGIN" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/conf-available/security.conf'
            : tech === 'express'
            ? 'src/server.ts (Express Middleware)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/security.conf',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "x-frame-options"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
        thirdPartyHostedNote:
          'Alternatively, configure Content-Security-Policy: frame-ancestors \'self\'; which takes precedence over X-Frame-Options in all modern browsers.',
        alternativeConfigs: [
          {
            technology: 'Nginx',
            snippet: `add_header X-Frame-Options "SAMEORIGIN" always;`,
            location: '/etc/nginx/conf.d/security.conf',
          },
          {
            technology: 'Apache',
            snippet: `Header always set X-Frame-Options "SAMEORIGIN"`,
            location: '/etc/apache2/conf-available/security.conf',
          },
        ],
      };

    case 'xcto':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set X-Content-Type-Options "nosniff"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express\napp.use((req, res, next) => {\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  next();\n});`
            : tech === 'caddy'
            ? `header X-Content-Type-Options "nosniff"`
            : `# Nginx Web Server Directive\nadd_header X-Content-Type-Options "nosniff" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/conf-available/security.conf'
            : tech === 'express'
            ? 'src/server.ts (Express Middleware)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/security.conf',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "x-content-type-options"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        thirdPartyHostedNote:
          'Ensure your web server or CDN sends correct Content-Type response headers (e.g. text/html, application/json) before enforcing nosniff.',
      };

    case 'hsts':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`
            : tech === 'caddy'
            ? `header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
            : `# Nginx Web Server Directive\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/sites-available/your-domain-ssl.conf'
            : tech === 'express'
            ? 'src/server.ts (Express Middleware)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/ssl.conf (HTTPS server block)',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "strict-transport-security"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        thirdPartyHostedNote:
          'In Cloudflare, enable HSTS under SSL/TLS > Edge Certificates > HTTP Strict Transport Security. Only enable includeSubDomains after verifying all subdomains support HTTPS.',
      };

    case 'referrer':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set Referrer-Policy "strict-origin-when-cross-origin"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`
            : tech === 'caddy'
            ? `header Referrer-Policy "strict-origin-when-cross-origin"`
            : `# Nginx Web Server Directive\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/conf-available/security.conf'
            : tech === 'express'
            ? 'src/server.ts (Express Middleware)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/security.conf',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "referrer-policy"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
        thirdPartyHostedNote:
          'Protects user privacy by stripping query strings and sensitive URL parameters when following external outbound links.',
      };

    case 'permissions':
      return {
        detectedTechnology: tech,
        configSnippet:
          tech === 'apache'
            ? `<IfModule mod_headers.c>\n  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"\n</IfModule>`
            : tech === 'express'
            ? `// Node.js Express\napp.use((req, res, next) => {\n  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');\n  next();\n});`
            : tech === 'caddy'
            ? `header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"`
            : `# Nginx Web Server Directive\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;`,
        configLocation:
          tech === 'apache'
            ? '/etc/apache2/conf-available/security.conf'
            : tech === 'express'
            ? 'src/server.ts (Express Middleware)'
            : tech === 'caddy'
            ? '/etc/caddy/Caddyfile'
            : '/etc/nginx/conf.d/security.conf',
        verificationCommand: `curl -I https://${targetDomain} | grep -i "permissions-policy"`,
        documentationUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
        thirdPartyHostedNote:
          'Prevents third-party ad tags and embedded iframes from accessing user camera, microphone, or geolocation hardware.',
      };
  }
}

/**
 * Deterministic cybersecurity analyst rules engine.
 * Converts actual scanner evidence into clear, jargon-free, beginner-friendly explanations
 * without inventing unobserved vulnerabilities or exaggerating severity.
 */
export function generateDeterministicDomainAnalysis(
  report: DomainAnalysisReport
): DomainAiSecurityAnalysis {
  const domain = report.domain || 'Target Domain';
  const findings: DomainSecurityFindingAnalysis[] = [];
  const positiveHighlights: string[] = [];
  const keyFactsObserved: string[] = [];

  const httpProbe = report.httpProbe;
  const tls = report.tlsCertificate;
  const rdap = report.rdap;
  const dnsRecords = report.dnsRecords;
  const resolvedIps = report.resolvedIps || [];

  // 1. FACTUAL INVENTORY: What was directly observed by the scanner
  if (resolvedIps.length > 0) {
    const ipList = resolvedIps.map((i) => i.ip).join(', ');
    const isCdn = resolvedIps.some((i) => i.isCdnOrCloud);
    keyFactsObserved.push(
      `Resolved to ${resolvedIps.length} IP address(es) (${ipList})${isCdn ? ' routed through a managed cloud/CDN edge network' : ''}.`
    );
  }

  if (tls) {
    if (tls.valid) {
      keyFactsObserved.push(
        `HTTPS is active with valid TLS certificate (${tls.protocol || 'TLS'} / ${tls.cipher || 'Modern Cipher'}), valid for ${tls.daysRemaining ?? 'N/A'} remaining days.`
      );
      positiveHighlights.push(
        `Transport Layer Security (TLS) is valid and actively encrypting web traffic (${tls.protocol || 'TLS'}).`
      );
    } else if (tls.error) {
      keyFactsObserved.push(`TLS certificate handshake encountered an error: ${tls.error}.`);
    }
  }

  if (httpProbe) {
    if (httpProbe.redirectChain && httpProbe.redirectChain.length > 0) {
      const chainStr = httpProbe.redirectChain
        .map((r) => `HTTP ${r.statusCode || 'Redirect'} -> ${r.url}`)
        .join(', ');
      keyFactsObserved.push(
        `HTTP probe observed redirect sequence (${chainStr}) terminating at HTTP ${httpProbe.statusCode || 200}.`
      );
    } else if (httpProbe.statusCode) {
      keyFactsObserved.push(`HTTP probe returned status code ${httpProbe.statusCode} ${httpProbe.statusText || 'OK'}.`);
    }

    if (httpProbe.httpsEnforced) {
      positiveHighlights.push('Website automatically enforces HTTPS encryption for visitors.');
    }

    const missing = httpProbe.missingSecurityHeaders || [];
    if (missing.length > 0) {
      keyFactsObserved.push(`${missing.length} standard browser security hardening header(s) were absent from responses: ${missing.join(', ')}.`);
    } else {
      positiveHighlights.push('All standard baseline HTTP security hardening headers were observed.');
    }
  }

  if (rdap) {
    if (rdap.status === 'Retrieved' && rdap.registrar) {
      keyFactsObserved.push(`RDAP registration records successfully retrieved (Registrar: ${rdap.registrar}).`);
      positiveHighlights.push(`Authoritative domain registration verified with ${rdap.registrar}.`);
    } else if (rdap.status === 'Forbidden' || rdap.httpStatusCode === 403) {
      keyFactsObserved.push('RDAP registration query returned HTTP 403 Forbidden from authoritative registry.');
    } else if (rdap.status === 'Unavailable' || rdap.status === 'RateLimited' || rdap.status === 'TimedOut') {
      keyFactsObserved.push(`RDAP registry lookup was ${rdap.status} (${rdap.errorDetails || 'Registry did not respond to passive query'}).`);
    }
  }

/**
 * Safely inspects both missingSecurityHeaders catalogs and raw securityHeaders keys
 * to determine if a security header is confirmed missing.
 */
function isHeaderMissing(
  httpProbe: DomainAnalysisReport['httpProbe'] | undefined,
  primaryKey: string,
  searchTerms: string[]
): boolean {
  if (!httpProbe) return false;

  // 1. Check missingSecurityHeaders catalog entries (case-insensitive)
  if (Array.isArray(httpProbe.missingSecurityHeaders)) {
    const inMissingList = httpProbe.missingSecurityHeaders.some((item) => {
      const lower = item.toLowerCase();
      return (
        lower === primaryKey.toLowerCase() ||
        searchTerms.some((t) => lower.includes(t.toLowerCase()))
      );
    });
    if (inMissingList) return true;
  }

  // 2. Check if present in securityHeaders with non-empty, non-null value
  if (httpProbe.securityHeaders) {
    for (const [key, val] of Object.entries(httpProbe.securityHeaders)) {
      const lower = key.toLowerCase();
      if (
        lower === primaryKey.toLowerCase() ||
        searchTerms.some((t) => lower.includes(t.toLowerCase()))
      ) {
        if (val && String(val).trim().length > 0 && String(val).toLowerCase() !== 'null') {
          return false; // Confirmed present
        }
      }
    }
  }

  // 3. If response was received (e.g. statusCode present) and header wasn't verified present
  if (httpProbe.statusCode) {
    return true;
  }

  return false;
}

  // 2. FINDINGS: Structure each observation into a clear, beginner-friendly analysis

  // (0) DNS Resolution Failure Check
  const isDnsFailed = Boolean(
    report.dnsFailed ||
    (resolvedIps.length === 0 &&
      (!dnsRecords || Object.values(dnsRecords).flat().length === 0))
  );

  if (isDnsFailed) {
    findings.push({
      id: 'finding-dns-resolution-failed',
      title: 'DNS Resolution Failure: Target Hostname Unreachable',
      category: 'DNS & Infrastructure',
      severity: 'Medium',
      severityExplanation:
        'The target domain did not resolve to any active IP address via recursive DNS lookup. Communications cannot reach the host.',
      confidence: 'Confirmed',
      whatObserved: 'Standard DNS queries for A and AAAA resource records returned no valid IP endpoints.',
      whatThisMeans:
        'Internet devices and web browsers cannot discover where to send traffic for this domain. The domain may be inactive, expired, or misconfigured.',
      potentialRisk:
        'The domain is in an unreachable state. If previously used in production, the domain could be vulnerable to dangling DNS or zone hijacking if third-party services still point to it.',
      possibleAttackScenario:
        'An adversary observing an abandoned domain with dangling DNS records could claim the referenced cloud resource (e.g. S3 bucket, GitHub Pages) and impersonate the service.',
      howToPreventIt:
        'Verify registrar nameserver delegation, ensure authoritative DNS zone files contain valid A/AAAA records, and de-provision obsolete DNS records.',
      technicalDetails: `Domain: ${domain} • Resolved IPs: 0 • Status: DNS Resolution Inconclusive / Failed`,
      remediationGuide: {
        detectedTechnology: 'dns',
        configSnippet: `# Authoritative DNS Zone Records:\n@    300    IN    A     <SERVER_IPV4_ADDRESS>\n@    300    IN    AAAA  <SERVER_IPV6_ADDRESS>`,
        configLocation: 'Authoritative Nameserver / DNS Management Console',
        verificationCommand: `dig +trace +short ${domain} A && nslookup ${domain}`,
        documentationUrl: 'https://www.rfc-editor.org/rfc/rfc1035',
        thirdPartyHostedNote: 'Ensure registrar NS records match your DNS host (e.g. Cloudflare, Route53, NS1) and delete obsolete CNAME records pointing to decommissioned services.',
      },
    });
  }

  // (0b) HTTP Probe Timeout or Connection Failure Finding
  const isHttpUnavailable =
    Boolean(httpProbe &&
    (httpProbe.provenance?.status === 'TimedOut' ||
      httpProbe.provenance?.status === 'Unavailable' ||
      httpProbe.provenance?.status === 'Blocked'));

  if (isHttpUnavailable && httpProbe) {
    const statusType = httpProbe.provenance.status;
    findings.push({
      id: 'finding-http-probe-unavailable',
      title: `HTTP Service Probe ${statusType === 'TimedOut' ? 'Timed Out' : statusType === 'Blocked' ? 'Blocked by Policy' : 'Unavailable'}`,
      category: 'Transport Security',
      severity: 'Low',
      severityExplanation:
        'The passive HTTP scanner did not receive a complete response from the web server within the timeout boundary.',
      confidence: 'Confirmed',
      whatObserved: `HTTP probe status: ${statusType} (${httpProbe.provenance.details || 'Connection did not return HTTP headers'}).`,
      whatThisMeans:
        'Port 80/443 on this target either dropped the connection, timed out, or rejected the scanner request. Web server headers could not be retrieved.',
      potentialRisk:
        'Web services may be offline, firewalled to restricted IP ranges, or running on non-standard ports.',
      possibleAttackScenario:
        'None directly inferred. Service unavailability prevents passive inspection of web application boundaries.',
      howToPreventIt:
        'Verify web server daemon status, ensure ports 80/443 are listening, and check edge firewall filtering rules.',
      technicalDetails: `Probe Status: ${statusType} • Target: ${httpProbe.probeUrl || domain} • Details: ${httpProbe.provenance.details || 'No response'}`,
    });
  }

  // (A) Content-Security-Policy (CSP)
  const isCspMissing = isHeaderMissing(httpProbe, 'content-security-policy', [
    'content-security-policy',
    'csp',
    'content security policy',
  ]);
  if (isCspMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-csp',
      title: 'Content-Security-Policy (CSP) is missing',
      category: 'Header Hardening',
      severity: 'Low',
      severityExplanation:
        'A missing CSP header is a defense-in-depth hardening concern, not proof that the site is compromised or contains an exploitable injection bug.',
      confidence: 'Confirmed',
      whatObserved: 'The HTTP server response did not include a Content-Security-Policy header.',
      whatThisMeans:
        'The website does not provide the visitor’s browser with strict rules about which domains are allowed to load scripts, styles, or media.',
      potentialRisk:
        'If the application also happens to have an injection vulnerability (like Cross-Site Scripting), an attacker could load unauthorized external scripts into a visitor’s browser session.',
      possibleAttackScenario:
        'In a hypothetical situation where an attacker discovers an unsanitized input form or forum post, the absence of CSP allows injected script code to execute and attempt to capture session credentials.',
      howToPreventIt:
        'Deploy a Content-Security-Policy HTTP header (e.g. `default-src \'self\'; script-src \'self\'; object-src \'none\';`). Always sanitize and contextually encode all dynamic user inputs.',
      technicalDetails: 'Header: Content-Security-Policy • Observed Value: null / missing • Probe URL: ' + (httpProbe?.finalUrl || report.targetNormalized),
      remediationGuide: buildHeaderRemediationGuide('csp', domain, httpProbe?.serverBanner),
    });
  }

  // (B) X-Frame-Options (Clickjacking protection)
  const isXfoMissing = isHeaderMissing(httpProbe, 'x-frame-options', [
    'x-frame-options',
    'xfo',
    'frame-options',
  ]);
  if (isXfoMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-xfo',
      title: 'X-Frame-Options (Clickjacking protection) is missing',
      category: 'Header Hardening',
      severity: 'Low',
      severityExplanation:
        'This is a preventative browser boundary control. Lack of framing restrictions does not mean an attack has occurred.',
      confidence: 'Confirmed',
      whatObserved: 'Neither an X-Frame-Options header nor a CSP frame-ancestors directive was detected in HTTP responses.',
      whatThisMeans:
        'Third-party websites may be permitted to embed this webpage inside an invisible or transparent frame (iframe).',
      potentialRisk:
        'Malicious third-party websites could attempt clickjacking by embedding this site under a deceptive user interface, enticing visitors to unwittingly click buttons or alter account settings.',
      possibleAttackScenario:
        'An attacker might place this website in an invisible iframe beneath an enticing button (such as "Click to claim reward") on a malicious page, tricking logged-in users into clicking sensitive controls.',
      howToPreventIt:
        'Configure the web server to send `X-Frame-Options: SAMEORIGIN` (or `DENY`), or specify `frame-ancestors \'self\';` within Content-Security-Policy.',
      technicalDetails: 'Header: X-Frame-Options • Observed Value: null / missing',
      remediationGuide: buildHeaderRemediationGuide('xfo', domain, httpProbe?.serverBanner),
    });
  }

  // (C) X-Content-Type-Options (MIME Sniffing protection)
  const isXctoMissing = isHeaderMissing(httpProbe, 'x-content-type-options', [
    'x-content-type-options',
    'content-type-options',
    'nosniff',
  ]);
  if (isXctoMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-xcto',
      title: 'X-Content-Type-Options (MIME sniffing prevention) is missing',
      category: 'Header Hardening',
      severity: 'Low',
      severityExplanation:
        'A missing MIME sniffing header is an informational/low hardening gap. It requires user file uploads and specific browser conditions to be dangerous.',
      confidence: 'Confirmed',
      whatObserved: 'The HTTP response header `X-Content-Type-Options: nosniff` was not returned by the server.',
      whatThisMeans:
        'Web browsers might try to guess ("sniff") the content type of downloaded files instead of strictly adhering to the declared Content-Type header.',
      potentialRisk:
        'If users can upload non-executable assets (such as profile pictures or text files) containing embedded scripts, a browser might mistakenly execute them as HTML or JavaScript.',
      possibleAttackScenario:
        'If an attacker uploads an image file containing malicious HTML/JavaScript onto the server, an older or permissive browser might sniff the file as HTML and execute the payload.',
      howToPreventIt:
        'Add `X-Content-Type-Options: nosniff` to all HTTP web server responses and CDN edge configurations.',
      technicalDetails: 'Header: X-Content-Type-Options • Observed Value: null / missing',
      remediationGuide: buildHeaderRemediationGuide('xcto', domain, httpProbe?.serverBanner),
    });
  }

  // (D) Referrer-Policy
  const isRefMissing = isHeaderMissing(httpProbe, 'referrer-policy', [
    'referrer-policy',
  ]);
  if (isRefMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-ref',
      title: 'Referrer-Policy header is missing',
      category: 'Header Hardening',
      severity: 'Informational',
      severityExplanation:
        'Modern browsers already enforce default privacy boundaries; setting this header provides deterministic, explicit cross-origin policy control.',
      confidence: 'Confirmed',
      whatObserved: 'The HTTP server did not return an explicit Referrer-Policy header.',
      whatThisMeans:
        'The website relies on the client browser’s default settings to determine how much address information is passed when users follow outbound links.',
      potentialRisk:
        'If sensitive identifiers, tokens, or personal identifiers are contained inside web address query strings, they might be leaked in HTTP Referer headers to external web servers.',
      possibleAttackScenario:
        'If a URL contains a reset token or user account ID (e.g. `?token=xyz`), clicking an external link could transmit that token to an external site\'s access logs.',
      howToPreventIt:
        'Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer` on all responses to protect user privacy.',
      technicalDetails: 'Header: Referrer-Policy • Observed Value: null / missing',
      remediationGuide: buildHeaderRemediationGuide('referrer', domain, httpProbe?.serverBanner),
    });
  }

  // (E) Permissions-Policy
  const isPermMissing = isHeaderMissing(httpProbe, 'permissions-policy', [
    'permissions-policy',
    'feature-policy',
  ]);
  if (isPermMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-perm',
      title: 'Permissions-Policy header is missing',
      category: 'Header Hardening',
      severity: 'Informational',
      severityExplanation:
        'Informational recommendation. Does not give attackers access to hardware without explicit user consent prompts.',
      confidence: 'Confirmed',
      whatObserved: 'No Permissions-Policy (or Feature-Policy) header was returned in HTTP responses.',
      whatThisMeans:
        'The site does not explicitly restrict browser capabilities (such as camera, microphone, or geolocation) for embedded frames or third-party scripts.',
      potentialRisk:
        'Embedded third-party scripts or iframes could theoretically request hardware device permissions from visitors under the site’s origin context.',
      possibleAttackScenario:
        'An embedded third-party analytics script or advertising widget could prompt users for location access without explicit restriction from the primary site.',
      howToPreventIt:
        'Define a restrictive `Permissions-Policy: camera=(), microphone=(), geolocation=()` header disabling device features that your application does not require.',
      technicalDetails: 'Header: Permissions-Policy • Observed Value: null / missing',
      remediationGuide: buildHeaderRemediationGuide('permissions', domain, httpProbe?.serverBanner),
    });
  }

  // (F) HSTS (Strict-Transport-Security)
  const isHstsMissing = isHeaderMissing(httpProbe, 'strict-transport-security', [
    'strict-transport-security',
    'hsts',
  ]);
  if (isHstsMissing && httpProbe && !isHttpUnavailable) {
    findings.push({
      id: 'finding-header-hsts',
      title: 'Strict-Transport-Security (HSTS) is missing',
      category: 'Transport Security',
      severity: 'Low',
      severityExplanation:
        'While HTTPS is active, without HSTS an adversary performing active network interception could attempt to strip TLS on a user’s initial plaintext connection.',
      confidence: 'Confirmed',
      whatObserved: 'The HTTP server did not return a Strict-Transport-Security header.',
      whatThisMeans:
        'The website does not instruct client browsers to remember that all future visits must strictly and exclusively use HTTPS.',
      potentialRisk:
        'A user typing `http://` on an untrusted public Wi-Fi network could be susceptible to a man-in-the-middle SSL-stripping attack before the redirect to HTTPS completes.',
      possibleAttackScenario:
        'On an unencrypted coffee shop Wi-Fi network, an attacker intercepting local traffic could catch an initial unencrypted HTTP request and serve a spoofed page before the browser transitions to HTTPS.',
      howToPreventIt:
        'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses once HTTPS is verified across all subdomains.',
      technicalDetails: 'Header: Strict-Transport-Security • Observed Value: null / missing',
      remediationGuide: buildHeaderRemediationGuide('hsts', domain, httpProbe?.serverBanner),
    });
  } else if (
    httpProbe?.securityHeaders?.['strict-transport-security'] ||
    httpProbe?.securityHeaders?.['HTTP Strict Transport Security (HSTS)']
  ) {
    const val =
      httpProbe?.securityHeaders?.['strict-transport-security'] ||
      httpProbe?.securityHeaders?.['HTTP Strict Transport Security (HSTS)'];
    positiveHighlights.push(
      `Strict-Transport-Security (HSTS) is configured: ${val}.`
    );
  }

  // (G) TLS Certificate & Transport Security Observations
  if (tls && tls.valid) {
    findings.push({
      id: 'finding-transport-tls',
      title: `Transport Security: Valid ${tls.protocol || 'TLS 1.3'} Encryption Active`,
      category: 'Transport Security',
      severity: 'Informational',
      severityExplanation:
        'Positive security control. Strong cryptography protects user sessions in transit against passive eavesdropping.',
      confidence: 'Confirmed',
      whatObserved: `Valid TLS certificate issued by "${tls.issuer || 'Trusted CA'}" using ${tls.protocol || 'TLS 1.3'} and ${tls.cipher || 'Modern Cipher'}.`,
      whatThisMeans:
        'All communication between client browsers and this domain is encrypted with modern cryptographic algorithms.',
      potentialRisk:
        'No active risk identified for this layer. Ensure certificate renewals are monitored to prevent unexpected expiration.',
      possibleAttackScenario:
        'Passive wiretapping and eavesdropping on network traffic cannot decrypt communication payloads protected by modern TLS.',
      howToPreventIt:
        'Maintain automated certificate renewal (e.g. ACME/Let\'s Encrypt) and enforce modern TLS 1.3/1.2 while disabling legacy TLS 1.0/1.1.',
      technicalDetails: `Protocol: ${tls.protocol || 'TLS 1.3'} • Cipher: ${tls.cipher || 'Unknown'} • Valid Until: ${tls.validTo || 'N/A'} (${tls.daysRemaining ?? 'N/A'} days remaining)`,
    });
  } else if (tls && tls.error) {
    findings.push({
      id: 'finding-transport-tls-error',
      title: 'TLS Certificate Handshake Anomaly Detected',
      category: 'Transport Security',
      severity: 'Medium',
      severityExplanation:
        'TLS handshake failed or threw an error during connection. This affects visitor trust and encryption guarantees.',
      confidence: 'Confirmed',
      whatObserved: `TLS probe encountered error: ${tls.error}.`,
      whatThisMeans:
        'The web server did not successfully complete a secure cryptographic handshake with the scanner.',
      potentialRisk:
        'Visitors attempting to connect via HTTPS may see browser warning screens, or traffic could fall back to unencrypted HTTP if not enforced.',
      possibleAttackScenario:
        'An attacker on a local network might take advantage of connection fallback behavior if users bypass browser certificate warnings.',
      howToPreventIt:
        'Verify certificate configuration, renewal status, and intermediate chain certificates on the web server or CDN proxy.',
      technicalDetails: `TLS Error Details: ${tls.error}`,
    });
  }

  // (H) RDAP & Registration Observations (e.g. HTTP 403 or unavailable)
  if (rdap && (rdap.status === 'Forbidden' || rdap.httpStatusCode === 403)) {
    findings.push({
      id: 'finding-rdap-403',
      title: 'Domain Registration (RDAP) lookup returned HTTP 403 Forbidden',
      category: 'Registration & RDAP',
      severity: 'Informational',
      severityExplanation:
        'An RDAP HTTP 403 response is an administrative or rate-limiting decision by the top-level registry. It is NOT a security flaw or vulnerability on the website itself.',
      confidence: 'Confirmed',
      whatObserved: 'The authoritative top-level registry for this domain responded with HTTP 403 Forbidden to the automated RDAP query.',
      whatThisMeans:
        'The domain registrar or top-level registry (e.g. .live registry) restricts automated queries or requires specialized query credentials or API access.',
      potentialRisk:
        'Public ownership history and creation dates cannot be automatically verified through standard passive RDAP queries. Does not introduce website vulnerabilities.',
      possibleAttackScenario:
        'None. An administrative query block from an external registry has zero operational impact on the security or availability of the website.',
      howToPreventIt:
        'No corrective action required on the target domain. If ownership validation is required, consult accredited registrar portals directly.',
      technicalDetails: `RDAP Registry Status: Forbidden (HTTP 403) • Registry URL: ${rdap.sourceUrl || 'Authoritative TLD RDAP Server'}`,
    });
  } else if (rdap && rdap.status === 'Retrieved') {
    findings.push({
      id: 'finding-rdap-verified',
      title: 'Domain Registration Verified via Authoritative RDAP',
      category: 'Registration & RDAP',
      severity: 'Informational',
      severityExplanation:
        'Legitimate registration record retrieved with verifiable registrar provenance.',
      confidence: 'Confirmed',
      whatObserved: `Domain is registered with "${rdap.registrar || 'Verified Registrar'}" (Registered: ${rdap.registrationDate ? new Date(rdap.registrationDate).toLocaleDateString() : 'Recorded'}).`,
      whatThisMeans:
        'The domain’s official registry record is publicly accessible and provides verifiable administrative ownership details.',
      potentialRisk:
        'Standard operational visibility. Ensure domain lock (ClientTransferProhibited) and DNSSEC are enabled to prevent unauthorized transfer attempts.',
      possibleAttackScenario:
        'Adversaries attempting domain hijacking cannot easily transfer domains protected by registrar lock and multi-factor authentication.',
      howToPreventIt:
        'Enable registrar transfer lock, multi-factor authentication on registrar accounts, and monitor domain expiration dates.',
      technicalDetails: `Registrar: ${rdap.registrar || 'N/A'} • Status: ${rdap.domainStatus?.join(', ') || 'Active'}`,
    });
  }

  // (I) HTTP Redirect Chain (e.g. HTTP 308 followed by HTTP 200)
  if (httpProbe && httpProbe.redirectChain && httpProbe.redirectChain.length > 0) {
    const chain = httpProbe.redirectChain;
    const finalStatus = httpProbe.statusCode || 200;
    const redirectsText = chain.map((r) => `HTTP ${r.statusCode || '3xx'} (${r.url})`).join(' ➔ ');

    findings.push({
      id: 'finding-redirect-routing',
      title: `HTTP Routing: ${chain[0].statusCode || '308'} Redirect Observed followed by HTTP ${finalStatus}`,
      category: 'Redirect & Routing',
      severity: 'Informational',
      severityExplanation:
        'Canonical redirects (e.g. redirecting bare domain to www or HTTP to HTTPS) are standard best practice web architecture and do not represent security vulnerabilities.',
      confidence: 'Confirmed',
      whatObserved: `HTTP scanner observed redirect path: ${redirectsText} ➔ HTTP ${finalStatus} at final destination (${httpProbe.finalUrl}).`,
      whatThisMeans:
        'The web server automatically forwards incoming web requests to a standardized canonical destination URL.',
      potentialRisk:
        'No risk detected. Standard canonical forwarding ensures users arrive at the intended secure web property.',
      possibleAttackScenario:
        'An attack would only be possible if the redirect accepted untrusted user-supplied destination URLs (open redirect), which was not observed here.',
      howToPreventIt:
        'Keep redirect destinations statically configured or strictly validated against an internal allowlist of domain URLs.',
      technicalDetails: `Redirect Count: ${httpProbe.redirectCount} • Final URL: ${httpProbe.finalUrl} • Status: ${finalStatus}`,
    });
  }

  // (J) DNS & CDN Infrastructure Observations
  if (resolvedIps.length > 0) {
    const isCloud = resolvedIps.some((i) => i.isCdnOrCloud);
    findings.push({
      id: 'finding-infra-dns',
      title: `Network Infrastructure: ${resolvedIps.length} Resolved IP Endpoints (${isCloud ? 'Cloud / CDN Protected' : 'Direct Host'})`,
      category: 'DNS & Infrastructure',
      severity: 'Informational',
      severityExplanation:
        'Network endpoint resolution is a factual baseline observation, not a vulnerability.',
      confidence: 'Confirmed',
      whatObserved: `Domain resolves to ${resolvedIps.map((i) => i.ip).join(', ')}${isCloud ? ' located in known CDN/Cloud provider address space' : ''}.`,
      whatThisMeans:
        isCloud
          ? 'The domain leverages a content delivery network or cloud edge proxy to route traffic and protect the origin server.'
          : 'The domain resolves directly to dedicated or hosted server IP infrastructure.',
      potentialRisk:
        'No inherent risk. Cloud proxies help mitigate DDoS attacks and protect origin IP addresses from direct reconnaissance.',
      possibleAttackScenario:
        'Attackers frequently probe for leaked origin IP addresses to bypass CDN firewalls; maintaining origin privacy is standard operational practice.',
      howToPreventIt:
        'If using a CDN, ensure the origin web server only accepts connections from designated CDN IP ranges and keeps origin IP unlisted in public DNS.',
      technicalDetails: `Resolved IPs: ${resolvedIps.map((i) => `${i.ip} (IPv${i.version})`).join(', ')}`,
    });
  }

  // 3. OVERALL ASSESSMENT: Plain-English summary of domain security posture
  let overallAssessment = '';
  const missingHeadersCount = httpProbe?.missingSecurityHeaders?.length || 0;
  const isTlsValid = tls?.valid;
  const isTls13 = tls?.protocol?.includes('1.3') || tls?.protocol?.includes('TLS');

  if (isDnsFailed) {
    overallAssessment =
      `DNS resolution failed for domain "${domain}". The domain could not be resolved to any active IP addresses. ` +
      `This indicates an inactive, unregistered, or misconfigured domain name, or an authoritative nameserver failure. ` +
      `Passive web and transport checks were unable to connect.`;
  } else if (isHttpUnavailable && !isTlsValid) {
    overallAssessment =
      `Passive domain reconnaissance for "${domain}" resolved network endpoints (${resolvedIps.map((i) => i.ip).join(', ')}), ` +
      `but the HTTP web server did not respond within the connection timeout window. ` +
      `The web service may be offline, firewalled, or serving non-HTTP protocols.`;
  } else if (isTlsValid && missingHeadersCount > 0) {
    overallAssessment =
      `Domain "${domain}" demonstrates strong transport-layer encryption (HTTPS active with valid ${tls?.protocol || 'TLS 1.3'} encryption), ` +
      `but lacks ${missingHeadersCount} standard browser security hardening header(s) (including ${httpProbe?.missingSecurityHeaders.slice(0, 3).join(', ')}). ` +
      `These missing headers are defense-in-depth protective boundaries; they are not proof of compromise or active exploitation. ` +
      `All identified risks are low-severity hardening opportunities that can be remediated through web server header configuration.`;
  } else if (isTlsValid && missingHeadersCount === 0) {
    overallAssessment =
      `Domain "${domain}" exhibits an exemplary security posture. Transport layer encryption is valid (${tls?.protocol || 'TLS 1.3'}), ` +
      `HTTPS is enforced, and all key browser hardening headers (CSP, HSTS, X-Frame-Options) are actively deployed. No security gaps were detected in passive recon.`;
  } else {
    overallAssessment =
      `Passive domain reconnaissance for "${domain}" completed with a calculated risk score of ${report.riskScore}/100 (${report.riskLevel}). ` +
      `The domain was successfully analyzed across DNS, transport encryption, and HTTP header endpoints. Review the individual findings below for concrete hardening guidance.`;
  }

  // 4. PRIORITIZED NEXT STEPS: Actionable roadmap ordered by importance
  const prioritizedNextSteps: PrioritizedNextStep[] = [];
  if (isCspMissing || isXfoMissing) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Deploy Content-Security-Policy (CSP) & X-Frame-Options (DENY/SAMEORIGIN)',
      rationale:
        'Mitigates common client-side clickjacking and uncontrolled script execution vectors at zero infrastructure cost.',
    });
  }
  if (isXctoMissing || isRefMissing) {
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Deploy X-Content-Type-Options: nosniff and Referrer-Policy: strict-origin-when-cross-origin',
      rationale:
        'Prevents MIME confusion attacks and sensitive internal URL leakage in outgoing HTTP requests.',
    });
  }
  if (isPermMissing || isHstsMissing) {
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Implement granular Permissions-Policy and submit domain for HSTS preload inclusion',
      rationale:
        'Locks down browser hardware APIs (camera, geolocation) and guarantees TLS encryption before the first network connection.',
    });
  }
  prioritizedNextSteps.push({
    priority: 'Verification',
    action: 'Execute automated regression scans and monitor RDAP registry expiry dates',
    rationale:
      'Ensures security header configurations persist across web server updates and deployment pipelines.',
  });

  // 5. LIMITATIONS: Clearly identify what the scan did NOT test or could not verify
  const limitations = [
    'Passive reconnaissance only: Did not perform invasive penetration testing, input fuzzing, or active exploit validation.',
    'Backend application logic, internal database queries, and authenticated user workflows were not evaluated.',
    'Missing browser security headers do not confirm whether server-side input sanitization or output encoding is implemented.',
    'Network probes were conducted from an external scanner perspective and do not reflect internal network access controls.',
  ];

  return {
    domain,
    generatedAt: new Date().toISOString(),
    modelUsed: 'Veylith Deterministic DFIR Expert Engine',
    isAiGenerated: false,
    overallAssessment,
    keyFactsObserved,
    findings,
    positiveHighlights,
    prioritizedNextSteps,
    limitations,
    disclaimer: AI_ANALYST_DISCLAIMER,
  };
}

/**
 * Converts a DomainAnalysisReport and its AI Security Analysis into an InvestigationSimpleReport.
 */
export function convertDomainAnalysisToSimpleReport(
  report: DomainAnalysisReport
): import('../types').InvestigationSimpleReport {
  const analysis = report.aiSecurityAnalysis || generateDeterministicDomainAnalysis(report);
  return {
    target: report.domain,
    targetType: 'domain',
    generatedAt: analysis.generatedAt,
    overallAssessment: analysis.overallAssessment,
    whatWasDiscovered: analysis.keyFactsObserved,
    whatIsWorkingWell: analysis.positiveHighlights,
    securityConcerns: analysis.findings.map((f) => {
      const confMeta = classifyFindingConfidence({
        title: f.title,
        category: f.category,
        observedResult: f.whatObserved,
        evidenceReference: f.technicalDetails,
      });
      return {
        id: f.id,
        title: f.title,
        category: f.category,
        severity: f.severity,
        severityExplanation: f.severityExplanation,
        confidence: f.confidence,
        whatObserved: f.whatObserved,
        whatThisMeans: f.whatThisMeans,
        potentialRisk: f.potentialRisk,
        possibleAttackScenario: f.possibleAttackScenario,
        howToPreventIt: f.howToPreventIt,
        technicalDetails: f.technicalDetails,
        remediationGuide: f.remediationGuide,
        verificationStatus: f.verificationStatus || confMeta.verificationStatus,
        confidenceLevel: f.confidenceLevel || confMeta.confidenceLevel,
        detectionMethod: f.detectionMethod || confMeta.detectionMethod,
        evidenceReference: f.evidenceReference || confMeta.evidenceReference,
        potentialFalsePositiveExplanation: f.potentialFalsePositiveExplanation || confMeta.potentialFalsePositiveExplanation,
        recommendedNextStep: f.recommendedNextStep || confMeta.recommendedNextStep,
      };
    }),
    prioritizedNextSteps: analysis.prioritizedNextSteps || [
      {
        priority: 'Immediate',
        action: 'Review and deploy missing browser hardening headers',
        rationale: 'Provides instant client-side boundary defense against clickjacking and XSS.',
      },
      {
        priority: 'High Priority',
        action: 'Verify DNS MX and SPF/DKIM anti-spoofing records',
        rationale: 'Protects domain reputation and prevents email impersonation attacks.',
      },
      {
        priority: 'Scheduled Hardening',
        action: 'Establish certificate expiration monitoring',
        rationale: 'Ensures TLS availability without service interruption.',
      },
    ],
    limitations: analysis.limitations,
    disclaimer: analysis.disclaimer,
    isAiGenerated: analysis.isAiGenerated,
    modelUsed: analysis.modelUsed,
  };
}

/**
 * Builds the strict prompt for Gemini API to generate natural-language analyst explanations
 * adhering strictly to observed scanner facts without inventing unobserved vulnerabilities.
 */
export function buildDomainAnalystPrompt(report: DomainAnalysisReport): {
  systemPrompt: string;
  userPrompt: string;
} {
  const systemPrompt = `You are VEYLITH AI, a professional cybersecurity analyst explaining web domain scan results in clear, simple language to a beginner.

STRICT MANDATORY RULES:
1. Explain findings in plain English without overwhelming users with jargon.
2. AI MUST NOT INVENT VULNERABILITIES:
   - Missing security headers (CSP, X-Frame-Options, etc.) must NEVER be classified as High or Critical vulnerabilities. They are Informational or Low severity defense-in-depth hardening concerns.
   - Never claim that a domain is hacked, compromised, infected, or actively vulnerable without supporting evidence.
   - Distinguish an observed fact from a potential consequence.
   - RDAP errors (like HTTP 403, timeouts, or rate limits) are administrative registry responses, NOT vulnerabilities on the target site.
   - A CDN, cloud provider, redirect (e.g. HTTP 308 to 200), or public IP is not inherently suspicious.
   - Passive scanning cannot confirm whether an attack is possible.
3. Every finding MUST include:
   - id: Unique string identifier (e.g. "finding-csp")
   - title: Plain-English title
   - category: 'Header Hardening' | 'Transport Security' | 'DNS & Infrastructure' | 'Registration & RDAP' | 'Redirect & Routing'
   - severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical'
   - severityExplanation: Why this severity was assigned in simple language
   - confidence: 'Confirmed' | 'Potential' | 'Inferred' | 'Unknown'
   - whatObserved: Actual facts returned by the scanner
   - whatThisMeans: Simple plain-language explanation
   - potentialRisk: Realistic plain-English risk explanation
   - possibleAttackScenario: High-level hypothetical abuse scenario (educational, no exploit instructions)
   - howToPreventIt: Practical, specific mitigation recommendations
   - technicalDetails: Raw technical data (headers, status codes)
4. OUTPUT FORMAT: Respond ONLY with valid JSON conforming strictly to the requested schema.`;

  const userPrompt = `Analyze the following domain scan evidence for domain: "${report.domain}":

EVIDENCE DATA:
- Target: ${report.domain} (Normalized: ${report.targetNormalized})
- Resolved IPs: ${JSON.stringify(report.resolvedIps)}
- TLS Certificate: ${JSON.stringify(report.tlsCertificate)}
- HTTP Probe:
  * Status: ${report.httpProbe?.statusCode} ${report.httpProbe?.statusText}
  * Final URL: ${report.httpProbe?.finalUrl}
  * Redirect Chain: ${JSON.stringify(report.httpProbe?.redirectChain)}
  * HTTPS Enforced: ${report.httpProbe?.httpsEnforced}
  * Observed Headers: ${JSON.stringify(report.httpProbe?.securityHeaders)}
  * Missing Headers: ${JSON.stringify(report.httpProbe?.missingSecurityHeaders)}
- RDAP Registration Status: ${JSON.stringify(report.rdap)}
- DNS Records: A=${JSON.stringify(report.dnsRecords.a)}, MX=${JSON.stringify(report.dnsRecords.mx)}, NS=${JSON.stringify(report.dnsRecords.ns)}
- Deterministic Risk Score: ${report.riskScore}/100 (${report.riskLevel})

Generate the JSON response with this exact schema:
{
  "domain": "${report.domain}",
  "overallAssessment": "Short plain-English summary of domain security posture",
  "keyFactsObserved": ["Fact 1", "Fact 2"],
  "positiveHighlights": ["Positive 1", "Positive 2"],
  "findings": [
    {
      "id": "finding-...",
      "title": "...",
      "category": "Header Hardening",
      "severity": "Low",
      "severityExplanation": "...",
      "confidence": "Confirmed",
      "whatObserved": "...",
      "whatThisMeans": "...",
      "potentialRisk": "...",
      "possibleAttackScenario": "...",
      "howToPreventIt": "...",
      "technicalDetails": "..."
    }
  ],
  "limitations": ["..."],
  "disclaimer": "${AI_ANALYST_DISCLAIMER}"
}`;

  return { systemPrompt, userPrompt };
}

/**
 * Validates the Gemini response to ensure schema integrity and absence of invented facts.
 */
export function validateAiDomainAnalysis(
  data: any,
  report: DomainAnalysisReport
): DomainAiSecurityAnalysis | null {
  if (!data || typeof data !== 'object') return null;
  if (typeof data.overallAssessment !== 'string' || !Array.isArray(data.findings)) return null;

  // Enforce anti-hallucination guard: If any missing header finding was marked High or Critical, downgrade it to Low
  const sanitizedFindings: DomainSecurityFindingAnalysis[] = data.findings.map(
    (f: any, idx: number) => {
      let sev = f.severity || 'Informational';
      const isHeaderFinding =
        f.category === 'Header Hardening' ||
        f.title?.toLowerCase().includes('header') ||
        f.title?.toLowerCase().includes('csp') ||
        f.title?.toLowerCase().includes('x-frame') ||
        f.title?.toLowerCase().includes('x-content-type');

      // Mandatory rule: A missing header alone must not produce a High or Critical severity
      if (isHeaderFinding && (sev === 'High' || sev === 'Critical')) {
        sev = 'Low';
      }

      // RDAP errors are Informational
      if (
        (f.title?.toLowerCase().includes('rdap') || f.category === 'Registration & RDAP') &&
        (sev === 'High' || sev === 'Critical' || sev === 'Medium')
      ) {
        sev = 'Informational';
      }

      return {
        id: f.id || `ai-finding-${idx + 1}`,
        title: f.title || 'Security Observation',
        category: f.category || 'Header Hardening',
        severity: sev,
        severityExplanation:
          f.severityExplanation ||
          'Assigned based on defense-in-depth security principles and observed facts.',
        confidence: f.confidence || 'Confirmed',
        whatObserved: f.whatObserved || 'Observed during automated reconnaissance.',
        whatThisMeans: f.whatThisMeans || 'Configuration detail identified during scan.',
        potentialRisk: f.potentialRisk || 'Potential risk under specific conditions.',
        possibleAttackScenario:
          f.possibleAttackScenario ||
          'Hypothetical attack scenario under specific unverified conditions.',
        howToPreventIt: f.howToPreventIt || 'Implement recommended security hardening configuration.',
        technicalDetails: f.technicalDetails || undefined,
      };
    }
  );

  return {
    domain: data.domain || report.domain,
    generatedAt: new Date().toISOString(),
    modelUsed: data.modelUsed || 'Gemini 3.8 Flash (AI Analyst)',
    isAiGenerated: true,
    overallAssessment: data.overallAssessment,
    keyFactsObserved: Array.isArray(data.keyFactsObserved) ? data.keyFactsObserved : [],
    positiveHighlights: Array.isArray(data.positiveHighlights) ? data.positiveHighlights : [],
    findings: sanitizedFindings,
    limitations: Array.isArray(data.limitations)
      ? data.limitations
      : generateDeterministicDomainAnalysis(report).limitations,
    disclaimer: AI_ANALYST_DISCLAIMER,
  };
}
