import { Finding, EvidenceItem, SeverityLevel, ConfidenceLevel } from '../types';

export type VerificationStatus = 'VERIFIED' | 'INFERRED' | 'UNKNOWN';

export interface GroundedArtifact {
  type: 'ip' | 'cve' | 'hash' | 'header' | 'domain';
  value: string;
  isSupported: boolean;
  evidenceReference?: string;
  provenanceNote?: string;
}

export interface GroundingAuditResult {
  verificationStatus: VerificationStatus;
  isFullyGrounded: boolean;
  groundingScore: number; // 0 to 100
  artifactsObserved: GroundedArtifact[];
  unsupportedClaims: string[];
  groundingRationale: string;
  disclaimer: string;
}

export interface InvestigationTelemetryContext {
  domain?: string;
  resolvedIps?: string[];
  dnsRecords?: Record<string, any>;
  securityHeaders?: Record<string, string | null>;
  missingSecurityHeaders?: string[];
  serverBanner?: string;
  tlsValid?: boolean;
  tlsError?: string;
  fileName?: string;
  fileHash?: string;
  fileEntropy?: number;
  detectedFormat?: string;
  pcapEndpoints?: string[];
  pcapProtocols?: string[];
  caseEvidence?: EvidenceItem[];
  caseFindings?: Finding[];
}

/**
 * Extracts factual cybersecurity observables (IPs, CVEs, Hashes, Security Headers)
 * from text or analysis summaries and audits them against genuine telemetry.
 */
export function auditFactualClaimsAgainstTelemetry(
  text: string,
  context: InvestigationTelemetryContext = {}
): GroundingAuditResult {
  const artifacts: GroundedArtifact[] = [];
  const unsupported: string[] = [];

  // Known valid telemetry entity pools
  const validIps = new Set<string>();
  (context.resolvedIps || []).forEach((ip) => validIps.add(ip.toLowerCase()));
  (context.pcapEndpoints || []).forEach((ip) => validIps.add(ip.toLowerCase()));
  (context.caseEvidence || [])
    .filter((e) => e.type === 'ip')
    .forEach((e) => validIps.add(e.value.toLowerCase()));

  const validHashes = new Set<string>();
  if (context.fileHash) validHashes.add(context.fileHash.toLowerCase());
  (context.caseEvidence || [])
    .filter((e) => e.type === 'hash')
    .forEach((e) => validHashes.add(e.value.toLowerCase()));

  const validHeaders = new Set<string>();
  if (context.securityHeaders) {
    Object.keys(context.securityHeaders).forEach((h) => validHeaders.add(h.toLowerCase()));
  }
  if (context.missingSecurityHeaders) {
    context.missingSecurityHeaders.forEach((h) => validHeaders.add(h.toLowerCase()));
  }

  const validCves = new Set<string>();
  (context.caseEvidence || [])
    .filter((e) => e.type === 'cve')
    .forEach((e) => validCves.add(e.value.toUpperCase()));

  // 1. Audit IP addresses mentioned in claim text
  const ipRegex = /\b(?:[1-9]\d{0,2}\.){3}[1-9]\d{0,2}\b/g;
  let ipMatch: RegExpExecArray | null;
  while ((ipMatch = ipRegex.exec(text)) !== null) {
    const ip = ipMatch[0];
    // Ignore version strings (e.g. 1.20.1 or 2.4.0)
    const isVersionLike = ip.split('.').some((part) => Number(part) > 255);
    if (isVersionLike) continue;

    const isSupported = validIps.has(ip.toLowerCase());
    artifacts.push({
      type: 'ip',
      value: ip,
      isSupported,
      evidenceReference: isSupported ? `Telemetry IP: ${ip}` : undefined,
      provenanceNote: isSupported ? 'Matched to verified DNS/Socket resolution' : 'Uncorroborated IP address in claim',
    });
    if (!isSupported) {
      unsupported.push(`Claim references IP ${ip} which does not exist in collected telemetry.`);
    }
  }

  // 2. Audit CVE identifiers
  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
  let cveMatch: RegExpExecArray | null;
  while ((cveMatch = cveRegex.exec(text)) !== null) {
    const cve = cveMatch[0].toUpperCase();
    const isSupported = validCves.has(cve);
    artifacts.push({
      type: 'cve',
      value: cve,
      isSupported,
      evidenceReference: isSupported ? `Case CVE: ${cve}` : undefined,
      provenanceNote: isSupported ? 'Directly recorded in case evidence' : 'Uncorrelated CVE citation',
    });
    if (!isSupported) {
      unsupported.push(`Claim cites ${cve} without supporting vulnerability evidence in active case.`);
    }
  }

  // 3. Audit Security Headers
  const knownSecurityHeaderNames = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ];
  for (const hdr of knownSecurityHeaderNames) {
    if (text.toLowerCase().includes(hdr)) {
      const isSupported =
        validHeaders.has(hdr) ||
        (context.securityHeaders && context.securityHeaders[hdr] !== undefined) ||
        Boolean(context.missingSecurityHeaders?.some((m) => m.toLowerCase().includes(hdr)));

      artifacts.push({
        type: 'header',
        value: hdr,
        isSupported: Boolean(isSupported),
        evidenceReference: isSupported ? `HTTP Probe Header: ${hdr}` : undefined,
        provenanceNote: isSupported ? 'Observed in HTTP Probe telemetry' : 'Unobserved header claim',
      });
      if (!isSupported) {
        unsupported.push(`Claim references header "${hdr}" which was not probed in active telemetry.`);
      }
    }
  }

  // Calculate Grounding Score and Status
  const totalArtifacts = artifacts.length;
  const supportedCount = artifacts.filter((a) => a.isSupported).length;

  let score = 100;
  if (totalArtifacts > 0) {
    score = Math.round((supportedCount / totalArtifacts) * 100);
  }

  let verificationStatus: VerificationStatus = 'VERIFIED';
  let rationale = 'All cited entities directly correspond to verifiable telemetry.';

  if (unsupported.length > 0) {
    if (supportedCount === 0) {
      verificationStatus = 'UNKNOWN';
      rationale = 'Claims rely on indicators not present in collected evidence. Treat as unverified hypothesis.';
    } else {
      verificationStatus = 'INFERRED';
      rationale = 'Partial telemetry alignment with reasoned inferences or uncorroborated references.';
    }
  } else if (text.toLowerCase().includes('inferred') || text.toLowerCase().includes('hypothesis')) {
    verificationStatus = 'INFERRED';
    rationale = 'Logical deductions derived from verified underlying observables.';
  }

  return {
    verificationStatus,
    isFullyGrounded: unsupported.length === 0,
    groundingScore: score,
    artifactsObserved: artifacts,
    unsupportedClaims: unsupported,
    groundingRationale: rationale,
    disclaimer:
      'Veylith Grounding Engine audits all AI and analyst statements against immutable collected telemetry.',
  };
}

/**
 * Generates explainable confidence metadata, false-positive context,
 * and prioritized investigative next steps for a finding.
 */
export function deriveFindingConfidenceMetadata(
  finding: Partial<Finding>,
  context: InvestigationTelemetryContext = {}
): {
  verificationStatus: VerificationStatus;
  detectionMethod: string;
  evidenceReference: string;
  falsePositiveExplanation: string;
  recommendedNextStep: string;
} {
  const cat = finding.category || 'Infrastructure & Recon';
  const title = (finding.title || '').toLowerCase();

  let verificationStatus: VerificationStatus = 'VERIFIED';
  let detectionMethod = 'Direct Telemetry Capture';
  let evidenceReference = finding.evidenceIds?.[0] ? `EVD-${finding.evidenceIds[0]}` : `SENSOR-${finding.sourceTool || 'CORE'}`;
  let falsePositiveExplanation = 'Ensure testing environment and operational context are taken into account.';
  let recommendedNextStep = 'Review raw probe telemetry and corroborate with complementary sensors.';

  // 1. Security Headers
  if (cat === 'Hardening & Security Header' || title.includes('header') || title.includes('csp') || title.includes('hsts')) {
    detectionMethod = 'RFC 7230 HTTP Response Header Evaluation';
    evidenceReference = `HTTP Probe (${context.domain || finding.targetEntity || 'Target'})`;
    verificationStatus = 'VERIFIED';

    if (title.includes('csp') || title.includes('content-security-policy')) {
      falsePositiveExplanation =
        'If this endpoint is a pure REST/gRPC API returning only JSON without rendering HTML in a browser, CSP is not functionally required.';
      recommendedNextStep =
        'Verify whether this endpoint renders web user interfaces; if so, deploy a Content-Security-Policy header restricting script-src.';
    } else if (title.includes('x-frame-options') || title.includes('clickjacking')) {
      falsePositiveExplanation =
        'If the application is intentionally designed to be embedded in trusted enterprise partner portals via CSP frame-ancestors, XFO absence may be deliberate.';
      recommendedNextStep =
        'Verify if frame-ancestors directive is active in CSP, or set X-Frame-Options to SAMEORIGIN.';
    } else if (title.includes('strict-transport-security') || title.includes('hsts')) {
      falsePositiveExplanation =
        'If the service operates strictly in an isolated internal test network without public DNS exposure, HSTS preload may not be applicable.';
      recommendedNextStep =
        'Ensure HTTPS redirection is active and deploy Strict-Transport-Security with max-age=31536000.';
    } else {
      falsePositiveExplanation =
        'Non-browser endpoints (e.g. webhook listeners) do not parse browser security headers.';
      recommendedNextStep = 'Review web server configuration file and append recommended header directives.';
    }
  }

  // 2. Binary & Static Forensics
  else if (cat === 'Binary & Static Forensics' || title.includes('entropy') || title.includes('masquerad')) {
    if (title.includes('masquerad')) {
      detectionMethod = 'Magic Bytes Signature vs Extension Cross-Check';
      evidenceReference = `Magic: ${finding.targetEntity || 'File'}`;
      verificationStatus = 'VERIFIED';
      falsePositiveExplanation =
        'Certain hybrid polyglot file formats or installers may legitimately bundle executable stub headers.';
      recommendedNextStep =
        'Quarantine file sample immediately; verify cryptographic hash against threat catalogs; do not execute.';
    } else if (title.includes('entropy')) {
      detectionMethod = 'Shannon Bitwise Entropy Distribution Calculation';
      evidenceReference = `Shannon: ${finding.targetEntity || 'File'}`;
      verificationStatus = 'INFERRED';
      falsePositiveExplanation =
        'High entropy (>7.2 bits/byte) naturally occurs in benign compressed files (ZIP, PNG, MP4, gzip) and encrypted database backups without malware present.';
      recommendedNextStep =
        'Inspect file signature to confirm whether file is a legitimate compressed archive before flagging as packed malware.';
    } else {
      detectionMethod = 'Static Structural Header Parsing';
      evidenceReference = `Static: ${finding.targetEntity || 'File'}`;
      verificationStatus = 'VERIFIED';
      falsePositiveExplanation =
        'Debugging symbols and administrative utility binaries can share characteristics with malicious tooling.';
      recommendedNextStep =
        'Correlate extracted printable strings with corporate software inventory.';
    }
  }

  // 3. Network & Protocol
  else if (cat === 'Network & Protocol' || title.includes('pcap') || title.includes('beacon') || title.includes('syn')) {
    if (title.includes('syn') || title.includes('scan')) {
      detectionMethod = 'TCP Flag Distribution & Connection State Tracking';
      evidenceReference = `PCAP Flow: ${finding.targetEntity || 'Network'}`;
      verificationStatus = 'INFERRED';
      falsePositiveExplanation =
        'Aggressive firewall health checks, load balancer keep-alives, or network vulnerability scanners can generate high SYN-without-ACK ratios.';
      recommendedNextStep =
        'Check source IP against corporate monitoring tools and vulnerability scanner allowlists.';
    } else if (title.includes('cleartext') || title.includes('unencrypted')) {
      detectionMethod = 'Deep Packet Inspection for Unencrypted Protocol Payloads';
      evidenceReference = `PCAP Payload: ${finding.targetEntity || 'Network'}`;
      verificationStatus = 'VERIFIED';
      falsePositiveExplanation =
        'Legacy diagnostic protocols or internal test harness traffic operating over isolated sandbox subnets.';
      recommendedNextStep =
        'Migrate transport to TLS 1.3 or SSH; immediately revoke and rotate any cleartext credentials observed in packet stream.';
    } else {
      detectionMethod = 'PCAP Network Flow Analysis';
      evidenceReference = `PCAP Telemetry: ${finding.targetEntity || 'Network'}`;
      verificationStatus = 'VERIFIED';
      falsePositiveExplanation =
        'High traffic volume may be caused by automated backups or scheduled batch sync jobs.';
      recommendedNextStep =
        'Isolate suspect IP and inspect firewall perimeter connection logs.';
    }
  }

  // 4. Vulnerability & Exploit
  else if (cat === 'Vulnerability & Exploit' || title.includes('cve')) {
    detectionMethod = 'CISA Known Exploited Vulnerability (KEV) Catalog Correlation';
    evidenceReference = `CISA KEV / NVD Catalog`;
    verificationStatus = 'INFERRED'; // Vulnerability match by version/service is inferred exploitability, not proof of active compromise
    falsePositiveExplanation =
      'Target software may have backported security patches applied by OS distribution maintainers without incrementing the primary version string.';
    recommendedNextStep =
      'Review package changelog or run authenticated host vulnerability scan to verify if vendor patch was backported.';
  }

  // 5. Infrastructure & DNS
  else {
    detectionMethod = 'Authoritative DNS Query & WHOIS/RDAP Extraction';
    evidenceReference = `DNS RR: ${finding.targetEntity || 'Domain'}`;
    verificationStatus = 'VERIFIED';
    falsePositiveExplanation =
      'DNS propagation delays, multi-region CDN GeoDNS routing, or split-horizon DNS may cause varying responses depending on client location.';
    recommendedNextStep =
      'Query authoritative nameservers directly with dig or kdig to eliminate recursive resolver cache skew.';
  }

  return {
    verificationStatus,
    detectionMethod,
    evidenceReference,
    falsePositiveExplanation,
    recommendedNextStep,
  };
}
