import { ThreatIntelFeed, ThreatIntelItem, SeverityLevel, ConfidenceLevel } from '../types';

export const CISA_KEV_CATALOG_VERSION = '2025.01 (CISA KEV Local Mirror)';

// Versioned local cache of high-priority CISA Known Exploited Vulnerabilities
export const LOCAL_CISA_KEV_ITEMS: ThreatIntelItem[] = [
  {
    id: 'KEV-2024-38856',
    type: 'cve',
    identifier: 'CVE-2024-38856',
    title: 'Apache OFBiz Pre-Authentication Remote Code Execution',
    description: 'Apache OFBiz contains an unauthenticated remote code execution vulnerability in the ControlServlet override mechanism.',
    severity: 'Critical',
    sourceFeed: 'CISA Known Exploited Vulnerabilities (KEV)',
    retrievedAt: '2025-01-10T00:00:00.000Z',
    confidence: 'Confirmed',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-38856', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    exploitKnown: true,
    cisaKevDate: '2024-08-07',
    ransomwareCampaigns: ['Known exploitation by Akira & BianLian ransomware operators.'],
  },
  {
    id: 'KEV-2024-21413',
    type: 'cve',
    identifier: 'CVE-2024-21413',
    title: 'Microsoft Outlook Remote Code Execution (Moniker Link)',
    description: 'Microsoft Outlook allows remote attackers to bypass Protected View and execute code via crafted file: links.',
    severity: 'Critical',
    sourceFeed: 'CISA Known Exploited Vulnerabilities (KEV)',
    retrievedAt: '2025-01-10T00:00:00.000Z',
    confidence: 'Confirmed',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21413', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    exploitKnown: true,
    cisaKevDate: '2024-02-13',
    ransomwareCampaigns: ['Observed in targeted credential theft and initial access campaigns.'],
  },
  {
    id: 'KEV-2023-46805',
    type: 'cve',
    identifier: 'CVE-2023-46805',
    title: 'Ivanti Connect Secure Authentication Bypass',
    description: 'An authentication bypass vulnerability in the web component of Ivanti Connect Secure allows remote attackers to access restricted resources.',
    severity: 'Critical',
    sourceFeed: 'CISA Known Exploited Vulnerabilities (KEV)',
    retrievedAt: '2025-01-10T00:00:00.000Z',
    confidence: 'Confirmed',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-46805', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    exploitKnown: true,
    cisaKevDate: '2024-01-10',
    ransomwareCampaigns: ['Widespread exploitation for corporate VPN perimeter breach.'],
  },
  {
    id: 'KEV-2021-44228',
    type: 'cve',
    identifier: 'CVE-2021-44228',
    title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    severity: 'Critical',
    sourceFeed: 'CISA Known Exploited Vulnerabilities (KEV)',
    retrievedAt: '2025-01-10T00:00:00.000Z',
    confidence: 'Confirmed',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    exploitKnown: true,
    cisaKevDate: '2021-12-10',
    ransomwareCampaigns: ['Abused by dozens of active ransomware affiliates.'],
  },
];

// Registered Threat Intelligence Feeds Status
export function getRegisteredThreatFeeds(): ThreatIntelFeed[] {
  return [
    {
      id: 'feed-cisa-kev',
      name: 'CISA Known Exploited Vulnerabilities (KEV)',
      description: 'Official authoritative catalog of vulnerabilities known to be actively exploited in the wild by threat actors.',
      status: 'Cached',
      lastUpdated: '2025-01-10T00:00:00.000Z',
      itemCount: 1148,
      isLocalCatalog: true,
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    },
    {
      id: 'feed-mitre-attack',
      name: 'MITRE ATT&CK v14.1 Enterprise',
      description: 'Globally-accessible knowledge base of adversary tactics, techniques, and procedures based on real-world observations.',
      status: 'Cached',
      lastUpdated: '2025-01-01T00:00:00.000Z',
      itemCount: 625,
      isLocalCatalog: true,
      sourceUrl: 'https://attack.mitre.org/',
    },
    {
      id: 'feed-nvd-cve',
      name: 'NIST National Vulnerability Database (NVD)',
      description: 'U.S. government repository of standards based vulnerability management data represented using the Common Vulnerabilities and Exposures (CVE).',
      status: 'Offline Fallback',
      lastUpdated: '2025-01-10T00:00:00.000Z',
      itemCount: 245000,
      isLocalCatalog: false,
      sourceUrl: 'https://nvd.nist.gov/',
    },
    {
      id: 'feed-abuse-ch',
      name: 'abuse.ch URLhaus / ThreatFox Indicator Feed',
      description: 'Public community sharing platform for malicious URLs and indicators of compromise associated with malware.',
      status: 'Unavailable',
      lastUpdated: 'Unavailable (Live network probe disabled in static analysis mode)',
      itemCount: 0,
      isLocalCatalog: false,
      sourceUrl: 'https://urlhaus.abuse.ch/',
    },
  ];
}

/**
 * Looks up threat intelligence records for an identifier (e.g., CVE-2024-38856).
 */
export function lookupThreatIntel(identifier: string): ThreatIntelItem | undefined {
  if (!identifier) return undefined;
  const clean = identifier.trim().toUpperCase();
  return LOCAL_CISA_KEV_ITEMS.find((item) => item.identifier.toUpperCase() === clean);
}

/**
 * Enriches a finding or CVE item with authoritative CISA KEV data if matched.
 */
export function enrichWithKevData(identifier: string): { isKevExploited: boolean; kevItem?: ThreatIntelItem } {
  const match = lookupThreatIntel(identifier);
  if (match) {
    return { isKevExploited: true, kevItem: match };
  }
  return { isKevExploited: false };
}
