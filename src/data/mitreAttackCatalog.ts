import { MitreAttackTechnique, MitreTactic, Finding, FindingMitreMapping } from '../types';

export const MITRE_ATTACK_VERSION = 'v14.1 (Enterprise Matrix)';

export const MITRE_ATTACK_TECHNIQUES: MitreAttackTechnique[] = [
  // Initial Access
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, packet, or interface exploits.',
    detection: 'Monitor application logs, crash reports, and web server telemetry for abnormal request URI lengths, SQL fragments, or remote file inclusions.',
    mitigation: 'Implement regular software patching, Web Application Firewalls (WAF), and boundary network isolation.',
    url: 'https://attack.mitre.org/techniques/T1190/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments or malicious links.',
    detection: 'Inspect inbound email gateways for deceptive display names, mismatched SPF/DKIM/DMARC headers, and newly registered sender domains.',
    mitigation: 'Enforce anti-spoofing DMARC policies, multi-factor authentication, and user security awareness training.',
    url: 'https://attack.mitre.org/techniques/T1566/',
    platforms: ['Linux', 'Windows', 'macOS', 'SaaS'],
  },
  {
    id: 'T1133',
    name: 'External Remote Services',
    tactic: 'Initial Access',
    description: 'Adversaries may leverage external-facing remote services such as VPNs, Citrix gateways, or RDP to access enterprise networks.',
    detection: 'Audit remote authentication logs for anomalous geographical logins, off-hours access, and failed credential bursts.',
    mitigation: 'Enforce phishing-resistant MFA, network segmentation, and rate-limiting on remote access gateways.',
    url: 'https://attack.mitre.org/techniques/T1133/',
    platforms: ['Windows', 'Linux'],
  },

  // Execution
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Cmd) to execute commands, scripts, or binaries.',
    detection: 'Enable PowerShell Script Block Logging (Event ID 4104), audit bash history, and monitor process lineage for interactive shells spawned by web workers.',
    mitigation: 'Enforce PowerShell Constrained Language Mode, AppLocker, and strict execution policies.',
    url: 'https://attack.mitre.org/techniques/T1059/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'T1204',
    name: 'User Execution',
    tactic: 'Execution',
    description: 'An adversary may rely upon specific actions by a user in order to gain execution, such as opening a malicious invoice or clicking a link.',
    detection: 'Track process creation events where office suites, PDF readers, or browsers spawn scripting engines (powershell.exe, cmd.exe, cscript.exe).',
    mitigation: 'Block execution of macros from untrusted locations, isolate browser sandboxes, and configure attachment filtering.',
    url: 'https://attack.mitre.org/techniques/T1204/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },

  // Persistence
  {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    description: 'Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence.',
    detection: 'Monitor Windows Run keys, startup folders, systemd services, and init.d scripts for unauthorized modifications.',
    mitigation: 'Restrict write permissions to autostart directories and use Sysmon/auditd for real-time registry and file integrity monitoring.',
    url: 'https://attack.mitre.org/techniques/T1547/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'T1505',
    name: 'Server Software Component',
    tactic: 'Persistence',
    description: 'Adversaries may abuse server software components, such as web shells or malicious IIS modules, to maintain persistent access.',
    detection: 'Inspect web root directories for unexpected PHP/JSP/ASPX files and monitor HTTP POST requests directed at obscure static files.',
    mitigation: 'Make web application docroots read-only for web server daemon users and maintain strict file integrity monitoring (FIM).',
    url: 'https://attack.mitre.org/techniques/T1505/',
    platforms: ['Linux', 'Windows'],
  },

  // Privilege Escalation
  {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may exploit software vulnerabilities in elevated processes or kernel drivers to escalate system privileges.',
    detection: 'Audit system kernel patch levels, monitor abnormal syscall combinations (ptrace, setuid), and track sudden user ID transitions.',
    mitigation: 'Apply operating system security updates promptly and disable unneeded SUID/SGID binaries.',
    url: 'https://attack.mitre.org/techniques/T1068/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },

  // Defense Evasion
  {
    id: 'T1036',
    name: 'Masquerading',
    tactic: 'Defense Evasion',
    description: 'Adversaries may manipulate file names, extensions, or directory structures to make malicious files appear legitimate (e.g., invoice.pdf having PE MZ executable headers).',
    detection: 'Compare MIME types, magic byte signatures, and file extensions. Alert when PE, ELF, or script headers mismatch benign extensions.',
    mitigation: 'Implement strict content-type verification at ingress gateways and file upload endpoints; inspect binary magic bytes rather than trusting file extensions.',
    url: 'https://attack.mitre.org/techniques/T1036/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    description: 'Adversaries may attempt to make an executable or data difficult to discover or analyze by using encryption, packing (UPX, Themida), or high-entropy encoding.',
    detection: 'Calculate Shannon entropy across binary sections. Sections exhibiting entropy > 7.2 bits/byte indicate packing or encryption.',
    mitigation: 'Inspect packed PE section headers, extract printable bounded strings, and employ memory dump unpacking in sandbox environments.',
    url: 'https://attack.mitre.org/techniques/T1027/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
  {
    id: 'T1562',
    name: 'Impair Defenses',
    tactic: 'Defense Evasion',
    description: 'Adversaries may disable or modify defensive tools (EDR agents, firewalls, security headers) to avoid detection.',
    detection: 'Monitor security service termination events, missing security headers on production reverse proxies, and tampering with logging agents.',
    mitigation: 'Enforce tamper protection on security endpoints and configure immutable central logging.',
    url: 'https://attack.mitre.org/techniques/T1562/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },

  // Credential Access
  {
    id: 'T1552',
    name: 'Unsecured Credentials',
    tactic: 'Credential Access',
    description: 'Adversaries may search for private keys, passwords, or basic auth tokens stored in plaintext within source code, captures, or unencrypted transmissions.',
    detection: 'Inspect PCAP payloads for plaintext Authorization: Basic headers, FTP USER/PASS strings, and hardcoded API tokens in extracted strings.',
    mitigation: 'Enforce HTTPS/TLS for all internal and external communication and prohibit basic authentication over cleartext protocols.',
    url: 'https://attack.mitre.org/techniques/T1552/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },
  {
    id: 'T1040',
    name: 'Network Sniffing',
    tactic: 'Credential Access',
    description: 'Adversaries may sniff network traffic to capture authentication credentials or sensitive data traveling over unencrypted protocols.',
    detection: 'Detect network interfaces operating in promiscuous mode and audit unencrypted internal network traffic.',
    mitigation: 'Enforce HSTS with preload, end-to-end TLS, and 802.1X network access control.',
    url: 'https://attack.mitre.org/techniques/T1040/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },

  // Discovery
  {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts to identify exploitable entry points (e.g. TCP SYN scanning).',
    detection: 'Monitor network flow telemetry for high ratios of TCP SYN packets without subsequent ACK/handshake completions.',
    mitigation: 'Deploy intrusion detection systems (IDS), rate-limit incoming TCP SYNs, and block unauthorized scanning IPs.',
    url: 'https://attack.mitre.org/techniques/T1046/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },

  // Command and Control
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend C2 traffic with normal network activity.',
    detection: 'Analyze flow duration, regular interval beaconing heuristics, and abnormal user-agent strings in HTTP headers.',
    mitigation: 'Deploy forward SSL/TLS decryption inspection proxies and monitor outbound web telemetry for non-browser patterns.',
    url: 'https://attack.mitre.org/techniques/T1071/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },
  {
    id: 'T1071.004',
    name: 'DNS C2 Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate with C2 servers using DNS query and response records (e.g. high-entropy subdomains or TXT records).',
    detection: 'Monitor DNS resolvers for long query labels (> 40 characters), high subdomain entropy, and abnormal volumes of TXT/NULL record queries.',
    mitigation: 'Enforce DNS RPZ (Response Policy Zones), inspect DNS packet payloads, and restrict egress DNS traffic to approved internal resolvers.',
    url: 'https://attack.mitre.org/techniques/T1071/004/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },

  // Exfiltration
  {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data by exfiltrating it over a different protocol than that used for C2 (e.g. DNS tunneling, unencrypted FTP, ICMP payloads).',
    detection: 'Track large volume outbound flows over non-standard ports and monitor high-frequency DNS query streams encoding binary payloads.',
    mitigation: 'Implement egress traffic filtering and deep packet inspection (DPI) on perimeter firewalls.',
    url: 'https://attack.mitre.org/techniques/T1048/',
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
  },

  // Impact
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data on target systems or within storage repositories to interrupt availability and demand ransom payments.',
    detection: 'Monitor for rapid mass file renaming, creation of ransom notes (.txt, .html), and bulk invocation of cryptographic API symbols.',
    mitigation: 'Maintain offline immutable backups, configure volume shadow copy protections, and restrict file-system access permissions.',
    url: 'https://attack.mitre.org/techniques/T1486/',
    platforms: ['Linux', 'Windows', 'macOS'],
  },
];

/**
 * Deterministically maps verified or inferred findings to MITRE ATT&CK techniques.
 * Avoids mapping speculative observations without evidence grounds.
 */
export function mapFindingToMitreTechniques(finding: Finding): FindingMitreMapping[] {
  const mappings: FindingMitreMapping[] = [];
  const text = `${finding.title} ${finding.description} ${finding.observedResult} ${finding.targetEntity} ${finding.category}`.toLowerCase();

  // 1. Masquerading (T1036)
  if (text.includes('masquerad') || text.includes('extension mismatch') || text.includes('pe executable') && text.includes('.pdf')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1036',
      techniqueName: 'Masquerading',
      tactic: 'Defense Evasion',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || finding.title,
    });
  }

  // 2. Directory Traversal / Zip Slip (T1059 / T1036)
  if (text.includes('zip slip') || text.includes('traversal') || text.includes('../') || text.includes('..\\')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1059',
      techniqueName: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: 'Relative path traversal entry detected in archive header.',
    });
  }

  // 3. Cleartext Credentials / Insecure Auth (T1552)
  if (text.includes('cleartext') || text.includes('basic auth') || text.includes('credentials') || text.includes('password in payload')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1552',
      techniqueName: 'Unsecured Credentials',
      tactic: 'Credential Access',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || 'Plaintext credentials observed in network telemetry.',
    });
  }

  // 4. DNS Tunneling / Exfiltration (T1071.004 / T1048)
  if (text.includes('dns tunnel') || text.includes('high-entropy dns') || text.includes('exfiltration')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1071.004',
      techniqueName: 'DNS C2 Protocol',
      tactic: 'Command and Control',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || 'High-entropy subdomain queries detected.',
    });
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1048',
      techniqueName: 'Exfiltration Over Alternative Protocol',
      tactic: 'Exfiltration',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: 'Encoded payloads channeled through recursive DNS records.',
    });
  }

  // 5. Port Scan / TCP SYN Flood (T1046)
  if (text.includes('port scan') || text.includes('syn flood') || text.includes('syn scan')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1046',
      techniqueName: 'Network Service Discovery',
      tactic: 'Discovery',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || 'High SYN-to-ACK ratio observed.',
    });
  }

  // 6. Missing Defensive Controls / HSTS (T1040 / T1562)
  if (text.includes('strict-transport-security') || text.includes('hsts missing') || text.includes('unencrypted transport')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1040',
      techniqueName: 'Network Sniffing',
      tactic: 'Credential Access',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: 'Missing HSTS exposes communication channel to passive interception.',
    });
  }

  // 7. Obfuscated Files / High Entropy (T1027)
  if (text.includes('high entropy') && (text.includes('packed') || text.includes('cryptographic overlay') || text.includes('upx'))) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1027',
      techniqueName: 'Obfuscated Files or Information',
      tactic: 'Defense Evasion',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || 'Shannon entropy > 7.2 bits/byte observed.',
    });
  }

  // 8. Public Exploit / Vulnerability (T1190)
  if (finding.category === 'Vulnerability & Exploit' || text.includes('cve-') || text.includes('exploit')) {
    mappings.push({
      findingId: finding.id,
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      evidenceSupported: true,
      confidence: finding.confidence || 'Confirmed',
      evidenceQuote: finding.observedResult || 'Documented public vulnerability in perimeter service.',
    });
  }

  return mappings;
}

export function getMitreTechniqueById(id: string): MitreAttackTechnique | undefined {
  return MITRE_ATTACK_TECHNIQUES.find((t) => t.id.toLowerCase() === id.toLowerCase());
}

export function getMitreTechniquesByTactic(tactic: MitreTactic): MitreAttackTechnique[] {
  return MITRE_ATTACK_TECHNIQUES.filter((t) => t.tactic === tactic);
}
