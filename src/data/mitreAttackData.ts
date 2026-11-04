import { MitreAttackTechnique, MitreTacticId } from '../types';

export interface MitreTacticDefinition {
  id: MitreTacticId;
  name: string;
  description: string;
}

export const MITRE_TACTICS: Record<MitreTacticId, MitreTacticDefinition> = {
  TA0001: {
    id: 'TA0001',
    name: 'Initial Access',
    description: 'Techniques adversaries use to enter the target enterprise network.',
  },
  TA0002: {
    id: 'TA0002',
    name: 'Execution',
    description: 'Techniques that result in adversary-controlled code running on a local or remote system.',
  },
  TA0003: {
    id: 'TA0003',
    name: 'Persistence',
    description: 'Techniques used to maintain their foothold across restarts, changed credentials, and other interruptions.',
  },
  TA0004: {
    id: 'TA0004',
    name: 'Privilege Escalation',
    description: 'Techniques that adversaries use to gain higher-level permissions on a system or network.',
  },
  TA0005: {
    id: 'TA0005',
    name: 'Defense Evasion',
    description: 'Techniques adversaries use to avoid detection throughout their compromise.',
  },
  TA0006: {
    id: 'TA0006',
    name: 'Credential Access',
    description: 'Techniques for stealing credentials like account names and passwords.',
  },
  TA0007: {
    id: 'TA0007',
    name: 'Discovery',
    description: 'Techniques an adversary may use to gain knowledge about the system and internal network.',
  },
  TA0008: {
    id: 'TA0008',
    name: 'Lateral Movement',
    description: 'Techniques that adversaries use to enter and control remote systems on a network.',
  },
  TA0009: {
    id: 'TA0009',
    name: 'Collection',
    description: 'Techniques adversaries may use to gather data of interest to their goal.',
  },
  TA0011: {
    id: 'TA0011',
    name: 'Command and Control',
    description: 'Techniques that adversaries may use to communicate with systems under their control.',
  },
  TA0010: {
    id: 'TA0010',
    name: 'Exfiltration',
    description: 'Techniques that adversaries use to steal data from your network.',
  },
  TA0040: {
    id: 'TA0040',
    name: 'Impact',
    description: 'Techniques adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes.',
  },
};

export const MITRE_TECHNIQUES: MitreAttackTechnique[] = [
  // Initial Access
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries may attempt to exploit a vulnerability or weakness in an Internet-facing computer or program.',
    detectionGuidance: 'Monitor web server application logs, ingress WAF blocks, and unusual inbound HTTP POST requests targeting known CVE patterns.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1190/',
  },
  {
    id: 'T1133',
    name: 'External Remote Services',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries may leverage external-facing remote services such as VPNs, Citrix, or RDP to gain initial access.',
    detectionGuidance: 'Audit ingress network perimeter for unauthenticated remote desktop (3389) or SSH (22) without multi-factor authentication.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1133/',
  },
  {
    id: 'T1566',
    name: 'Phishing',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries may send phishing messages with malicious attachments or links to trick users into executing code.',
    detectionGuidance: 'Analyze inbound email links for typo-squatted domains and attachments containing macro-enabled or disguised executable payloads.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/',
  },

  // Defense Evasion
  {
    id: 'T1036.001',
    name: 'Masquerading: Invalid Code Signatures',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries may disguise metadata or fake file extensions to fool users or security controls into trusting an executable file.',
    detectionGuidance: 'Compare magic byte signatures (MZ, ELF) against declared file extensions and container metadata.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1036/001/',
  },
  {
    id: 'T1036.005',
    name: 'Masquerading: Match Legitimate Name or Location',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries may match or approximate the name or location of legitimate files or system utilities.',
    detectionGuidance: 'Inspect binary execution paths and hash matches against known benign operating system baselines.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1036/005/',
  },
  {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.',
    detectionGuidance: 'Calculate Shannon entropy across file sections; values exceeding 7.2 bits/byte in code sections indicate packing or encryption.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1027/',
  },
  {
    id: 'T1027.002',
    name: 'Software Packing',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries may perform software packing (e.g. UPX, Themida) to compress and conceal the actual payload logic.',
    detectionGuidance: 'Detect UPX section names (.UPX0, .UPX1) and section raw sizes significantly smaller than virtual sizes.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1027/002/',
  },
  {
    id: 'T1562.001',
    name: 'Impair Defenses: Disable or Modify Tools',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries may modify system configurations, strip headers, or disable security tools to prevent detection.',
    detectionGuidance: 'Detect missing security headers (CSP, HSTS) or disabled host firewall rules on production infrastructure.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1562/001/',
  },

  // Execution
  {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution.',
    detectionGuidance: 'Inspect extracted strings for encoded command execution flags (-enc, -encodedCommand) and download cradles.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1059/001/',
  },
  {
    id: 'T1059.004',
    name: 'Command and Scripting Interpreter: Unix Shell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'Adversaries may abuse Unix shell commands (/bin/sh, /bin/bash) for execution.',
    detectionGuidance: 'Extract commands referencing curl, wget, chmod +x, or reverse shell syntax (/dev/tcp).',
    referenceUrl: 'https://attack.mitre.org/techniques/T1059/004/',
  },

  // Credential Access
  {
    id: 'T1552.001',
    name: 'Unsecured Credentials: Credentials in Files',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    description: 'Adversaries may search local files, network streams, or capture logs for insecurely stored plaintext credentials.',
    detectionGuidance: 'Detect plaintext Authorization: Basic, USER/PASS commands, or private keys within network captures and file dumps.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1552/001/',
  },
  {
    id: 'T1040',
    name: 'Network Sniffing',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    description: 'Adversaries may sniff network traffic to capture cleartext credentials or sensitive communication.',
    detectionGuidance: 'Audit network segments for promiscuous mode capture activity and unencrypted administrative protocols (HTTP, FTP, Telnet).',
    referenceUrl: 'https://attack.mitre.org/techniques/T1040/',
  },

  // Discovery
  {
    id: 'T1046',
    name: 'Network Service Discovery',
    tacticId: 'TA0007',
    tacticName: 'Discovery',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable targets.',
    detectionGuidance: 'Detect high ratios of TCP SYN packets across multiple destination ports without completing three-way handshakes.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1046/',
  },
  {
    id: 'T1595.002',
    name: 'Active Scanning: Vulnerability Scanning',
    tacticId: 'TA0007',
    tacticName: 'Discovery',
    description: 'Adversaries may execute automated vulnerability scanners against external web applications.',
    detectionGuidance: 'Detect repeated probes with distinctive scanner User-Agents (e.g. Nikto, Nuclei, Acunetix) or rapid path enumerations.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1595/002/',
  },

  // Command and Control
  {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to blend in.',
    detectionGuidance: 'Examine regular beaconing intervals, anomalous User-Agent strings, and connections to unregistered dynamic DNS domains.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1071/001/',
  },
  {
    id: 'T1071.004',
    name: 'Application Layer Protocol: DNS',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries may communicate using DNS protocol messages to evade firewalls that allow outbound port 53.',
    detectionGuidance: 'Detect high-entropy subdomains, unusual query lengths (> 40 characters), and abnormally high volumes of TXT or NULL records.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1071/004/',
  },
  {
    id: 'T1573',
    name: 'Encrypted Channel',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries may employ a known encryption protocol, such as TLS/SSL, to conceal command and control traffic.',
    detectionGuidance: 'Inspect TLS Client Hello Server Name Indication (SNI) against threat intelligence feeds and monitor for self-signed certificates.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1573/',
  },

  // Exfiltration
  {
    id: 'T1048.003',
    name: 'Exfiltration Over Alternative Protocol: DNS Exfiltration',
    tacticId: 'TA0010',
    tacticName: 'Exfiltration',
    description: 'Adversaries may steal data by encoding stolen content into DNS query labels destined for attacker-controlled authoritative nameservers.',
    detectionGuidance: 'Calculate aggregate subdomain byte lengths and identify base32/hex-encoded payloads in outbound DNS traffic.',
    referenceUrl: 'https://attack.mitre.org/techniques/T1048/003/',
  },
];
