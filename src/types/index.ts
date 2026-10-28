export type ConfidenceLevel = 'Observed' | 'Confirmed' | 'Inferred' | 'Potential' | 'Unknown';

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type InvestigationStatus = 'Open' | 'In Progress' | 'Analyzing' | 'Closed' | 'Archived';

export interface EvidenceItem {
  id: string;
  caseId?: string;
  name: string;
  type: 'domain' | 'ip' | 'file' | 'hash' | 'cve' | 'pcap' | 'header' | 'certificate' | 'finding';
  value: string;
  confidence: ConfidenceLevel;
  source: string;
  timestamp: string;
  metadata?: Record<string, any>;
  notes?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  status: 'Unresolved' | 'Investigating' | 'Mitigated' | 'False Positive';
  sourceTool: string;
  collectedAt: string;
  relevantInput: string;
  evidenceIds: string[];
}

export interface CaseRecord {
  id: string; // e.g. #VY-2025-0047
  title: string;
  description: string;
  priority: SeverityLevel;
  status: InvestigationStatus;
  leadAnalyst: string;
  createdAt: string;
  updatedAt: string;
  scope: string[];
  tags: string[];
  evidence: EvidenceItem[];
  findings: Finding[];
  notes: {
    id: string;
    author: string;
    text: string;
    timestamp: string;
  }[];
  auditLog: {
    id: string;
    action: string;
    actor: string;
    timestamp: string;
    details: string;
  }[];
}

export interface DomainAnalysisReport {
  domain: string;
  resolvedIps: { ip: string; version: number }[];
  dnsRecords: {
    a: string[];
    aaaa: string[];
    mx: { exchange: string; priority: number }[];
    txt: string[][];
    ns: string[];
  };
  tlsCertificate?: {
    valid: boolean;
    subject?: string;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    protocol?: string;
    cipher?: string;
  };
  httpProbe?: {
    statusCode?: number;
    statusText?: string;
    redirectChain: string[];
    securityHeaders: Record<string, string | null>;
    missingSecurityHeaders: string[];
    serverBanner?: string;
    contentLength?: number;
  };
  rdap?: any;
  uncompletedChecks: string[];
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  riskFactors: string[];
}

export interface EntropyBlock {
  blockIndex: number;
  offset: number;
  entropy: number;
}

export interface UnavailableCheck {
  name: string;
  category: string;
  reason: string;
  defensiveAlternative: string;
}

export interface BoundedMetadata {
  peMetadata?: {
    machine?: string;
    subsystem?: string;
    is64Bit?: boolean;
    peHeaderOffset?: number;
    compileTimestamp?: string;
    numberOfSections?: number;
    sections?: { name: string; virtualSize: number; rawSize: number; entropy: number }[];
  };
  elfMetadata?: {
    bitness?: string;
    endianness?: string;
    osAbi?: string;
    type?: string;
    machine?: string;
  };
  pdfMetadata?: {
    version?: string;
    hasJavaScript?: boolean;
    hasLaunchActions?: boolean;
    hasOpenAction?: boolean;
    hasEmbeddedFiles?: boolean;
    objectCount?: number;
  };
  apkMetadata?: {
    isApk: boolean;
    packageName?: string;
    permissions?: { name: string; risk: 'Dangerous' | 'Privacy' | 'Normal'; description: string }[];
    dexFilesFound?: number;
    dexFileNames?: string[];
    nativeArchitectures?: string[];
    hasCertificates?: boolean;
    hasDebuggableFlag?: boolean;
  };
}

export interface FileAnalysisResult {
  fileName: string;
  fileSize: number;
  fileSizeFormatted: string;
  mimeType: string;
  sha256: string;
  sha1: string;
  md5: string;
  magicBytes: string;
  detectedFormat: string;
  formatMismatch: boolean;
  mismatchDescription?: string;
  entropy: number;
  entropyEvaluation: {
    status: 'Normal' | 'Moderate' | 'High';
    explanation: string;
  };
  entropyBlocks?: EntropyBlock[];
  printableStrings: {
    total: number;
    extracted: { value: string; category: 'url' | 'ip' | 'api' | 'path' | 'string' | 'command' | 'registry' }[];
  };
  metadata?: BoundedMetadata;
  apkDetails?: {
    isApk: boolean;
    packageName?: string;
    permissions?: string[];
    dexFilesFound?: number;
    hasDebuggableFlag?: boolean;
  };
  unavailableChecks: UnavailableCheck[];
  timestamp: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  timestamp: string;
  modelUsed?: string;
  roleName?: string;
  isFallback?: boolean;
}

export interface PcapPacket {
  index: number;
  timestamp: number; // microseconds or millis
  timeStr: string;
  length: number;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'IPv6' | 'Other';
  appProtocol?: string;
  info: string;
}

export interface PcapAnalysisResult {
  fileName: string;
  fileSize: number;
  format: 'PCAP (Standard)' | 'PCAPNG (Next Gen)' | 'Unknown';
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  avgPacketRate: number;
  protocols: Record<string, number>;
  topConversations: {
    pair: string;
    src: string;
    dst: string;
    packets: number;
    bytes: number;
    proto: string;
  }[];
  anomalies: {
    severity: SeverityLevel;
    title: string;
    description: string;
    evidence: string;
  }[];
  packets: PcapPacket[];
}

export interface CveItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  cvss: number;
  severity: SeverityLevel;
  notes?: string;
  references: string[];
}

export type ViewTab =
  | 'overview'
  | 'domain-intel'
  | 'file-forensics'
  | 'pcap-lab'
  | 'investigation-workspace'
  | 'vulnerability-intel'
  | 'ai-analysis'
  | 'reports'
  | 'data-sources'
  | 'settings'
  | 'android-project';
