export type ConfidenceLevel = 'Observed' | 'Confirmed' | 'Inferred' | 'Potential' | 'Unknown';

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type InvestigationStatus = 'Open' | 'In Progress' | 'Analyzing' | 'Closed' | 'Archived';

export type FindingCategory =
  | 'Network & Protocol'
  | 'Binary & Static Forensics'
  | 'Infrastructure & Recon'
  | 'Vulnerability & Exploit'
  | 'Hardening & Security Header'
  | 'Correlation Observation';

export type CorrelationStatus = 'confirmed' | 'unverified' | 'dismissed';

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
  id: string; // Unique finding ID (e.g. FND-0047-01)
  caseId?: string; // Associated case ID
  title: string;
  category: FindingCategory;
  targetEntity: string; // Target or affected entity (domain, IP, file name, host, hash)
  observedResult: string; // Actual observed result
  description: string;
  severity: SeverityLevel;
  severityRationale?: string; // Explanation of severity weighting
  confidence: ConfidenceLevel;
  status: 'Unresolved' | 'Investigating' | 'Mitigated' | 'False Positive';
  sourceTool: string; // Evidence source / tool subsystem
  evidenceSource?: string; // Specific telemetry stream or probe
  collectedAt: string; // UTC observation timestamp (ISO 8601)
  timestamp?: string; // UTC observation timestamp alias
  provenance?: string; // Sensor or extraction provenance
  limitations?: string[]; // Bounded buffers, missing fields, or environmental constraints
  relevantInput?: string; // Raw input tested / queried
  evidenceIds: string[]; // Related evidence IDs
  relatedFindingIds?: string[]; // Correlated or related finding IDs
  riskImplications?: string; // Measured impact without hyperbole

  // Phase 6 Unified Finding Confidence & Evidence Verification Architecture
  verificationStatus?: 'VERIFIED' | 'INFERRED' | 'UNKNOWN'; // Ground-truth evidence verification
  confidenceLevel?: 'HIGH' | 'MEDIUM' | 'LOW'; // Explainable confidence tier
  evidenceReference?: string; // Explicit evidence pointer (e.g. "DNS A Record: 93.184.216.34", "SHA-256 Hash")
  detectionMethod?: string; // Specific sensor/technique (e.g. "Direct Probe Observation", "Cryptographic Hash")
  potentialFalsePositiveExplanation?: string; // Explainable conditions that could trigger false positive
  recommendedNextStep?: string; // Concrete next step for investigator
}

export interface CaseRecord {
  id: string; // e.g. #VY-2025-0047
  title: string;
  description: string;
  priority: SeverityLevel;
  status: InvestigationStatus;
  leadAnalyst: string;
  classification?: string;
  createdAt: string;
  updatedAt: string;
  scope: string[];
  tags: string[];
  evidence: EvidenceItem[];
  findings: Finding[];
  correlationOverrides?: Record<string, CorrelationStatus>; // edgeId -> status
  dismissedCorrelationIds?: string[];
  unverifiedCorrelationIds?: string[];
  isTrainingScenario?: boolean;
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
  timeline?: any[];
}

export type ProvenanceStatus =
  | 'Retrieved'
  | 'Cached'
  | 'Unavailable'
  | 'Blocked'
  | 'TimedOut'
  | 'NotChecked';

export interface FieldProvenance {
  status: ProvenanceStatus;
  source: string;
  timestamp: string;
  details?: string;
  ageMs?: number;
}

export interface SecurityHeaderObservation {
  header: string;
  value: string | null;
  observed: boolean;
  status: 'Present' | 'Missing' | 'Unobserved';
  description: string;
  hardeningRole: string;
  isProofOfExploit: boolean;
}

export interface RiskFactorItem {
  id: string;
  category: string;
  title: string;
  weight: number;
  observedValue: string;
  rationale: string;
  mitigation: string;
}

export interface DomainAnalysisReport {
  domain: string;
  targetNormalized: string;
  analysisTimestamp: string;
  engineVersion: string;
  provenance: {
    dns: FieldProvenance;
    tls: FieldProvenance;
    http: FieldProvenance;
    rdap: FieldProvenance;
  };
  resolvedIps: { ip: string; version: number; resolver?: string; isCdnOrCloud?: boolean }[];
  dnsRecords: {
    a: string[];
    aaaa: string[];
    mx: { exchange: string; priority: number }[];
    txt: string[][];
    ns: string[];
    cname?: string[];
  };
  dnsFailed?: boolean;
  tlsCertificate?: {
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
  };
  httpProbe?: {
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
  };
  rdap?: {
    status: 'Retrieved' | 'Unavailable' | 'RateLimited' | 'Forbidden' | 'TimedOut';
    sourceUrl?: string;
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
  };
  uncompletedChecks: Array<{ check: string; reason: string; category: string }>;
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  riskFactors: string[];
  riskFactorDetails: RiskFactorItem[];
  scoringLimitations: string[];
  dataCompleteness: number; // 0 to 100%
  ssrfGuards: {
    passed: boolean;
    checkedAddresses: string[];
  };
  aiSecurityAnalysis?: DomainAiSecurityAnalysis;
}

export type InvestigationViewMode = 'simple' | 'deep';

export interface PrioritizedNextStep {
  priority: 'Immediate' | 'High Priority' | 'Scheduled Hardening' | 'Verification';
  action: string;
  rationale: string;
}

export interface FindingRemediationGuide {
  detectedTechnology?: string; // e.g. "nginx", "apache", "cloudflare", "express", "generic"
  configSnippet: string;
  configLocation: string; // e.g. "/etc/nginx/conf.d/security.conf"
  verificationCommand: string; // e.g. "curl -I https://domain"
  documentationUrl?: string; // MDN or RFC link
  thirdPartyHostedNote?: string; // Guidance for Cloudflare, CloudFront, Vercel
  alternativeConfigs?: Array<{
    technology: string;
    snippet: string;
    location: string;
  }>;
}

export interface SimpleFindingItem {
  id: string;
  title: string;
  category: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  severityExplanation: string;
  confidence: 'Confirmed' | 'Potential' | 'Inferred' | 'Unknown';
  whatObserved: string;
  whatThisMeans: string;
  potentialRisk: string;
  possibleAttackScenario: string;
  howToPreventIt: string;
  technicalDetails?: string;
  remediationGuide?: FindingRemediationGuide;
  // Phase 6 Unified Confidence Engine
  verificationStatus?: 'VERIFIED' | 'INFERRED' | 'UNKNOWN';
  confidenceLevel?: 'HIGH' | 'MEDIUM' | 'LOW';
  evidenceReference?: string;
  detectionMethod?: string;
  potentialFalsePositiveExplanation?: string;
  recommendedNextStep?: string;
}

export interface InvestigationSimpleReport {
  target: string;
  targetType: 'domain' | 'file' | 'pcap' | 'case';
  generatedAt: string;
  overallAssessment: string;
  whatWasDiscovered: string[];
  whatIsWorkingWell: string[];
  securityConcerns: SimpleFindingItem[];
  prioritizedNextSteps: PrioritizedNextStep[];
  limitations: string[];
  disclaimer: string;
  isAiGenerated?: boolean;
  modelUsed?: string;
}

export interface DomainSecurityFindingAnalysis {
  id: string;
  title: string;
  category: 'Header Hardening' | 'Transport Security' | 'DNS & Infrastructure' | 'Registration & RDAP' | 'Redirect & Routing';
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  severityExplanation: string;
  confidence: 'Confirmed' | 'Potential' | 'Inferred' | 'Unknown';
  whatObserved: string;
  whatThisMeans: string;
  potentialRisk: string;
  possibleAttackScenario: string;
  howToPreventIt: string;
  technicalDetails?: string;
  remediationGuide?: FindingRemediationGuide;
  // Phase 6 Unified Confidence Engine
  verificationStatus?: 'VERIFIED' | 'INFERRED' | 'UNKNOWN';
  confidenceLevel?: 'HIGH' | 'MEDIUM' | 'LOW';
  evidenceReference?: string;
  detectionMethod?: string;
  potentialFalsePositiveExplanation?: string;
  recommendedNextStep?: string;
}

export interface DomainAiSecurityAnalysis {
  domain: string;
  generatedAt: string;
  modelUsed: string;
  isAiGenerated: boolean;
  overallAssessment: string;
  keyFactsObserved: string[];
  findings: DomainSecurityFindingAnalysis[];
  positiveHighlights: string[];
  prioritizedNextSteps?: PrioritizedNextStep[];
  limitations: string[];
  disclaimer: string;
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
    hasZipSlipTraversal?: boolean;
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
  simpleReport?: InvestigationSimpleReport;
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

export interface PcapInterfaceInfo {
  id: number;
  linkType: number;
  linkTypeName: string;
  name?: string;
  tsResolution: string;
  tsOffsetSeconds: number;
  isBinaryResolution: boolean;
  malformedOptions?: boolean;
}

export interface PcapPacket {
  index: number;
  timestamp: number; // microseconds or millis (0 if unreliable/missing)
  timeStr: string;
  length: number;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'IPv6' | 'Other';
  appProtocol?: string;
  info: string;
  interfaceId?: number;
  timestampUnreliable?: boolean;
  timestampLimitation?: string;
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
  interfaces?: PcapInterfaceInfo[];
  linkType?: number;
  linkTypeName?: string;
  truncatedPacketsCount?: number;
  unsupportedLinkType?: boolean;
  simpleReport?: InvestigationSimpleReport;
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
  | 'evidence-graph'
  | 'vulnerability-intel'
  | 'ai-analysis'
  | 'reports'
  | 'data-sources'
  | 'settings'
  | 'android-project';
