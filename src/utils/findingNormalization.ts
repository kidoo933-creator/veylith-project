import { Finding, FindingCategory, SeverityLevel, ConfidenceLevel } from '../types';
import { classifyFindingConfidence } from './aiEvidenceGrounding';

/**
 * Validates that an ISO string is a valid UTC date.
 * If invalid or absent, returns the current UTC time in ISO format.
 */
export function ensureUtcIsoString(timestamp?: string): string {
  if (!timestamp) return new Date().toISOString();
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}

/**
 * Generates a standard defensible finding ID.
 * Example: FND-VY20250047-01
 */
export function generateFindingId(caseId?: string, sequence?: number): string {
  const prefix = caseId ? caseId.replace(/[^A-Za-z0-9]/g, '') : 'GEN';
  const seqStr = sequence !== undefined ? String(sequence).padStart(2, '0') : Math.random().toString(36).slice(2, 6).toUpperCase();
  return `FND-${prefix}-${seqStr}`;
}

/**
 * Normalizes a partial or raw finding into a strict, unified Finding record.
 * Guarantees that no fields are fabricated while ensuring defensible defaults
 * for category, timestamp, severity rationale, limitations, and evidence links.
 */
export function normalizeFinding(raw: Partial<Finding>, caseId?: string): Finding {
  const nowUtc = ensureUtcIsoString(raw.collectedAt || raw.timestamp);
  const targetCaseId = raw.caseId || caseId;

  // Derive target entity
  const targetEntity =
    raw.targetEntity?.trim() ||
    raw.relevantInput?.trim() ||
    'Unspecified Target';

  // Derive observed result
  const observedResult =
    raw.observedResult?.trim() ||
    raw.description?.trim() ||
    raw.title?.trim() ||
    'No verifiable observation recorded.';

  // Map category or select appropriate default
  let category: FindingCategory = 'Infrastructure & Recon';
  if (raw.category) {
    category = raw.category;
  } else if (raw.sourceTool?.includes('File') || raw.title?.toLowerCase().includes('file') || raw.title?.toLowerCase().includes('binary')) {
    category = 'Binary & Static Forensics';
  } else if (raw.sourceTool?.includes('Pcap') || raw.sourceTool?.includes('Network') || raw.title?.toLowerCase().includes('beacon')) {
    category = 'Network & Protocol';
  } else if (raw.title?.toLowerCase().includes('cve') || raw.title?.toLowerCase().includes('vulnerability')) {
    category = 'Vulnerability & Exploit';
  } else if (raw.title?.toLowerCase().includes('header') || raw.title?.toLowerCase().includes('csp') || raw.title?.toLowerCase().includes('hsts')) {
    category = 'Hardening & Security Header';
  }

  // Derive defensible severity and rationale
  const severity: SeverityLevel = raw.severity || 'Info';
  let severityRationale = raw.severityRationale?.trim();
  if (!severityRationale) {
    switch (severity) {
      case 'Critical':
        severityRationale = 'Confirmed high-impact indicator directly threatening asset integrity or active unauthorized egress.';
        break;
      case 'High':
        severityRationale = 'High-probability indicator of masquerading, untrusted cryptographic identity, or remote code access path.';
        break;
      case 'Medium':
        severityRationale = 'Anomalous operational behavior or elevated indicator requiring analyst verification.';
        break;
      case 'Low':
        severityRationale = 'Hardening deficiency or non-standard configuration without evidence of active technical exploitability.';
        break;
      case 'Info':
      default:
        severityRationale = 'Informational baseline observation recorded for operational context and situational awareness.';
        break;
    }
  }

  const limitations = Array.isArray(raw.limitations)
    ? raw.limitations.filter(Boolean)
    : [];

  const evidenceIds = Array.isArray(raw.evidenceIds)
    ? Array.from(new Set(raw.evidenceIds.filter(Boolean)))
    : [];

  const relatedFindingIds = Array.isArray(raw.relatedFindingIds)
    ? Array.from(new Set(raw.relatedFindingIds.filter(Boolean)))
    : [];

  const confidenceMeta = classifyFindingConfidence({
    title: raw.title || 'Untitled Observation',
    category,
    observedResult,
    detectionMethod: raw.detectionMethod,
    evidenceReference: raw.evidenceReference,
    isDirectTelemetry: raw.confidence !== 'Inferred' && raw.confidence !== 'Potential',
  });

  const finding: Finding = {
    id: raw.id || generateFindingId(targetCaseId),
    caseId: targetCaseId,
    title: raw.title?.trim() || 'Untitled Observation',
    category,
    targetEntity,
    observedResult,
    description: raw.description?.trim() || observedResult,
    severity,
    severityRationale,
    confidence: raw.confidence || 'Observed',
    status: raw.status || 'Unresolved',
    sourceTool: raw.sourceTool || 'Veylith Forensics Core',
    evidenceSource: raw.evidenceSource || raw.sourceTool || 'Veylith Sensor',
    collectedAt: nowUtc,
    timestamp: nowUtc,
    provenance: raw.provenance || `${raw.sourceTool || 'Veylith'} Telemetry Capture`,
    limitations,
    relevantInput: raw.relevantInput || targetEntity,
    evidenceIds,
    relatedFindingIds,
    riskImplications: raw.riskImplications || undefined,
    // Phase 6 Unified Confidence Engine
    verificationStatus: raw.verificationStatus || confidenceMeta.verificationStatus,
    confidenceLevel: raw.confidenceLevel || confidenceMeta.confidenceLevel,
    detectionMethod: raw.detectionMethod || confidenceMeta.detectionMethod,
    evidenceReference: raw.evidenceReference || confidenceMeta.evidenceReference,
    potentialFalsePositiveExplanation: raw.potentialFalsePositiveExplanation || raw.falsePositiveExplanation || confidenceMeta.potentialFalsePositiveExplanation,
    falsePositiveExplanation: raw.falsePositiveExplanation || raw.potentialFalsePositiveExplanation || confidenceMeta.potentialFalsePositiveExplanation,
    recommendedNextStep: raw.recommendedNextStep || confidenceMeta.recommendedNextStep,
    remediationGuide: raw.remediationGuide,
  };

  return finding;
}

/**
 * Creates a Domain Recon / TLS / Header finding with full Phase 1 metadata.
 */
export function createDomainFinding(params: {
  caseId: string;
  domain: string;
  title: string;
  category?: FindingCategory;
  observedResult: string;
  description: string;
  severity: SeverityLevel;
  severityRationale: string;
  confidence?: ConfidenceLevel;
  sourceTool: string;
  evidenceIds: string[];
  limitations?: string[];
  riskImplications?: string;
}): Finding {
  return normalizeFinding(
    {
      caseId: params.caseId,
      title: params.title,
      category: params.category || 'Infrastructure & Recon',
      targetEntity: params.domain,
      observedResult: params.observedResult,
      description: params.description,
      severity: params.severity,
      severityRationale: params.severityRationale,
      confidence: params.confidence || 'Observed',
      status: 'Unresolved',
      sourceTool: params.sourceTool,
      evidenceSource: `${params.sourceTool} / Probe Telemetry`,
      provenance: `Direct network socket probe to target domain (${params.domain})`,
      limitations: params.limitations || [
        'Passive read-only query; does not evaluate internal network services behind firewalls.',
      ],
      relevantInput: params.domain,
      evidenceIds: params.evidenceIds,
      riskImplications: params.riskImplications,
    },
    params.caseId
  );
}

/**
 * Creates a Static File Forensics finding with full Phase 1 metadata.
 */
export function createFileForensicsFinding(params: {
  caseId: string;
  fileName: string;
  sha256: string;
  title: string;
  observedResult: string;
  description: string;
  severity: SeverityLevel;
  severityRationale: string;
  confidence?: ConfidenceLevel;
  evidenceIds: string[];
  limitations?: string[];
  riskImplications?: string;
}): Finding {
  return normalizeFinding(
    {
      caseId: params.caseId,
      title: params.title,
      category: 'Binary & Static Forensics',
      targetEntity: `${params.fileName} (${params.sha256.slice(0, 16)}...)`,
      observedResult: params.observedResult,
      description: params.description,
      severity: params.severity,
      severityRationale: params.severityRationale,
      confidence: params.confidence || 'Observed',
      status: 'Investigating',
      sourceTool: 'Veylith File Forensics Engine',
      evidenceSource: 'Local In-Memory Demuxer & Magic Signature Scanner',
      provenance: 'Local file buffer parsing via WebCrypto & deterministic byte header inspection',
      limitations: params.limitations || [
        'Static file analysis only; dynamic behavioral sandbox telemetry not executed.',
      ],
      relevantInput: params.fileName,
      evidenceIds: params.evidenceIds,
      riskImplications: params.riskImplications,
    },
    params.caseId
  );
}

/**
 * Creates a PCAP Packet Lab finding with full Phase 1 metadata.
 */
export function createPcapFinding(params: {
  caseId: string;
  pcapFile: string;
  title: string;
  targetEndpoint: string;
  observedResult: string;
  description: string;
  severity: SeverityLevel;
  severityRationale: string;
  confidence?: ConfidenceLevel;
  evidenceIds: string[];
  limitations?: string[];
  riskImplications?: string;
}): Finding {
  return normalizeFinding(
    {
      caseId: params.caseId,
      title: params.title,
      category: 'Network & Protocol',
      targetEntity: params.targetEndpoint,
      observedResult: params.observedResult,
      description: params.description,
      severity: params.severity,
      severityRationale: params.severityRationale,
      confidence: params.confidence || 'Observed',
      status: 'Unresolved',
      sourceTool: 'Veylith PCAP Lab',
      evidenceSource: 'Frame Demuxer & Transport Conversation Parser',
      provenance: `Demuxed from capture frame stream (${params.pcapFile})`,
      limitations: params.limitations || [
        'Packet analysis bounded to captured frame payload; encrypted TLS sessions not decrypted without private key material.',
      ],
      relevantInput: params.targetEndpoint,
      evidenceIds: params.evidenceIds,
      riskImplications: params.riskImplications,
    },
    params.caseId
  );
}
