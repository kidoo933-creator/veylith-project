import { CaseRecord, InvestigationQaReport, QaIssue, QaCheckCategory } from '../types';
import { normalizeUtcTimestamp } from './timelineEngine';

/**
 * Deterministically audits an investigation CaseRecord across 8 core quality and defensibility dimensions.
 */
export function auditInvestigationQuality(caseRecord: CaseRecord): InvestigationQaReport {
  const issues: QaIssue[] = [];
  let totalChecks = 8;
  let passedChecks = 0;

  const evidence = caseRecord.evidence || [];
  const findings = caseRecord.findings || [];
  const auditLog = caseRecord.auditLog || [];

  // =========================================================================
  // CHECK 1: Missing Provenance
  // =========================================================================
  const unprovenancedEvidence = evidence.filter((ev) => !ev.source || ev.source === 'Unknown' || ev.source.trim() === '');
  if (unprovenancedEvidence.length > 0) {
    issues.push({
      id: 'QA-PROV-01',
      category: 'Provenance',
      severity: 'Warning',
      title: 'Evidence Items Missing Ingestion Provenance',
      description: `${unprovenancedEvidence.length} evidence artifact(s) do not record an origin sensor, collector, or acquisition tool: [${unprovenancedEvidence.map((e) => e.id).join(', ')}].`,
      targetType: 'evidence',
      actionableRemediation: 'Update evidence records with authoritative acquisition tool (e.g., "PCAP Lab Dissector", "Domain DNS Engine").',
    });
  } else {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 2: Timestamp Inconsistencies
  // =========================================================================
  const inconsistentTimeItems: { id: string; issue: string }[] = [];
  evidence.forEach((ev) => {
    const norm = normalizeUtcTimestamp(ev.timestamp);
    if (norm.inconsistency) {
      inconsistentTimeItems.push({ id: ev.id, issue: `${norm.inconsistency}: ${norm.details || ''}` });
    }
  });
  findings.forEach((f) => {
    const norm = normalizeUtcTimestamp(f.collectedAt || f.timestamp);
    if (norm.inconsistency) {
      inconsistentTimeItems.push({ id: f.id, issue: `${norm.inconsistency}: ${norm.details || ''}` });
    }
  });

  if (inconsistentTimeItems.length > 0) {
    issues.push({
      id: 'QA-TIME-01',
      category: 'Timestamps',
      severity: 'Warning',
      title: 'Timestamp Inconsistencies or Missing Timezones Detected',
      description: `${inconsistentTimeItems.length} artifact(s) exhibit timestamp anomalies (future dates, missing UTC offsets, or epoch zero): ${inconsistentTimeItems.map((i) => `${i.id} (${i.issue})`).join('; ')}.`,
      targetType: 'evidence',
      actionableRemediation: 'Re-synchronize sensor clocks and enforce strict ISO-8601 UTC notation with explicit "Z" suffix.',
    });
  } else {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 3: Duplicate Evidence Detection
  // =========================================================================
  const seenEvidence = new Map<string, string>();
  const duplicates: { origId: string; dupId: string; val: string }[] = [];

  evidence.forEach((ev) => {
    const key = `${ev.type}:${ev.value.toLowerCase().trim()}`;
    if (seenEvidence.has(key)) {
      duplicates.push({ origId: seenEvidence.get(key)!, dupId: ev.id, val: ev.value });
    } else {
      seenEvidence.set(key, ev.id);
    }
  });

  if (duplicates.length > 0) {
    issues.push({
      id: 'QA-DUP-01',
      category: 'Deduplication',
      severity: 'Notice',
      title: 'Duplicate Evidence Ingestion Detected',
      description: `Identical evidence values ingested multiple times: ${duplicates.map((d) => `"${d.val}" in [${d.origId}] and [${d.dupId}]`).join(', ')}.`,
      targetType: 'evidence',
      actionableRemediation: 'Deduplicate redundant evidence records or merge their provenance notes into a single canonical entry.',
    });
  } else {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 4: Unsupported Findings (Grounded Evidence Requirement)
  // =========================================================================
  const ungroundedFindings = findings.filter((f) => !f.evidenceIds || f.evidenceIds.length === 0);
  if (ungroundedFindings.length > 0) {
    issues.push({
      id: 'QA-UNGROUNDED-01',
      category: 'Evidence Support',
      severity: 'Critical',
      title: 'Findings Logged Without Grounded Evidence Pointers',
      description: `${ungroundedFindings.length} finding(s) do not cite any supporting evidence IDs: [${ungroundedFindings.map((f) => f.id).join(', ')}]. Unsubstantiated findings fail legal defensibility standards.`,
      targetType: 'finding',
      actionableRemediation: 'Link verified evidence items (e.g., DNS telemetry, file hash, packet frame) to each finding.',
    });
  } else {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 5: Conflicting Observations
  // =========================================================================
  const targetMap = new Map<string, Finding[]>();
  findings.forEach((f) => {
    const t = f.targetEntity.toLowerCase().trim();
    const list = targetMap.get(t) || [];
    list.push(f);
    targetMap.set(t, list);
  });

  let hasConflict = false;
  targetMap.forEach((fList, entity) => {
    const hasUnresolved = fList.some((f) => f.status === 'Unresolved');
    const hasFalsePositive = fList.some((f) => f.status === 'False Positive');
    if (hasUnresolved && hasFalsePositive) {
      hasConflict = true;
      issues.push({
        id: `QA-CONFLICT-${entity.slice(0, 8)}`,
        category: 'Consistency',
        severity: 'Warning',
        title: `Contradictory Finding Statuses for Entity "${entity}"`,
        description: `Entity "${entity}" is marked simultaneously as "Unresolved" in one finding and "False Positive" in another.`,
        targetType: 'finding',
        actionableRemediation: 'Reconcile investigation findings for this target to maintain a consistent disposition.',
      });
    }
  });

  if (!hasConflict) {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 6: Incomplete Acquisition (Zero-byte or Hashless Evidence)
  // =========================================================================
  const incompleteEvidence = evidence.filter((e) => {
    if (e.type === 'file' && (!e.value || e.value.length < 5)) return true;
    if (e.type === 'hash' && !/^[a-fA-F0-9]{32,64}$/.test(e.value)) return true;
    return false;
  });

  if (incompleteEvidence.length > 0) {
    issues.push({
      id: 'QA-ACQ-01',
      category: 'Acquisition Completeness',
      severity: 'Critical',
      title: 'Incomplete Acquisition Telemetry',
      description: `${incompleteEvidence.length} file or hash evidence records contain invalid or missing payloads: [${incompleteEvidence.map((e) => e.id).join(', ')}].`,
      targetType: 'evidence',
      actionableRemediation: 'Re-acquire digital artifact or recompute cryptographic hash before proceeding with forensic attribution.',
    });
  } else {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 7: Integrity & Tamper Check (Audit Log Chain Verification)
  // =========================================================================
  let tamperVerified = true;
  if (auditLog.length > 1) {
    for (let i = 1; i < auditLog.length; i++) {
      const prev = auditLog[i - 1];
      const curr = auditLog[i];
      if (curr.prevHash && prev.hash && curr.prevHash !== prev.hash) {
        tamperVerified = false;
        issues.push({
          id: 'QA-TAMPER-01',
          category: 'Integrity',
          severity: 'Critical',
          title: 'Audit Log Cryptographic Hash Chain Broken',
          description: `Audit log record #${curr.id} references prevHash "${curr.prevHash.slice(0, 12)}...", but preceding record #${prev.id} has hash "${prev.hash.slice(0, 12)}...". Potential unauthorized record alteration.`,
          targetType: 'audit',
          actionableRemediation: 'Investigate audit log storage backend for unauthorized record modifications.',
        });
        break;
      }
    }
  }

  if (tamperVerified) {
    passedChecks++;
  }

  // =========================================================================
  // CHECK 8: Weak Severity Rationale
  // =========================================================================
  const weakSeverityFindings = findings.filter(
    (f) => (f.severity === 'Critical' || f.severity === 'High') && (!f.severityRationale || f.severityRationale.trim().length < 15)
  );

  if (weakSeverityFindings.length > 0) {
    issues.push({
      id: 'QA-RAT-01',
      category: 'Severity Rationale',
      severity: 'Warning',
      title: 'Critical/High Severity Findings Missing Technical Rationale',
      description: `${weakSeverityFindings.length} finding(s) with High/Critical severity lack an explainable rationale: [${weakSeverityFindings.map((f) => f.id).join(', ')}].`,
      targetType: 'finding',
      actionableRemediation: 'Document the CVSS or business impact justification for High and Critical classifications to prevent subjective severity inflation.',
    });
  } else {
    passedChecks++;
  }

  // Calculate Health Score (0 - 100)
  const penalty = issues.reduce((acc, iss) => {
    if (iss.severity === 'Critical') return acc + 25;
    if (iss.severity === 'Warning') return acc + 10;
    return acc + 3;
  }, 0);

  const overallHealthScore = Math.max(0, 100 - penalty);
  const status = overallHealthScore >= 90 ? 'Clean' : overallHealthScore >= 70 ? 'Minor Issues' : 'Action Required';

  return {
    overallHealthScore,
    status,
    totalChecks,
    passedChecks,
    issues,
    tamperVerified,
    evaluatedAt: new Date().toISOString(),
  };
}
