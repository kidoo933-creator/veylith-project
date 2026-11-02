import {
  CaseRecord,
  InvestigationSimpleReport,
  SimpleFindingItem,
  PrioritizedNextStep,
} from '../types';

export const CASE_ANALYST_DISCLAIMER =
  'Executive Incident Briefing synthesized deterministically from verifiable case evidence, formal findings, and timeline records. No external assumptions or unverified indicators are added.';

/**
 * Deterministic cybersecurity analyst rules engine for Case Investigations.
 * Synthesizes an executive-level, human-readable incident briefing (Simple Results)
 * from the full case dossier.
 */
export function generateCaseSimpleReport(caseRecord: CaseRecord): InvestigationSimpleReport {
  const caseId = caseRecord.id;
  const title = caseRecord.title || 'Investigation Case';
  const findings: SimpleFindingItem[] = [];
  const whatWasDiscovered: string[] = [];
  const whatIsWorkingWell: string[] = [];
  const limitations: string[] = [];

  const evidenceCount = caseRecord.evidence?.length || 0;
  const findingRecords = caseRecord.findings || [];
  const unresolvedFindings = findingRecords.filter(
    (f) => f.status === 'Unresolved' || f.status === 'Investigating'
  );
  const mitigatedFindings = findingRecords.filter((f) => f.status === 'Mitigated');

  // 1. FACTUAL DISCOVERIES
  whatWasDiscovered.push(
    `Investigation "${title}" (${caseId}) currently tracks ${evidenceCount} verified evidence item(s) and ${findingRecords.length} formal forensic finding(s).`
  );
  whatWasDiscovered.push(
    `Assigned Lead Analyst: ${caseRecord.leadAnalyst || 'Lead Investigator'} • Priority: ${caseRecord.priority} • Status: ${caseRecord.status}.`
  );

  if (caseRecord.scope && caseRecord.scope.length > 0) {
    whatWasDiscovered.push(`Investigation Scope Boundaries: ${caseRecord.scope.join(', ')}.`);
  }

  // 2. POSITIVE DEFENSES / PROGRESS
  if (mitigatedFindings.length > 0) {
    whatIsWorkingWell.push(
      `${mitigatedFindings.length} finding(s) have been successfully mitigated or contained by the response team.`
    );
  }

  if (caseRecord.status === 'Closed' || caseRecord.status === 'Archived') {
    whatIsWorkingWell.push('Incident response cycle is complete and threat vectors have been neutralized.');
  } else if (unresolvedFindings.length === 0 && findingRecords.length > 0) {
    whatIsWorkingWell.push('All documented case findings have been investigated and resolved.');
  }

  // 3. SECURITY CONCERNS (Mapped from case findings with plain-language explanations)
  if (findingRecords.length > 0) {
    findingRecords.forEach((f) => {
      // Map severity
      let sev: SimpleFindingItem['severity'] = 'Medium';
      if (f.severity === 'Critical') sev = 'Critical';
      else if (f.severity === 'High') sev = 'High';
      else if (f.severity === 'Low') sev = 'Low';
      else if (f.severity === 'Info') sev = 'Informational';

      // Map confidence
      let conf: SimpleFindingItem['confidence'] = 'Confirmed';
      if (f.confidence === 'Observed' || f.confidence === 'Confirmed') conf = 'Confirmed';
      else if (f.confidence === 'Potential') conf = 'Potential';
      else if (f.confidence === 'Inferred') conf = 'Inferred';

      // Plain language translation
      const whatThisMeans =
        f.description ||
        `An observation of type "${f.category}" was registered against target entity "${f.targetEntity}".`;

      const potentialRisk =
        f.riskImplications ||
        `Unresolved findings in "${f.category}" could allow adversaries to persist or expand access within the environment.`;

      const possibleAttackScenario =
        f.observedResult
          ? `Observed evidence: "${f.observedResult}". If exploited, an attacker could leverage this behavior to impact "${f.targetEntity}".`
          : `An adversary observing "${f.targetEntity}" could exploit this condition during multi-stage campaign operations.`;

      const howToPreventIt =
        `Review telemetry for "${f.targetEntity}", enforce hardening recommendations for ${f.category}, and verify remediation with follow-up testing.`;

      findings.push({
        id: f.id,
        title: f.title,
        category: f.category,
        severity: sev,
        severityExplanation:
          f.severityRationale ||
          `Weighted as ${sev} based on affected entity "${f.targetEntity}" and potential operational risk.`,
        confidence: conf,
        whatObserved: f.observedResult || f.description,
        whatThisMeans,
        potentialRisk,
        possibleAttackScenario,
        howToPreventIt,
        technicalDetails: `Finding ID: ${f.id}\nTarget Entity: ${f.targetEntity}\nSource Tool: ${f.sourceTool}\nStatus: ${f.status}\nCollected At: ${f.collectedAt}\nRelated Evidence IDs: ${f.evidenceIds?.join(', ') || 'None'}`,
      });
    });
  } else {
    // Empty case baseline
    findings.push({
      id: 'fnd-case-empty',
      title: 'Investigation Intake Phase',
      category: 'Infrastructure & Recon',
      severity: 'Informational',
      severityExplanation: 'No formal security findings have been attached to this case yet.',
      confidence: 'Confirmed',
      whatObserved: 'Case initialized. Awaiting evidence ingestion from Domain Intel, File Forensics, or PCAP Lab.',
      whatThisMeans:
        'The investigation workspace has been established and is ready for analysts to log evidence and formal findings.',
      potentialRisk: 'No confirmed risks documented at this stage.',
      possibleAttackScenario: 'N/A — investigation is actively assembling initial forensic data.',
      howToPreventIt:
        'Use Domain Intelligence, File Forensics, or PCAP Lab to probe suspected infrastructure and attach findings.',
      technicalDetails: `Case ID: ${caseId} • Priority: ${caseRecord.priority}`,
    });
  }

  // 4. OVERALL ASSESSMENT
  let overallAssessment = '';
  const criticalCount = findingRecords.filter((f) => f.severity === 'Critical').length;
  const highCount = findingRecords.filter((f) => f.severity === 'High').length;

  if (criticalCount > 0 || highCount > 0) {
    overallAssessment =
      `INCIDENT ALERT — HIGH-PRIORITY ACTIONS REQUIRED: Case ${caseId} ("${title}") tracks ${criticalCount} Critical and ${highCount} High severity finding(s) ` +
      `across ${evidenceCount} evidence artifact(s). ${unresolvedFindings.length} finding(s) remain open and require immediate containment and analyst action. ` +
      `Review the prioritized response roadmap below to neutralize immediate threat vectors.`;
  } else if (findingRecords.length > 0) {
    overallAssessment =
      `STANDARD INVESTIGATION IN PROGRESS: Case ${caseId} ("${title}") is under active analysis with ${findingRecords.length} finding(s) ` +
      `and ${evidenceCount} evidence artifact(s). No uncontained Critical severity threats have been confirmed. ` +
      `Follow standard incident response protocols to verify and close remaining open items.`;
  } else {
    overallAssessment =
      `CASE INITIALIZED: Case ${caseId} ("${title}") is active and awaiting forensic data ingestion. ` +
      `No findings have been attached. Begin analysis by investigating domains, uploading suspicious files, or capturing PCAP telemetry.`;
  }

  // 5. PRIORITIZED NEXT STEPS
  const prioritizedNextSteps: PrioritizedNextStep[] = [];
  if (unresolvedFindings.some((f) => f.severity === 'Critical' || f.severity === 'High')) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Execute isolation and firewall blocking for all confirmed malicious indicators (IPs, domains, hashes)',
      rationale:
        'Halts adversary communication channels and isolates impacted assets from the enterprise network.',
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Correlate affected entities with historical SIEM/EDR logs to define incident blast radius',
      rationale:
        'Identifies whether other endpoints or user accounts were targeted by the same campaign.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Document formal post-incident report and update organizational detection rules (YARA/Sigma/Snort)',
      rationale:
        'Prevents re-compromise from identical adversary tactics and ensures institutional learning.',
    });
  } else {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Review collected evidence items and link correlated findings in the Evidence Graph',
      rationale: 'Establishes clear relational intelligence between domains, IPs, and files.',
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Verify finding statuses and transition mitigated findings to "Mitigated" in Workspace',
      rationale: 'Keeps case metrics and team handoff documentation accurate.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Generate full PDF / Markdown investigation report for stakeholder review',
      rationale: 'Provides an executive and technical record of all investigation activities.',
    });
  }

  // 6. LIMITATIONS
  limitations.push(
    'Case findings reflect only evidence and telemetry explicitly imported and verified in this workspace.'
  );
  limitations.push(
    'Unverified correlation links in the Evidence Graph represent inferred associations until validated by an analyst.'
  );

  return {
    target: `${caseId}: ${title}`,
    targetType: 'case',
    generatedAt: new Date().toISOString(),
    overallAssessment,
    whatWasDiscovered,
    whatIsWorkingWell,
    securityConcerns: findings,
    prioritizedNextSteps,
    limitations,
    disclaimer: CASE_ANALYST_DISCLAIMER,
    isAiGenerated: false,
    modelUsed: 'Veylith Deterministic DFIR Case Engine',
  };
}
