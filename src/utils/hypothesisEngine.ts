import { CaseRecord, HypothesisItem, HypothesisStatus, ConfidenceLevel } from '../types';

/**
 * Creates a structured investigative hypothesis.
 */
export function createHypothesisItem(
  caseId: string,
  data: {
    title: string;
    premise: string;
    confidence: 'High' | 'Medium' | 'Low';
    supportingEvidenceIds?: string[];
    contradictingEvidenceIds?: string[];
    alternativeExplanations?: string[];
    openQuestions?: string[];
    nextSteps?: string[];
    isAiSuggested?: boolean;
    author: string;
  }
): HypothesisItem {
  const now = new Date().toISOString();
  const id = `HYP-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;

  return {
    id,
    caseId,
    title: data.title.trim(),
    premise: data.premise.trim(),
    status: 'Active',
    confidence: data.confidence,
    supportingEvidenceIds: data.supportingEvidenceIds || [],
    contradictingEvidenceIds: data.contradictingEvidenceIds || [],
    alternativeExplanations: data.alternativeExplanations || [],
    openQuestions: data.openQuestions || [],
    nextSteps: data.nextSteps || [],
    isAiSuggested: !!data.isAiSuggested,
    author: data.author || 'Analyst',
    createdAt: now,
    updatedAt: now,
    revisions: [
      {
        timestamp: now,
        analyst: data.author || 'Analyst',
        action: 'Hypothesis Created',
        changeSummary: `Initialized hypothesis with status "Active" and confidence "${data.confidence}".`,
      },
    ],
  };
}

/**
 * Evaluates whether a hypothesis is evidence-supported, contradicted, or inconclusive.
 */
export function evaluateHypothesisEvidence(
  hypothesis: HypothesisItem,
  caseRecord: CaseRecord
): {
  supportedCount: number;
  contradictedCount: number;
  isConsistent: boolean;
  evaluationNote: string;
} {
  const caseEvidence = caseRecord.evidence || [];
  const validSupporting = hypothesis.supportingEvidenceIds.filter((id) => caseEvidence.some((e) => e.id === id));
  const validContradicting = hypothesis.contradictingEvidenceIds.filter((id) => caseEvidence.some((e) => e.id === id));

  let isConsistent = true;
  let evaluationNote = '';

  if (validContradicting.length > 0 && hypothesis.status === 'Supported') {
    isConsistent = false;
    evaluationNote = `Hypothesis marked as "Supported" despite ${validContradicting.length} documented contradicting evidence item(s).`;
  } else if (validSupporting.length === 0 && hypothesis.status === 'Supported') {
    isConsistent = false;
    evaluationNote = 'Hypothesis marked as "Supported" without any linked supporting evidence.';
  } else if (validSupporting.length > 0 && validContradicting.length === 0) {
    evaluationNote = `Supported by ${validSupporting.length} verified evidence artifact(s) with zero documented contradictions.`;
  } else {
    evaluationNote = `Inconclusive: ${validSupporting.length} supporting versus ${validContradicting.length} contradicting evidence items.`;
  }

  return {
    supportedCount: validSupporting.length,
    contradictedCount: validContradicting.length,
    isConsistent,
    evaluationNote,
  };
}
