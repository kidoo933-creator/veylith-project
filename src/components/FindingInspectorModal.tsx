import React, { useState } from 'react';
import { Finding, EvidenceItem, SeverityLevel, ConfidenceLevel } from '../types';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Compass,
  FileText,
  Layers,
  ExternalLink,
  Copy,
  Check,
  ChevronRight,
  Info,
  Server,
  Terminal,
  Activity,
  ArrowRight,
} from 'lucide-react';

interface FindingInspectorModalProps {
  finding: Finding;
  caseEvidence: EvidenceItem[];
  caseFindings: Finding[];
  onClose: () => void;
  onUpdateStatus?: (findingId: string, status: Finding['status']) => void;
  onNavigateToFinding?: (findingId: string) => void;
  onSelectEvidence?: (evidence: EvidenceItem) => void;
}

export const FindingInspectorModal: React.FC<FindingInspectorModalProps> = ({
  finding,
  caseEvidence,
  caseFindings,
  onClose,
  onUpdateStatus,
  onNavigateToFinding,
  onSelectEvidence,
}) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'observation' | 'evidence' | 'limitations' | 'related'>('observation');

  // Supporting evidence objects
  const citedEvidence = caseEvidence.filter((e) => finding.evidenceIds.includes(e.id));

  // Related findings
  const relatedFindings = caseFindings.filter(
    (f) =>
      f.id !== finding.id &&
      (finding.relatedFindingIds?.includes(f.id) ||
        f.evidenceIds.some((evId) => finding.evidenceIds.includes(evId)))
  );

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'Critical':
        return 'bg-red-100 text-red-800 dark:bg-red-950/80 dark:text-red-300 border-red-300 dark:border-red-800';
      case 'High':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-950/80 dark:text-orange-300 border-orange-300 dark:border-orange-800';
      case 'Medium':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 border-amber-300 dark:border-amber-800';
      case 'Low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/80 dark:text-blue-300 border-blue-300 dark:border-blue-800';
      case 'Info':
      default:
        return 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700';
    }
  };

  const getConfidenceBadge = (conf: ConfidenceLevel) => {
    switch (conf) {
      case 'Observed':
      case 'Confirmed':
        return 'bg-teal-50 text-teal-700 dark:bg-teal-950/70 dark:text-teal-300 border-teal-200 dark:border-teal-800';
      case 'Inferred':
        return 'bg-purple-50 text-purple-700 dark:bg-purple-950/70 dark:text-purple-300 border-purple-200 dark:border-purple-800';
      case 'Potential':
        return 'bg-amber-50 text-amber-700 dark:bg-amber-950/70 dark:text-amber-300 border-amber-200 dark:border-amber-800';
      default:
        return 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400 border-slate-300 dark:border-slate-700';
    }
  };

  const copyFindingJson = () => {
    navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const utcDateString = new Date(finding.collectedAt || finding.timestamp || Date.now()).toUTCString();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-900/60 backdrop-blur-xs">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-2xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-start justify-between gap-4 bg-slate-50/50 dark:bg-slate-800/30">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded-md bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200">
                {finding.id}
              </span>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-md bg-indigo-50 dark:bg-indigo-950/70 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                {finding.category || 'Forensic Finding'}
              </span>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(finding.severity)}`}>
                {finding.severity}
              </span>
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border ${getConfidenceBadge(finding.confidence)}`}>
                {finding.confidence}
              </span>
              {finding.verificationStatus && (
                <span
                  className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${
                    finding.verificationStatus === 'VERIFIED'
                      ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                      : finding.verificationStatus === 'INFERRED'
                      ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800'
                      : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                  }`}
                >
                  {finding.verificationStatus}
                </span>
              )}
            </div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white leading-snug">
              {finding.title}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              Target Entity: <span className="font-semibold text-slate-700 dark:text-slate-200">{finding.targetEntity}</span>
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={copyFindingJson}
              className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              title="Copy Finding JSON"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Subheader */}
        <div className="flex items-center gap-2 px-5 pt-3 border-b border-slate-100 dark:border-slate-800 text-xs font-medium bg-white dark:bg-slate-900">
          <button
            onClick={() => setActiveTab('observation')}
            className={`pb-2.5 px-1 border-b-2 transition ${
              activeTab === 'observation'
                ? 'border-teal-600 text-teal-600 dark:text-teal-400 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Observation & Analysis
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`pb-2.5 px-1 border-b-2 transition ${
              activeTab === 'evidence'
                ? 'border-teal-600 text-teal-600 dark:text-teal-400 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Supporting Evidence ({citedEvidence.length})
          </button>
          <button
            onClick={() => setActiveTab('limitations')}
            className={`pb-2.5 px-1 border-b-2 transition ${
              activeTab === 'limitations'
                ? 'border-teal-600 text-teal-600 dark:text-teal-400 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Limitations ({finding.limitations?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab('related')}
            className={`pb-2.5 px-1 border-b-2 transition ${
              activeTab === 'related'
                ? 'border-teal-600 text-teal-600 dark:text-teal-400 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Related Findings ({relatedFindings.length})
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs text-slate-700 dark:text-slate-300 flex-1">
          {activeTab === 'observation' && (
            <div className="space-y-4">
              {/* What Was Observed */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-2">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                  <Terminal className="w-3.5 h-3.5 text-teal-600" />
                  <span>What Was Observed</span>
                </div>
                <p className="font-mono text-xs text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-900 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 select-all">
                  {finding.observedResult || finding.description}
                </p>
                {finding.description && finding.description !== finding.observedResult && (
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed pt-1">
                    {finding.description}
                  </p>
                )}
              </div>

              {/* Provenance & Acquisition Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 block">Where It Came From</span>
                  <p className="font-semibold text-slate-900 dark:text-white text-xs">
                    {finding.sourceTool}
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Sensor: {finding.evidenceSource || finding.sourceTool}
                  </p>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">
                    Provenance: {finding.provenance || 'Acquired via standard passive inspection'}
                  </p>
                </div>

                <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 block">When Observed (UTC)</span>
                  <p className="font-mono font-semibold text-slate-900 dark:text-white text-xs flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-teal-600" />
                    <span>{utcDateString}</span>
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                    ISO: {finding.collectedAt || finding.timestamp}
                  </p>
                  <p className="text-[10px] text-teal-600 dark:text-teal-400 font-semibold mt-1">
                    Chain of Custody Timestamp Preserved
                  </p>
                </div>
              </div>

              {/* Why It Matters & Severity Rationale */}
              <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/50 dark:bg-amber-950/20 space-y-1.5 text-amber-900 dark:text-amber-200">
                <div className="flex items-center gap-1.5 font-bold text-xs">
                  <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                  <span>Why It Matters & Severity Rationale</span>
                </div>
                <p className="text-xs leading-relaxed">
                  {finding.severityRationale || 'Evaluated against defensible forensic criteria.'}
                </p>
              </div>

              {/* Risk Implications (Pragmatic & measured) */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold text-xs text-slate-900 dark:text-white">
                  <ShieldAlert className="w-4 h-4 text-purple-600" />
                  <span>Risk Implications</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  {finding.riskImplications ||
                    'Observed technical state should be correlated with complementary telemetry to establish definitive breach or unauthorized execution.'}
                </p>
              </div>

              {/* Confidence & Verification Architecture */}
              <div className="p-4 rounded-xl border border-teal-200 dark:border-teal-900/60 bg-teal-50/40 dark:bg-teal-950/20 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-bold text-xs text-teal-900 dark:text-teal-200">
                    <ShieldCheck className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                    <span>Evidence Verification & Confidence Engine</span>
                  </div>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-teal-100 dark:bg-teal-900/80 text-teal-800 dark:text-teal-300 font-bold">
                    {finding.verificationStatus || 'VERIFIED'}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1">
                  <div>
                    <span className="text-slate-500 dark:text-slate-400 font-semibold block">Detection Method:</span>
                    <span className="text-slate-800 dark:text-slate-200 font-medium">
                      {finding.detectionMethod || 'Direct Telemetry Capture'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400 font-semibold block">Evidence Reference:</span>
                    <span className="text-slate-800 dark:text-slate-200 font-mono font-medium">
                      {finding.evidenceReference || (finding.evidenceIds?.[0] ? `EVD-${finding.evidenceIds[0]}` : 'Direct Sensor Telemetry')}
                    </span>
                  </div>
                </div>

                {finding.falsePositiveExplanation && (
                  <div className="pt-1.5 border-t border-teal-200/60 dark:border-teal-800/60 text-[11px]">
                    <span className="font-semibold text-teal-950 dark:text-teal-300 block mb-0.5">Potential Non-Malicious Cause / False Positive:</span>
                    <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                      {finding.falsePositiveExplanation}
                    </p>
                  </div>
                )}

                {finding.recommendedNextStep && (
                  <div className="pt-1.5 border-t border-teal-200/60 dark:border-teal-800/60 text-[11px]">
                    <span className="font-semibold text-teal-950 dark:text-teal-300 block mb-0.5">Recommended Next Investigation Step:</span>
                    <p className="text-slate-700 dark:text-slate-300 font-medium leading-relaxed">
                      {finding.recommendedNextStep}
                    </p>
                  </div>
                )}
              </div>

              {/* Actionable Remediation (if available) */}
              {finding.remediationGuide && (
                <div className="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/40 dark:bg-blue-950/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-bold text-xs text-blue-900 dark:text-blue-200">
                      <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                      <span>Actionable Remediation Directives</span>
                    </div>
                    {finding.remediationGuide.detectedTechnology && (
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 uppercase font-bold">
                        {finding.remediationGuide.detectedTechnology}
                      </span>
                    )}
                  </div>
                  <pre className="font-mono text-[11px] p-2.5 rounded-lg bg-slate-900 text-slate-100 overflow-x-auto whitespace-pre-wrap select-all">
                    {finding.remediationGuide.configSnippet}
                  </pre>
                  {finding.remediationGuide.verificationCommand && (
                    <div className="pt-1 text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-semibold block mb-0.5">Verify with curl:</span>
                      <code className="font-mono text-[11px] px-2 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded block select-all">
                        {finding.remediationGuide.verificationCommand}
                      </code>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-500">
                The following verified evidence records directly substantiate this finding:
              </p>
              {citedEvidence.length === 0 ? (
                <div className="p-6 text-center text-slate-400 border border-dashed rounded-xl">
                  No explicit evidence IDs attached to this observation record.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {citedEvidence.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/40 space-y-1.5 hover:border-teal-500 transition cursor-pointer"
                      onClick={() => onSelectEvidence && onSelectEvidence(ev)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                            {ev.type}
                          </span>
                          <span className="font-semibold text-slate-900 dark:text-white text-xs">{ev.name}</span>
                        </div>
                        <span className="text-[10px] text-slate-400 font-mono">{ev.id}</span>
                      </div>
                      <p className="font-mono text-[11px] text-slate-600 dark:text-slate-300 truncate bg-white dark:bg-slate-900 p-1.5 rounded border border-slate-200 dark:border-slate-800">
                        {ev.value}
                      </p>
                      {ev.notes && <p className="text-[11px] text-slate-500 italic">{ev.notes}</p>}
                      <div className="flex items-center justify-between pt-1 text-[10px] text-slate-400">
                        <span>Source: {ev.source}</span>
                        <span>{new Date(ev.timestamp).toUTCString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'limitations' && (
            <div className="space-y-3">
              <div className="p-3.5 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60 rounded-xl flex items-start gap-2.5 text-blue-900 dark:text-blue-300">
                <Info className="w-4 h-4 shrink-0 mt-0.5 text-blue-600" />
                <p className="text-xs leading-relaxed">
                  Defensible DFIR requires explicit declaration of what was NOT observed or tested, preventing false assumptions of security or unwarranted conclusions.
                </p>
              </div>

              {(!finding.limitations || finding.limitations.length === 0) ? (
                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-500 text-xs">
                  • Inspection conducted strictly via passive, non-disruptive queries without dynamic code execution.
                </div>
              ) : (
                <ul className="space-y-2">
                  {finding.limitations.map((limit, idx) => (
                    <li
                      key={idx}
                      className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 text-xs flex items-start gap-2"
                    >
                      <span className="text-teal-600 font-bold shrink-0">•</span>
                      <span className="text-slate-700 dark:text-slate-300 leading-relaxed">{limit}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {activeTab === 'related' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-500">
                Other findings in case {finding.caseId || 'investigation'} sharing correlated evidence or targets:
              </p>
              {relatedFindings.length === 0 ? (
                <div className="p-6 text-center text-slate-400 border border-dashed rounded-xl">
                  No other findings directly share evidence artifacts with this finding.
                </div>
              ) : (
                <div className="space-y-2">
                  {relatedFindings.map((rf) => (
                    <div
                      key={rf.id}
                      onClick={() => onNavigateToFinding && onNavigateToFinding(rf.id)}
                      className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 flex items-center justify-between gap-3 hover:border-teal-500 hover:bg-slate-100/60 dark:hover:bg-slate-800 transition cursor-pointer"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${getSeverityBadge(rf.severity)}`}>
                            {rf.severity}
                          </span>
                          <span className="font-semibold text-slate-900 dark:text-white text-xs">{rf.title}</span>
                        </div>
                        <p className="text-[11px] text-slate-500 line-clamp-1">{rf.observedResult || rf.description}</p>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer with Status Management */}
        <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Investigation Status:</span>
            <select
              value={finding.status}
              onChange={(e) => onUpdateStatus && onUpdateStatus(finding.id, e.target.value as any)}
              className="px-2.5 py-1 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 font-semibold outline-none text-xs"
            >
              <option value="Unresolved">Unresolved</option>
              <option value="Investigating">Investigating</option>
              <option value="Mitigated">Mitigated</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-xl text-xs font-semibold transition"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
