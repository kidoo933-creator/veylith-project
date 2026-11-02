import React, { useState } from 'react';
import { InvestigationSimpleReport, SimpleFindingItem, PrioritizedNextStep } from '../types';
import {
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  ListOrdered,
  Clock,
  Layers,
  HelpCircle,
  ExternalLink,
  Lock,
  RefreshCw,
  Terminal,
  Copy,
  Check,
  Code2,
  Server,
} from 'lucide-react';

interface SimpleResultsReportProps {
  report: InvestigationSimpleReport;
  onRefreshAi?: () => void;
  isRefreshing?: boolean;
  onNavigateToDeep?: () => void;
}

export const SimpleResultsReport: React.FC<SimpleResultsReportProps> = ({
  report,
  onRefreshAi,
  isRefreshing = false,
  onNavigateToDeep,
}) => {
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);
  const [selectedTech, setSelectedTech] = useState<Record<string, string>>({});

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippetId(id);
    setTimeout(() => setCopiedSnippetId(null), 2000);
  };

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getSeverityStyle = (severity: SimpleFindingItem['severity']) => {
    switch (severity) {
      case 'Critical':
        return {
          badge: 'bg-red-100 dark:bg-red-950/80 text-red-800 dark:text-red-200 border-red-300 dark:border-red-800',
          border: 'border-l-red-500',
          icon: <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />,
        };
      case 'High':
        return {
          badge: 'bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-200 border-amber-300 dark:border-amber-800',
          border: 'border-l-amber-500',
          icon: <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />,
        };
      case 'Medium':
        return {
          badge: 'bg-blue-100 dark:bg-blue-950/80 text-blue-800 dark:text-blue-200 border-blue-300 dark:border-blue-800',
          border: 'border-l-blue-500',
          icon: <Info className="w-4 h-4 text-blue-600 dark:text-blue-400" />,
        };
      case 'Low':
        return {
          badge: 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700',
          border: 'border-l-slate-400',
          icon: <Info className="w-4 h-4 text-slate-500" />,
        };
      case 'Informational':
      default:
        return {
          badge: 'bg-teal-100 dark:bg-teal-950/80 text-teal-800 dark:text-teal-200 border-teal-300 dark:border-teal-800',
          border: 'border-l-teal-400',
          icon: <CheckCircle2 className="w-4 h-4 text-teal-600 dark:text-teal-400" />,
        };
    }
  };

  const getConfidenceStyle = (confidence: SimpleFindingItem['confidence']) => {
    switch (confidence) {
      case 'Confirmed':
        return 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800';
      case 'Potential':
        return 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/60 border-amber-200 dark:border-amber-800';
      case 'Inferred':
        return 'text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/60 border-purple-200 dark:border-purple-800';
      default:
        return 'text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800';
    }
  };

  const getPriorityStyle = (priority: PrioritizedNextStep['priority']) => {
    switch (priority) {
      case 'Immediate':
        return {
          bg: 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-300',
          pill: 'bg-red-600 text-white',
        };
      case 'High Priority':
        return {
          bg: 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/60 text-amber-700 dark:text-amber-300',
          pill: 'bg-amber-600 text-white',
        };
      case 'Scheduled Hardening':
        return {
          bg: 'bg-teal-50 dark:bg-teal-950/40 border-teal-200 dark:border-teal-900/60 text-teal-700 dark:text-teal-300',
          pill: 'bg-teal-600 text-white',
        };
      case 'Verification':
      default:
        return {
          bg: 'bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-900/60 text-blue-700 dark:text-blue-300',
          pill: 'bg-blue-600 text-white',
        };
    }
  };

  return (
    <div className="space-y-6" data-testid="simple-results-report">
      {/* 1. Analyst Transparency Disclaimer Banner */}
      <div className="bg-gradient-to-r from-teal-500/10 via-slate-500/5 to-purple-500/10 dark:from-teal-950/30 dark:via-slate-900/50 dark:to-purple-950/30 border border-teal-200/80 dark:border-teal-900/50 rounded-2xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 rounded-xl bg-teal-100 dark:bg-teal-900/60 text-teal-700 dark:text-teal-300 flex items-center justify-center shrink-0 mt-0.5">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                Analyst-Grade Human Translation
              </span>
              <span className="text-[10px] text-teal-600 dark:text-teal-400 font-semibold bg-teal-50 dark:bg-teal-950 border border-teal-200 dark:border-teal-800 px-2 py-0.5 rounded-full">
                {report.isAiGenerated ? 'AI Assisted' : 'Deterministic Synthesis'}
              </span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-0.5 leading-relaxed">
              {report.disclaimer}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
          {onRefreshAi && (
            <button
              onClick={onRefreshAi}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs disabled:opacity-50"
              title="Regenerate analysis with active AI model"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-purple-500 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{isRefreshing ? 'Synthesizing...' : 'Re-Analyze'}</span>
            </button>
          )}

          {onNavigateToDeep && (
            <button
              onClick={onNavigateToDeep}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-xl transition"
            >
              <span>Inspect Raw Telemetry</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* 2. Executive Overall Assessment Card */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-6 shadow-xs">
        <div className="flex items-center gap-2.5 mb-3">
          <div className="w-7 h-7 rounded-lg bg-teal-100 dark:bg-teal-950 text-teal-700 dark:text-teal-300 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Overall Security Assessment
            </h3>
            <span className="text-[11px] text-slate-400">
              Target: <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{report.target}</span> • Generated {new Date(report.generatedAt).toLocaleString()}
            </span>
          </div>
        </div>

        <div className="prose prose-slate dark:prose-invert max-w-none">
          <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-200 font-normal">
            {report.overallAssessment}
          </p>
        </div>
      </div>

      {/* 3. Side-by-Side: What Was Discovered vs What Is Working Well */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* What Was Discovered (Facts) */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 flex items-center justify-center">
              <Layers className="w-3.5 h-3.5" />
            </div>
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              What Was Discovered
            </h4>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Factual observations extracted directly from scanner probes without extrapolation:
          </p>
          <ul className="space-y-2 pt-1">
            {report.whatWasDiscovered.map((item, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-950/50 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800/80"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                <span className="leading-relaxed">{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* What Is Working Well (Positive Highlights) */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 flex items-center justify-center">
              <ShieldCheck className="w-3.5 h-3.5" />
            </div>
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              What Is Working Well
            </h4>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Validated security controls and defensive posture verified intact:
          </p>
          <ul className="space-y-2 pt-1">
            {report.whatIsWorkingWell.map((item, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 bg-emerald-50/50 dark:bg-emerald-950/20 p-2.5 rounded-xl border border-emerald-100/80 dark:border-emerald-900/40"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 mt-0.5 shrink-0" />
                <span className="leading-relaxed">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* 4. Security Concerns (Plain-English Explanations with 4 Pillars) */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span>Identified Security Concerns ({report.securityConcerns.length})</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Each concern is translated into clear, everyday language with its real-world impact and actionable fix.
            </p>
          </div>
          <span className="text-[11px] text-slate-400 self-start sm:self-auto">
            Click any concern to inspect technical telemetry
          </span>
        </div>

        {report.securityConcerns.length === 0 ? (
          <div className="p-8 text-center bg-slate-50 dark:bg-slate-950 rounded-2xl border border-dashed border-slate-200 dark:border-slate-800">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              No High or Medium Severity Concerns Detected
            </p>
            <p className="text-[11px] text-slate-400 max-w-md mx-auto mt-1">
              All tested baseline hardening parameters passed validation or operate within standard defensive thresholds.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {report.securityConcerns.map((fnd) => {
              const sev = getSeverityStyle(fnd.severity);
              const conf = getConfidenceStyle(fnd.confidence);
              const isExpanded = !!expandedFindings[fnd.id];

              return (
                <div
                  key={fnd.id}
                  className={`border rounded-2xl border-l-4 ${sev.border} border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 shadow-2xs overflow-hidden transition-all`}
                >
                  {/* Finding Header */}
                  <div className="p-4 sm:p-5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
                      <div className="flex items-center gap-2.5">
                        {sev.icon}
                        <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                          {fnd.title}
                        </h4>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        {/* Severity Badge */}
                        <span
                          className={`text-[10px] font-bold uppercase px-2.5 py-0.5 rounded-full border ${sev.badge}`}
                        >
                          {fnd.severity} Severity
                        </span>

                        {/* Verification Status Badge (Phase 6 Confidence Architecture) */}
                        <span
                          className={`text-[10px] font-bold uppercase px-2.5 py-0.5 rounded-md border ${
                            fnd.verificationStatus === 'INFERRED'
                              ? 'bg-purple-50 text-purple-700 dark:bg-purple-950/70 dark:text-purple-300 border-purple-300 dark:border-purple-800'
                              : fnd.verificationStatus === 'UNKNOWN'
                              ? 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                              : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                          }`}
                          title={`Verification Status: ${fnd.verificationStatus || 'VERIFIED'}`}
                        >
                          {fnd.verificationStatus || 'VERIFIED'}
                        </span>

                        {/* Confidence Level Badge */}
                        <span
                          className={`text-[10px] font-medium px-2 py-0.5 rounded-full border ${conf}`}
                        >
                          {fnd.confidenceLevel ? `${fnd.confidenceLevel} Confidence` : `${fnd.confidence} Confidence`}
                        </span>

                        {/* Category */}
                        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-md">
                          {fnd.category}
                        </span>
                      </div>
                    </div>

                    {/* What Was Observed */}
                    <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 mb-4">
                      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                        Observed Fact:
                      </span>
                      <p className="text-xs text-slate-700 dark:text-slate-300 font-mono">
                        {fnd.whatObserved}
                      </p>
                    </div>

                    {/* The 4 Human-Centric Pillars Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      {/* Pillar 1: What this means */}
                      <div className="bg-blue-50/40 dark:bg-blue-950/20 p-3.5 rounded-xl border border-blue-100/60 dark:border-blue-900/40 space-y-1">
                        <span className="font-bold text-blue-900 dark:text-blue-200 flex items-center gap-1.5">
                          <Info className="w-3.5 h-3.5 text-blue-600" />
                          What this means in plain English:
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                          {fnd.whatThisMeans}
                        </p>
                      </div>

                      {/* Pillar 2: Potential security risk */}
                      <div className="bg-amber-50/40 dark:bg-amber-950/20 p-3.5 rounded-xl border border-amber-100/60 dark:border-amber-900/40 space-y-1">
                        <span className="font-bold text-amber-900 dark:text-amber-200 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                          Why it matters (Potential Risk):
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                          {fnd.potentialRisk}
                        </p>
                      </div>

                      {/* Pillar 3: Possible attack scenario */}
                      <div className="bg-purple-50/40 dark:bg-purple-950/20 p-3.5 rounded-xl border border-purple-100/60 dark:border-purple-900/40 space-y-1">
                        <span className="font-bold text-purple-900 dark:text-purple-200 flex items-center gap-1.5">
                          <HelpCircle className="w-3.5 h-3.5 text-purple-600" />
                          Possible Attack Scenario (Educational):
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                          {fnd.possibleAttackScenario}
                        </p>
                      </div>

                      {/* Pillar 4: How to prevent it */}
                      <div className="bg-emerald-50/40 dark:bg-emerald-950/20 p-3.5 rounded-xl border border-emerald-100/60 dark:border-emerald-900/40 space-y-1">
                        <span className="font-bold text-emerald-900 dark:text-emerald-200 flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                          How to Prevent or Fix It:
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                          {fnd.howToPreventIt}
                        </p>
                      </div>
                    </div>

                    {/* Severity Rationale Explainer */}
                    <div className="mt-3.5 pt-3 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-2">
                      <span className="font-bold text-slate-700 dark:text-slate-300">
                        Severity Assignment Rationale:
                      </span>
                      <span>{fnd.severityExplanation}</span>
                    </div>

                    {/* Developer Remediation & Verification Suite */}
                    {fnd.remediationGuide && (
                      <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <Code2 className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                            <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                              Concrete Developer Remediation & Verification
                            </span>
                          </div>
                          {fnd.remediationGuide.detectedTechnology && fnd.remediationGuide.detectedTechnology !== 'generic' && (
                            <span className="inline-flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                              <Server className="w-3 h-3 text-teal-500" />
                              Detected: {fnd.remediationGuide.detectedTechnology.toUpperCase()}
                            </span>
                          )}
                        </div>

                        {/* Location and Doc Link */}
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-950 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800">
                          <div>
                            <span className="font-semibold text-slate-700 dark:text-slate-300">Target Config File:</span>{' '}
                            <code className="font-mono text-teal-700 dark:text-teal-300 text-[10.5px]">
                              {fnd.remediationGuide.configLocation}
                            </code>
                          </div>
                          {fnd.remediationGuide.documentationUrl && (
                            <a
                              href={fnd.remediationGuide.documentationUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-teal-600 dark:text-teal-400 hover:underline font-semibold"
                            >
                              <span>Official MDN / RFC Docs</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>

                        {/* Config Snippet Box */}
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="font-semibold text-slate-700 dark:text-slate-300">
                              Server Hardening Directive:
                            </span>
                            <button
                              type="button"
                              onClick={() => copyText(fnd.remediationGuide!.configSnippet, `${fnd.id}-cfg`)}
                              className="inline-flex items-center gap-1 text-[10px] font-semibold text-teal-600 dark:text-teal-400 hover:text-teal-700 dark:hover:text-teal-300 px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                              title="Copy config snippet"
                            >
                              {copiedSnippetId === `${fnd.id}-cfg` ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-500" />
                                  <span className="text-emerald-600 dark:text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy Config</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 bg-slate-900 rounded-xl text-emerald-400 font-mono text-[11px] leading-relaxed overflow-x-auto border border-slate-800">
                            <code>{fnd.remediationGuide.configSnippet}</code>
                          </pre>
                        </div>

                        {/* Verification Curl Command */}
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1">
                              <Terminal className="w-3.5 h-3.5 text-blue-500" />
                              Live Verification Command:
                            </span>
                            <button
                              type="button"
                              onClick={() => copyText(fnd.remediationGuide!.verificationCommand, `${fnd.id}-cmd`)}
                              className="inline-flex items-center gap-1 text-[10px] font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                              title="Copy verification command"
                            >
                              {copiedSnippetId === `${fnd.id}-cmd` ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-500" />
                                  <span className="text-emerald-600 dark:text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy Command</span>
                                </>
                              )}
                            </button>
                          </div>
                          <div className="p-2.5 bg-slate-950 rounded-xl text-blue-300 font-mono text-[11px] border border-slate-800 flex items-center justify-between">
                            <code className="truncate">{fnd.remediationGuide.verificationCommand}</code>
                          </div>
                        </div>

                        {/* 3rd Party Hosted Note if applicable */}
                        {fnd.remediationGuide.thirdPartyHostedNote && (
                          <p className="text-[10.5px] text-slate-500 dark:text-slate-400 italic bg-slate-50 dark:bg-slate-950/40 p-2 rounded-lg border border-slate-100 dark:border-slate-800">
                            💡 <span className="font-semibold">Edge / CDN Guidance:</span> {fnd.remediationGuide.thirdPartyHostedNote}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Expandable Technical Deep Dive */}
                    {fnd.technicalDetails && (
                      <div className="mt-3">
                        <button
                          type="button"
                          onClick={() => toggleFinding(fnd.id)}
                          className="flex items-center gap-1.5 text-xs font-semibold text-teal-600 dark:text-teal-400 hover:text-teal-700 dark:hover:text-teal-300 transition"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                          <span>
                            {isExpanded ? 'Hide Technical Telemetry' : 'Inspect Technical Details'}
                          </span>
                        </button>

                        {isExpanded && (
                          <div className="mt-2 space-y-2">
                            <div className="p-3 bg-slate-900 rounded-xl text-slate-200 font-mono text-[11px] leading-relaxed border border-slate-800 whitespace-pre-wrap">
                              {fnd.technicalDetails}
                            </div>
                            {(fnd.detectionMethod || fnd.evidenceReference || fnd.potentialFalsePositiveExplanation || fnd.recommendedNextStep) && (
                              <div className="p-3 bg-slate-50 dark:bg-slate-950/80 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-2">
                                <div className="text-[10px] font-bold uppercase tracking-wider text-teal-600 dark:text-teal-400">
                                  Confidence Engine & Verification Architecture
                                </div>
                                {fnd.detectionMethod && (
                                  <div>
                                    <span className="font-semibold text-slate-700 dark:text-slate-300">Detection Method: </span>
                                    <span className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">{fnd.detectionMethod}</span>
                                  </div>
                                )}
                                {fnd.evidenceReference && (
                                  <div>
                                    <span className="font-semibold text-slate-700 dark:text-slate-300">Evidence Reference: </span>
                                    <span className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">{fnd.evidenceReference}</span>
                                  </div>
                                )}
                                {fnd.potentialFalsePositiveExplanation && (
                                  <div>
                                    <span className="font-semibold text-amber-700 dark:text-amber-400">Potential False-Positive Rationale: </span>
                                    <span className="text-slate-600 dark:text-slate-400">{fnd.potentialFalsePositiveExplanation}</span>
                                  </div>
                                )}
                                {fnd.recommendedNextStep && (
                                  <div>
                                    <span className="font-semibold text-teal-700 dark:text-teal-400">Recommended Next Step: </span>
                                    <span className="text-slate-600 dark:text-slate-400">{fnd.recommendedNextStep}</span>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 5. Recommended Next Steps (Prioritized by Importance) */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-6 shadow-xs space-y-4">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-teal-100 dark:bg-teal-950 text-teal-700 dark:text-teal-300 flex items-center justify-center">
            <ListOrdered className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Recommended Next Steps (Prioritized by Importance)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Structured action plan ordered from immediate containment to long-term defensive hygiene.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 pt-2">
          {report.prioritizedNextSteps.map((step, idx) => {
            const pStyle = getPriorityStyle(step.priority);

            return (
              <div
                key={idx}
                className={`p-4 rounded-xl border ${pStyle.bg} flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${pStyle.pill}`}
                    >
                      {step.priority}
                    </span>
                    <span className="text-xs font-bold text-slate-900 dark:text-white">
                      {step.action}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed pl-0.5">
                    {step.rationale}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 6. Investigation Limitations & What Was NOT Tested */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 flex items-center justify-center">
            <HelpCircle className="w-3.5 h-3.5" />
          </div>
          <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
            Investigation Limitations & Verification Boundaries
          </h4>
        </div>
        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          Forensic integrity requires disclosing what could not be tested or remains unverified:
        </p>
        <ul className="space-y-2 pt-1">
          {report.limitations.map((lim, idx) => (
            <li
              key={idx}
              className="flex items-start gap-2.5 text-xs text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-950/50 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800/80"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0" />
              <span className="leading-relaxed">{lim}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
