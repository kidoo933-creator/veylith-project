import React, { useState } from 'react';
import {
  DomainAnalysisReport,
  DomainAiSecurityAnalysis,
  DomainSecurityFindingAnalysis,
} from '../types';
import { generateDeterministicDomainAnalysis, AI_ANALYST_DISCLAIMER } from '../utils/domainAiAnalyst';
import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Lock,
  Globe,
  Radio,
  FileCode,
  HelpCircle,
  Wrench,
  Search,
  ListOrdered,
  Terminal,
  Copy,
  Check,
  Code2,
  Server,
  ExternalLink,
} from 'lucide-react';

interface DomainAiAnalysisSectionProps {
  report: DomainAnalysisReport;
  onRefreshAi?: () => void;
  isRefreshing?: boolean;
}

export const DomainAiAnalysisSection: React.FC<DomainAiAnalysisSectionProps> = ({
  report,
  onRefreshAi,
  isRefreshing = false,
}) => {
  // Use server-provided AI analysis or fallback dynamically to client-side deterministic engine
  const analysis: DomainAiSecurityAnalysis =
    report.aiSecurityAnalysis || generateDeterministicDomainAnalysis(report);

  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({});
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippetId(id);
    setTimeout(() => setCopiedSnippetId(null), 2000);
  };

  const toggleTechnicalDetails = (id: string) => {
    setExpandedDetails((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredFindings = analysis.findings.filter((f) => {
    if (selectedSeverity !== 'all' && f.severity.toLowerCase() !== selectedSeverity.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.whatThisMeans.toLowerCase().includes(q) ||
        f.potentialRisk.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadgeClass = (severity: DomainSecurityFindingAnalysis['severity']) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-50 text-red-700 dark:bg-red-950/70 dark:text-red-300 border-red-200 dark:border-red-800';
      case 'High':
        return 'bg-orange-50 text-orange-700 dark:bg-orange-950/70 dark:text-orange-300 border-orange-200 dark:border-orange-800';
      case 'Medium':
        return 'bg-amber-50 text-amber-700 dark:bg-amber-950/70 dark:text-amber-300 border-amber-200 dark:border-amber-800';
      case 'Low':
        return 'bg-blue-50 text-blue-700 dark:bg-blue-950/70 dark:text-blue-300 border-blue-200 dark:border-blue-800';
      case 'Informational':
      default:
        return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700';
    }
  };

  const getConfidenceBadgeClass = (confidence: DomainSecurityFindingAnalysis['confidence']) => {
    switch (confidence) {
      case 'Confirmed':
        return 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800';
      case 'Potential':
        return 'bg-purple-50 text-purple-700 dark:bg-purple-950/70 dark:text-purple-300 border-purple-200 dark:border-purple-800';
      case 'Inferred':
        return 'bg-cyan-50 text-cyan-700 dark:bg-cyan-950/70 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800';
      case 'Unknown':
      default:
        return 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400 border-zinc-200 dark:border-zinc-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Mandatory Plain-English Disclaimer */}
      <div className="p-3.5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/80 rounded-2xl flex items-start gap-3 text-xs text-amber-900 dark:text-amber-200 shadow-xs">
        <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <p className="font-bold tracking-tight">Security Assessment Disclaimer</p>
          <p className="text-[11px] text-amber-800 dark:text-amber-300 leading-relaxed">
            {analysis.disclaimer || AI_ANALYST_DISCLAIMER}
          </p>
        </div>
      </div>

      {/* 2. Executive Overall Assessment Card */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-purple-50 dark:bg-purple-950/60 border border-purple-200 dark:border-purple-800 flex items-center justify-center text-purple-600 dark:text-purple-400 shadow-xs">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm md:text-base font-bold text-slate-900 dark:text-white">
                  AI Security Analyst Overall Assessment
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded-md font-mono bg-purple-50 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 font-medium">
                  {analysis.modelUsed}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Synthesized directly from verified scanner observations for <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">{report.domain}</span>
              </p>
            </div>
          </div>

          {onRefreshAi && (
            <button
              onClick={onRefreshAi}
              disabled={isRefreshing}
              className="px-3 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-xl border border-slate-200 dark:border-slate-700 transition flex items-center gap-1.5 shrink-0 self-start sm:self-auto disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-purple-600 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{isRefreshing ? 'Re-analyzing...' : 'Refresh AI Analysis'}</span>
            </button>
          )}
        </div>

        {/* Assessment Narrative */}
        <div className="p-4 bg-purple-50/40 dark:bg-purple-950/20 border border-purple-100 dark:border-purple-900/40 rounded-xl text-xs md:text-sm text-slate-800 dark:text-slate-200 leading-relaxed font-sans">
          {analysis.overallAssessment}
        </div>

        {/* Metric Badges Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Facts Observed</span>
            <span className="text-base font-bold font-mono text-slate-800 dark:text-slate-100">
              {analysis.keyFactsObserved.length}
            </span>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Positive Controls</span>
            <span className="text-base font-bold font-mono text-emerald-600 dark:text-emerald-400">
              {analysis.positiveHighlights.length}
            </span>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Hardening Findings</span>
            <span className="text-base font-bold font-mono text-blue-600 dark:text-blue-400">
              {analysis.findings.length}
            </span>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Scan Limitations</span>
            <span className="text-base font-bold font-mono text-slate-600 dark:text-slate-300">
              {analysis.limitations.length}
            </span>
          </div>
        </div>
      </div>

      {/* 3. Facts Observed & Positive Controls Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* What We Observed */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 text-slate-900 dark:text-white font-bold text-xs md:text-sm">
            <Radio className="w-4 h-4 text-teal-600" />
            <h4>What We Observed (Scanner Facts)</h4>
          </div>
          <p className="text-[11px] text-slate-400">
            Unmodified factual telemetry collected during passive socket, DNS, TLS, and HTTP inspection:
          </p>
          <ul className="space-y-2 text-xs">
            {analysis.keyFactsObserved.map((fact, i) => (
              <li
                key={i}
                className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200/50 dark:border-slate-700/50 flex items-start gap-2.5 text-slate-700 dark:text-slate-300"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-teal-500 mt-1.5 shrink-0" />
                <span className="leading-relaxed">{fact}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Positive Security Controls */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 text-slate-900 dark:text-white font-bold text-xs md:text-sm">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <h4>Active Positive Defenses</h4>
          </div>
          <p className="text-[11px] text-slate-400">
            Verified defensive controls confirmed to be active and operational:
          </p>
          {analysis.positiveHighlights.length > 0 ? (
            <ul className="space-y-2 text-xs">
              {analysis.positiveHighlights.map((highlight, i) => (
                <li
                  key={i}
                  className="p-2.5 rounded-xl bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200/60 dark:border-emerald-900/40 flex items-start gap-2.5 text-emerald-900 dark:text-emerald-200"
                >
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{highlight}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-400 p-4 text-center">
              No specific positive security configurations were confirmed in this passive scan.
            </p>
          )}
        </div>
      </div>

      {/* 4. Filterable Security Findings Section */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm md:text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-600" />
              <span>Detailed Security Findings & Explanations ({filteredFindings.length})</span>
            </h3>
            <p className="text-xs text-slate-400">
              Clear, simple-language breakdowns explaining what each observation means, potential risks, and concrete mitigations.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter findings..."
                className="pl-8 pr-3 py-1.5 text-xs bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-teal-500/20"
              />
            </div>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 outline-none font-medium"
            >
              <option value="all">Severity: All</option>
              <option value="Low">Low</option>
              <option value="Informational">Informational</option>
              <option value="Medium">Medium</option>
            </select>
          </div>
        </div>

        {/* Findings Cards List */}
        <div className="space-y-4">
          {filteredFindings.map((finding) => {
            const isExpanded = Boolean(expandedDetails[finding.id]);

            return (
              <div
                key={finding.id}
                className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4 transition hover:border-slate-300 dark:hover:border-slate-700"
              >
                {/* Finding Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {finding.id}
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                        {finding.category}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${getSeverityBadgeClass(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                          finding.verificationStatus === 'INFERRED'
                            ? 'bg-purple-50 text-purple-700 dark:bg-purple-950/70 dark:text-purple-300 border-purple-300 dark:border-purple-800'
                            : finding.verificationStatus === 'UNKNOWN'
                            ? 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                            : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                        }`}
                        title={`Verification Status: ${finding.verificationStatus || 'VERIFIED'}`}
                      >
                        {finding.verificationStatus || 'VERIFIED'}
                      </span>
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${getConfidenceBadgeClass(
                          finding.confidence
                        )}`}
                      >
                        {finding.confidenceLevel ? `${finding.confidenceLevel} Confidence` : finding.confidence}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-900 dark:text-white pt-1">
                      {finding.title}
                    </h4>
                  </div>
                </div>

                {/* Severity Justification Note */}
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-700/60 flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300">
                  <Info className="w-3.5 h-3.5 text-blue-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">Severity Rationale: </span>
                    <span>{finding.severityExplanation}</span>
                  </div>
                </div>

                {/* 4 Core Plain-English Pillars */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  {/* Pillar 1: What this means */}
                  <div className="p-3.5 bg-blue-50/30 dark:bg-blue-950/10 border border-blue-100 dark:border-blue-900/30 rounded-xl space-y-1">
                    <div className="flex items-center gap-1.5 font-bold text-blue-900 dark:text-blue-300 text-[11px] uppercase tracking-wide">
                      <HelpCircle className="w-3.5 h-3.5 text-blue-600" />
                      <span>What this means</span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                      {finding.whatThisMeans}
                    </p>
                  </div>

                  {/* Pillar 2: Potential risk */}
                  <div className="p-3.5 bg-amber-50/30 dark:bg-amber-950/10 border border-amber-100 dark:border-amber-900/30 rounded-xl space-y-1">
                    <div className="flex items-center gap-1.5 font-bold text-amber-900 dark:text-amber-300 text-[11px] uppercase tracking-wide">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-600" />
                      <span>Potential Security Risk</span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                      {finding.potentialRisk}
                    </p>
                  </div>

                  {/* Pillar 3: Possible attack scenario */}
                  <div className="p-3.5 bg-purple-50/30 dark:bg-purple-950/10 border border-purple-100 dark:border-purple-900/30 rounded-xl space-y-1">
                    <div className="flex items-center gap-1.5 font-bold text-purple-900 dark:text-purple-300 text-[11px] uppercase tracking-wide">
                      <Globe className="w-3.5 h-3.5 text-purple-600" />
                      <span>Possible Attack Scenario</span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                      {finding.possibleAttackScenario}
                    </p>
                  </div>

                  {/* Pillar 4: How to prevent it */}
                  <div className="p-3.5 bg-emerald-50/30 dark:bg-emerald-950/10 border border-emerald-100 dark:border-emerald-900/30 rounded-xl space-y-1">
                    <div className="flex items-center gap-1.5 font-bold text-emerald-900 dark:text-emerald-300 text-[11px] uppercase tracking-wide">
                      <Wrench className="w-3.5 h-3.5 text-emerald-600" />
                      <span>How to Prevent It</span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                      {finding.howToPreventIt}
                    </p>
                  </div>
                </div>

                {/* Developer Remediation & Verification Suite */}
                {finding.remediationGuide && (
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Code2 className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                        <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                          Actionable Configuration & Verification
                        </span>
                      </div>
                      {finding.remediationGuide.detectedTechnology && finding.remediationGuide.detectedTechnology !== 'generic' && (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                          <Server className="w-3 h-3 text-teal-500" />
                          Target: {finding.remediationGuide.detectedTechnology.toUpperCase()}
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-950 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800">
                      <div>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">Config Path:</span>{' '}
                        <code className="font-mono text-teal-700 dark:text-teal-300 text-[10.5px]">
                          {finding.remediationGuide.configLocation}
                        </code>
                      </div>
                      {finding.remediationGuide.documentationUrl && (
                        <a
                          href={finding.remediationGuide.documentationUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-teal-600 dark:text-teal-400 hover:underline font-semibold"
                        >
                          <span>Documentation</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          Server Directive:
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText(finding.remediationGuide!.configSnippet, `${finding.id}-cfg`)}
                          className="inline-flex items-center gap-1 text-[10px] font-semibold text-teal-600 dark:text-teal-400 hover:text-teal-700 dark:hover:text-teal-300 px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                          title="Copy snippet"
                        >
                          {copiedSnippetId === `${finding.id}-cfg` ? (
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
                        <code>{finding.remediationGuide.configSnippet}</code>
                      </pre>
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1">
                          <Terminal className="w-3.5 h-3.5 text-blue-500" />
                          Curl Verification Command:
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText(finding.remediationGuide!.verificationCommand, `${finding.id}-cmd`)}
                          className="inline-flex items-center gap-1 text-[10px] font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                          title="Copy verification command"
                        >
                          {copiedSnippetId === `${finding.id}-cmd` ? (
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
                      <div className="p-2.5 bg-slate-950 rounded-xl text-blue-300 font-mono text-[11px] border border-slate-800">
                        <code>{finding.remediationGuide.verificationCommand}</code>
                      </div>
                    </div>

                    {finding.remediationGuide.thirdPartyHostedNote && (
                      <p className="text-[10.5px] text-slate-500 dark:text-slate-400 italic bg-slate-50 dark:bg-slate-950/40 p-2 rounded-lg border border-slate-100 dark:border-slate-800">
                        💡 <span className="font-semibold">CDN / Edge Guidance:</span> {finding.remediationGuide.thirdPartyHostedNote}
                      </p>
                    )}
                  </div>
                )}

                {/* Expandable Technical Details for Professional Analysts */}
                {finding.technicalDetails && (
                  <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
                    <button
                      onClick={() => toggleTechnicalDetails(finding.id)}
                      className="text-xs font-semibold text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 flex items-center gap-1 transition"
                    >
                      <FileCode className="w-3.5 h-3.5 text-teal-600" />
                      <span>
                        {isExpanded ? 'Hide' : 'Expand'} Technical Evidence Details for Analysts
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-3.5 h-3.5 ml-0.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 ml-0.5" />
                      )}
                    </button>

                    {isExpanded && (
                      <div className="mt-2.5 space-y-2">
                        <div className="p-3 bg-slate-50 dark:bg-slate-800/80 rounded-xl border border-slate-200 dark:border-slate-700 font-mono text-[11px] text-slate-800 dark:text-slate-200 select-all leading-relaxed">
                          <div className="text-[10px] uppercase font-bold text-slate-400 mb-1 font-sans">
                            Ground-Truth Evidence
                          </div>
                          {finding.technicalDetails}
                        </div>
                        {(finding.detectionMethod || finding.evidenceReference || finding.potentialFalsePositiveExplanation || finding.recommendedNextStep) && (
                          <div className="p-3 bg-slate-50 dark:bg-slate-950/80 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-2">
                            <div className="text-[10px] font-bold uppercase tracking-wider text-teal-600 dark:text-teal-400">
                              Confidence Engine & Verification Architecture
                            </div>
                            {finding.detectionMethod && (
                              <div>
                                <span className="font-semibold text-slate-700 dark:text-slate-300">Detection Method: </span>
                                <span className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">{finding.detectionMethod}</span>
                              </div>
                            )}
                            {finding.evidenceReference && (
                              <div>
                                <span className="font-semibold text-slate-700 dark:text-slate-300">Evidence Reference: </span>
                                <span className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">{finding.evidenceReference}</span>
                              </div>
                            )}
                            {finding.potentialFalsePositiveExplanation && (
                              <div>
                                <span className="font-semibold text-amber-700 dark:text-amber-400">Potential False-Positive Rationale: </span>
                                <span className="text-slate-600 dark:text-slate-400">{finding.potentialFalsePositiveExplanation}</span>
                              </div>
                            )}
                            {finding.recommendedNextStep && (
                              <div>
                                <span className="font-semibold text-teal-700 dark:text-teal-400">Recommended Next Step: </span>
                                <span className="text-slate-600 dark:text-slate-400">{finding.recommendedNextStep}</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {filteredFindings.length === 0 && (
            <div className="p-8 text-center bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 text-slate-400 text-xs">
              No findings match your search or severity filter.
            </div>
          )}
        </div>
      </div>

      {/* 5. Recommended Next Steps (Prioritized by Importance) */}
      {analysis.prioritizedNextSteps && analysis.prioritizedNextSteps.length > 0 && (
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
                Structured mitigation plan ordered from immediate hardening to long-term hygiene.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 pt-2">
            {analysis.prioritizedNextSteps.map((step, idx) => {
              const isImm = step.priority === 'Immediate';
              const isHigh = step.priority === 'High Priority';
              const isSched = step.priority === 'Scheduled Hardening';
              const bg = isImm
                ? 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-300'
                : isHigh
                ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/60 text-amber-700 dark:text-amber-300'
                : isSched
                ? 'bg-teal-50 dark:bg-teal-950/40 border-teal-200 dark:border-teal-900/60 text-teal-700 dark:text-teal-300'
                : 'bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-900/60 text-blue-700 dark:text-blue-300';

              const pill = isImm
                ? 'bg-red-600 text-white'
                : isHigh
                ? 'bg-amber-600 text-white'
                : isSched
                ? 'bg-teal-600 text-white'
                : 'bg-blue-600 text-white';

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border ${bg} flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${pill}`}>
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
      )}

      {/* 6. What Was Not Tested (Limitations & Safety Boundary) */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2 text-slate-900 dark:text-white font-bold text-xs md:text-sm">
          <HelpCircle className="w-4 h-4 text-slate-500" />
          <h4>Scan Limitations & What Was Not Tested</h4>
        </div>
        <p className="text-[11px] text-slate-400">
          Responsible forensic disclosure: Understanding what passive inspection cannot verify is crucial for sound security decisions.
        </p>

        <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400">
          {analysis.limitations.map((lim, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span className="text-slate-400 font-bold">•</span>
              <span>{lim}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
