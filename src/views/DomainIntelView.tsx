import React, { useState } from 'react';
import { DomainAnalysisReport, FieldProvenance, ProvenanceStatus, ConfidenceLevel, Finding, InvestigationViewMode } from '../types';
import { createDomainFinding } from '../utils/findingNormalization';
import { DomainAiAnalysisSection } from '../components/DomainAiAnalysisSection';
import { InvestigationViewToggle } from '../components/InvestigationViewToggle';
import { generateDeterministicDomainAnalysis } from '../utils/domainAiAnalyst';
import { GeminiForensicsChat } from '../components/GeminiForensicsChat';
import {
  Globe,
  Search,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Server,
  AlertTriangle,
  CheckCircle,
  FileText,
  ExternalLink,
  Plus,
  Radio,
  Clock,
  ArrowRight,
  Info,
  Layers,
  ChevronRight,
  Database,
  Check,
  Flag,
  Sparkles,
} from 'lucide-react';

interface DomainIntelViewProps {
  onAttachEvidence: (
    name: string,
    type: 'domain' | 'ip' | 'header' | 'finding',
    value: string,
    notes: string,
    extra?: {
      source?: string;
      confidence?: ConfidenceLevel;
      metadata?: Record<string, any>;
    }
  ) => void;
  onLogFinding?: (caseId: string, findingData: Partial<Finding>) => void;
  activeCaseId: string;
}

export const DomainIntelView: React.FC<DomainIntelViewProps> = ({ onAttachEvidence, onLogFinding, activeCaseId }) => {
  const [targetInput, setTargetInput] = useState('example.com');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<DomainAnalysisReport | null>(null);
  const [viewMode, setViewMode] = useState<InvestigationViewMode>('simple');
  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'tls' | 'headers' | 'rdap' | 'scoring'>('overview');
  const [ssrfError, setSsrfError] = useState<string | null>(null);
  const [attachFeedback, setAttachFeedback] = useState<string | null>(null);
  const [isRefreshingAi, setIsRefreshingAi] = useState(false);

  const executeProbe = async (domainToProbe: string) => {
    const clean = domainToProbe.trim();
    if (!clean) return;
    setLoading(true);
    setSsrfError(null);
    setAttachFeedback(null);

    try {
      const res = await fetch('/api/domain/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: clean }),
      });

      const data = await res.json();
      if (!res.ok) {
        if (data.securityBlocked) {
          setSsrfError(`SSRF Security Guard Block: ${data.error}`);
        } else {
          setSsrfError(data.error || 'Domain investigation query failed');
        }
        setReport(null);
      } else {
        // Ensure aiSecurityAnalysis is present, generating deterministic analysis if needed
        if (!data.aiSecurityAnalysis) {
          data.aiSecurityAnalysis = generateDeterministicDomainAnalysis(data);
        }
        setReport(data);
        setViewMode('simple');
      }
    } catch (err: any) {
      setSsrfError(`Network error executing investigation: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRefreshAiAnalysis = async () => {
    if (!report) return;
    setIsRefreshingAi(true);
    try {
      const res = await fetch('/api/domain/ai-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.analysis) {
          setReport({
            ...report,
            aiSecurityAnalysis: data.analysis,
          });
        }
      }
    } catch (err) {
      console.warn('Failed to refresh AI analysis:', err);
    } finally {
      setIsRefreshingAi(false);
    }
  };

  const runInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    executeProbe(targetInput);
  };

  const handleAttachReportToCase = () => {
    if (!report) return;

    const notes = `Recon on ${report.domain} completed with risk score ${report.riskScore}/100 (${report.riskLevel}). Completeness: ${report.dataCompleteness}%. Observed factors: ${report.riskFactors.join('; ') || 'None'}.`;

    onAttachEvidence(
      report.domain,
      'domain',
      report.domain,
      notes,
      {
        source: `Veylith Recon Engine v${report.engineVersion}`,
        confidence: 'Observed',
        metadata: {
          target: report.targetNormalized,
          timestamp: report.analysisTimestamp,
          engineVersion: report.engineVersion,
          riskScore: report.riskScore,
          riskLevel: report.riskLevel,
          riskFactors: report.riskFactors,
          dataCompleteness: report.dataCompleteness,
          scoringLimitations: report.scoringLimitations,
          provenance: report.provenance,
        },
      }
    );

    setAttachFeedback(`Attached ${report.domain} evidence to Case ${activeCaseId}`);
    setTimeout(() => setAttachFeedback(null), 4000);
  };

  const handleLogFormalFinding = () => {
    if (!report || !onLogFinding) return;

    const finding = createDomainFinding({
      caseId: activeCaseId,
      domain: report.domain,
      title: `Domain Intelligence: ${report.domain} (${report.riskLevel} Risk)`,
      category: report.riskLevel === 'Low' ? 'Hardening & Security Header' : 'Infrastructure & Recon',
      observedResult: `Risk Score: ${report.riskScore}/100 (${report.riskLevel}). Completeness: ${report.dataCompleteness}%. Factors: ${report.riskFactors.join(', ') || 'Baseline verified'}.`,
      description: `Passive infrastructure reconnaissance on domain ${report.domain}. Resolved IPs: ${report.resolvedIps.map((i) => i.ip).join(', ') || 'None'}. TLS Valid: ${report.tlsCertificate?.valid ? 'Yes' : 'No'}.`,
      severity: report.riskLevel === 'Critical' ? 'Critical' : report.riskLevel === 'High' ? 'High' : report.riskLevel === 'Medium' ? 'Medium' : 'Low',
      severityRationale: `Assigned based on weighted observation factors: ${report.riskFactors.join('; ') || 'Standard baseline hardening observation'}.`,
      confidence: 'Observed',
      sourceTool: `Veylith Recon Engine v${report.engineVersion}`,
      evidenceIds: [],
      limitations: report.scoringLimitations,
      riskImplications: report.riskLevel === 'Low'
        ? 'Hardening observations do not indicate active exploitation or compromised server integrity.'
        : 'Elevated infrastructure anomaly requiring DNS and certificate validation.',
    });

    onLogFinding(activeCaseId, finding);
    setAttachFeedback(`Logged formal finding [${finding.id}] to Case ${activeCaseId}`);
    setTimeout(() => setAttachFeedback(null), 4000);
  };

  const renderProvenanceBadge = (prov?: FieldProvenance) => {
    if (!prov) return null;
    const statusMap: Record<ProvenanceStatus, { label: string; badge: string }> = {
      Retrieved: { label: 'Retrieved', badge: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800' },
      Cached: { label: 'Cached', badge: 'bg-blue-50 text-blue-700 dark:bg-blue-950/70 dark:text-blue-300 border-blue-200 dark:border-blue-800' },
      Unavailable: { label: 'Unavailable', badge: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400 border-slate-300 dark:border-slate-700' },
      Blocked: { label: 'Blocked by Policy', badge: 'bg-red-50 text-red-700 dark:bg-red-950/70 dark:text-red-300 border-red-200 dark:border-red-800' },
      TimedOut: { label: 'Timed Out', badge: 'bg-amber-50 text-amber-700 dark:bg-amber-950/70 dark:text-amber-300 border-amber-200 dark:border-amber-800' },
      NotChecked: { label: 'Not Checked', badge: 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400 border-zinc-200 dark:border-zinc-700' },
    };

    const conf = statusMap[prov.status] || statusMap.Unavailable;
    return (
      <span
        title={`Source: ${prov.source} • Time: ${new Date(prov.timestamp).toLocaleTimeString()} UTC • ${prov.details || ''}`}
        className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-medium border rounded-md ${conf.badge}`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
        {conf.label}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Title & Probe Search */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-teal-600" />
              Domain Intelligence & Infrastructure Recon
            </h1>
            <p className="text-xs text-slate-400">
              Deterministic, evidence-provenanced infrastructure analysis with strict SSRF defense boundaries.
            </p>
          </div>
          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1.5 bg-slate-50 dark:bg-slate-800 px-3 py-1 rounded-lg border border-slate-200 dark:border-slate-700">
            <Radio className="w-3.5 h-3.5 text-teal-500 animate-pulse" />
            <span>Targeting Case: {activeCaseId}</span>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={runInvestigation} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              required
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter target domain or URL (e.g. example.com, github.com)"
              className="w-full pl-10 pr-4 py-2.5 text-xs md:text-sm bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder:text-slate-400 outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-teal-600 hover:bg-teal-700 disabled:opacity-60 text-white text-xs md:text-sm font-semibold rounded-xl transition shadow-xs flex items-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Probing...</span>
              </>
            ) : (
              <span>Analyse</span>
            )}
          </button>
        </form>

        {/* SSRF Error Alert */}
        {ssrfError && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-3 text-xs text-red-700 dark:text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">SSRF Security Policy Block</p>
              <p className="text-[11px] leading-relaxed mt-0.5">{ssrfError}</p>
            </div>
          </div>
        )}
      </div>

      {/* Ready state when no domain has been probed yet */}
      {!report && !loading && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-4 shadow-xs">
          <div className="w-12 h-12 mx-auto rounded-2xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Authoritative Domain & Infrastructure Recon</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
              Provides verifiable source provenance on every data field. Resolves DNS records, inspects SSL/TLS certificates, tests HTTP security headers, and queries RDAP registries without guessing.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
            <span className="text-xs text-slate-400">Quick Test Targets:</span>
            {['example.com', 'cloudflare.com', 'github.com'].map((dom) => (
              <button
                key={dom}
                type="button"
                onClick={() => {
                  setTargetInput(dom);
                  executeProbe(dom);
                }}
                className="px-3 py-1 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-700 dark:text-slate-200 transition"
              >
                {dom}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Results View */}
      {report && (
        <div className="space-y-6">
          {/* Target Header Card */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400">
                <Globe className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base md:text-lg font-bold text-slate-900 dark:text-white font-mono">
                    {report.domain}
                  </h2>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                      report.riskLevel === 'Critical'
                        ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                        : report.riskLevel === 'High'
                        ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                        : report.riskLevel === 'Medium'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                        : 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300'
                    }`}
                  >
                    {report.riskLevel} Risk ({report.riskScore}/100)
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-mono">
                    v{report.engineVersion}
                  </span>
                </div>
                <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
                  <Clock className="w-3 h-3" />
                  Analyzed {new Date(report.analysisTimestamp).toLocaleString()} UTC • Data Completeness: {report.dataCompleteness}%
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {attachFeedback ? (
                <div className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 rounded-xl">
                  <Check className="w-3.5 h-3.5" />
                  <span>{attachFeedback}</span>
                </div>
              ) : (
                <>
                  <button
                    onClick={handleAttachReportToCase}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
                    title={`Attach domain artifact to Case ${activeCaseId}`}
                  >
                    <Plus className="w-3.5 h-3.5 text-teal-600" />
                    <span>Attach Evidence</span>
                  </button>

                  <button
                    onClick={handleLogFormalFinding}
                    className="flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-xl transition shadow-xs"
                    title={`Log unified finding to Case ${activeCaseId}`}
                  >
                    <Flag className="w-3.5 h-3.5" />
                    <span>Log Formal Finding</span>
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Top-Level Investigation Mode Toggle */}
          <InvestigationViewToggle
            mode={viewMode}
            onChange={setViewMode}
            simpleLabel="Simple Results"
            deepLabel="Deep Analysis"
            simpleDescription="Human-Readable Cybersecurity Analyst Report"
            deepDescription="Raw DNS, TLS, Headers, RDAP Telemetry & Ground Truth"
            findingCounts={{
              concerns: report.aiSecurityAnalysis?.findings?.filter((f) => f.severity !== 'Informational').length,
              technicalItems: report.resolvedIps.length + (report.httpProbe?.missingSecurityHeaders.length ?? 0) + (report.dnsRecords.mx.length + report.dnsRecords.ns.length),
            }}
          />

          {/* VIEW 1: SIMPLE RESULTS (DEFAULT) */}
          {viewMode === 'simple' && (
            <DomainAiAnalysisSection
              report={report}
              onRefreshAi={handleRefreshAiAnalysis}
              isRefreshing={isRefreshingAi}
            />
          )}

          {/* VIEW 2: DEEP ANALYSIS (TECHNICAL TELEMETRY) */}
          {viewMode === 'deep' && (
            <div className="space-y-6">
              {/* Navigation Sub-Tabs */}
              <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium">
                {[
                  { id: 'overview', label: 'Overview & Target Info' },
                  { id: 'scoring', label: `Deterministic Scoring (${report.riskScore})` },
                  { id: 'dns', label: `DNS Records (${report.resolvedIps.length + report.dnsRecords.mx.length + report.dnsRecords.ns.length})` },
                  { id: 'tls', label: 'TLS / SSL Certificate' },
                  { id: 'headers', label: `Security Headers (${report.httpProbe?.missingSecurityHeaders.length ?? 0} missing)` },
                  { id: 'rdap', label: 'RDAP / Registration' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition ${
                      activeTab === tab.id
                        ? 'bg-teal-600 text-white font-semibold shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>

              {/* TAB 1: OVERVIEW */}
              {activeTab === 'overview' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Domain Overview Data */}
              <div className="md:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                {/* AI Security Spotlight Banner */}
                {report.aiSecurityAnalysis && (
                  <div className="p-4 bg-gradient-to-r from-purple-500/10 via-teal-500/10 to-transparent border border-purple-200 dark:border-purple-800/80 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div className="flex items-start gap-2.5">
                      <Sparkles className="w-4 h-4 text-purple-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                          <span>AI Security Analyst Assessment</span>
                          <span className="text-[10px] font-normal px-1.5 py-0.2 rounded bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300">
                            {report.aiSecurityAnalysis.modelUsed}
                          </span>
                        </p>
                        <p className="text-[11px] text-slate-600 dark:text-slate-300 mt-1 line-clamp-2 leading-relaxed">
                          {report.aiSecurityAnalysis.overallAssessment}
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => setViewMode('simple')}
                      className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white font-semibold text-xs rounded-xl transition shadow-xs flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
                    >
                      <span>Read Plain-English Analysis</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Domain Infrastructure Overview</h3>
                  {renderProvenanceBadge(report.provenance.dns)}
                </div>

                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <dt className="text-slate-400">Target Hostname</dt>
                    <dd className="font-mono font-semibold text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.domain}
                    </dd>
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <dt className="text-slate-400">Registrar</dt>
                      {renderProvenanceBadge(report.provenance.rdap)}
                    </div>
                    <dd className="font-semibold text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.rdap?.registrar || (
                        <span className="text-slate-400 italic font-normal">
                          {report.rdap?.status === 'Forbidden' ? 'RDAP Query Forbidden (HTTP 403)' : 'Registration details unavailable'}
                        </span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Primary IP Address</dt>
                    <dd className="font-mono font-semibold text-slate-800 dark:text-slate-200 mt-0.5 flex items-center gap-2">
                      {report.resolvedIps[0] ? (
                        <>
                          <span>{report.resolvedIps[0].ip}</span>
                          <span className="text-[10px] px-1.5 py-0.2 bg-slate-100 dark:bg-slate-800 rounded font-normal text-slate-500">
                            IPv{report.resolvedIps[0].version}
                          </span>
                          {report.resolvedIps[0].isCdnOrCloud && (
                            <span className="text-[10px] px-1.5 py-0.2 bg-teal-50 dark:bg-teal-950 text-teal-600 dark:text-teal-400 rounded font-normal border border-teal-200 dark:border-teal-800">
                              CDN / Cloud
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="text-amber-500 font-normal">Unresolved (DNS failed)</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <dt className="text-slate-400">Web Server Banner</dt>
                      {renderProvenanceBadge(report.provenance.http)}
                    </div>
                    <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.httpProbe?.serverBanner || 'Not Disclosed / None'}
                    </dd>
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <dt className="text-slate-400">HTTPS Protocol & Cipher</dt>
                      {renderProvenanceBadge(report.provenance.tls)}
                    </div>
                    <dd className="text-slate-800 dark:text-slate-200 mt-0.5 font-mono">
                      {report.tlsCertificate?.protocol ? (
                        `${report.tlsCertificate.protocol} (${report.tlsCertificate.cipher || 'Standard Cipher'})`
                      ) : (
                        <span className="text-slate-400 italic font-normal">Port 443 Handshake Incomplete</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Registration Status</dt>
                    <dd className="text-slate-800 dark:text-slate-200 mt-0.5 font-mono text-[11px]">
                      {report.rdap?.domainStatus && report.rdap.domainStatus.length > 0 ? (
                        report.rdap.domainStatus.join(', ')
                      ) : (
                        <span className="text-slate-400 italic font-normal">
                          {report.rdap?.status === 'Forbidden' ? 'Status unavailable (RDAP 403)' : 'Not declared'}
                        </span>
                      )}
                    </dd>
                  </div>
                </dl>

                {/* HTTP Redirect Chain Inspection */}
                {report.httpProbe && report.httpProbe.redirectChain && (
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
                    <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                      HTTP Request & Redirect Chain ({report.httpProbe.redirectCount} redirects):
                    </span>
                    <div className="bg-slate-50 dark:bg-slate-800/60 p-2.5 rounded-xl border border-slate-200/60 dark:border-slate-700/60 space-y-1.5 font-mono text-[11px]">
                      {report.httpProbe.redirectChain.map((hop, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                          <span className="text-slate-400">#{idx + 1}</span>
                          <span className="font-semibold text-teal-600 dark:text-teal-400">
                            HTTP {hop.statusCode || '200'}
                          </span>
                          <span className="truncate">{hop.url}</span>
                        </div>
                      ))}
                      <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-700 flex items-center gap-1.5">
                        <ShieldCheck className="w-3 h-3 text-teal-500" />
                        <span>Every hop address validated against SSRF private and loopback filters before execution.</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Incomplete or Inconclusive Probes */}
                {report.uncompletedChecks.length > 0 && (
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 text-xs">
                    <span className="font-semibold text-slate-500 dark:text-slate-400 block mb-2">
                      Incomplete or Inconclusive Probes ({report.uncompletedChecks.length}):
                    </span>
                    <div className="space-y-1.5">
                      {report.uncompletedChecks.map((item, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 p-2 rounded-lg bg-slate-50 dark:bg-slate-800/40 text-[11px]"
                        >
                          <span className="px-1.5 py-0.2 bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded font-semibold text-[10px]">
                            {item.category}
                          </span>
                          <span className="font-medium text-slate-800 dark:text-slate-200">{item.check}:</span>
                          <span className="text-slate-500 dark:text-slate-400">{item.reason}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Threat Risk Summary Card */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Deterministic Risk Profile</h3>

                <div className="flex items-center gap-4">
                  <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                    <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                      <path
                        className="text-slate-200 dark:text-slate-700"
                        strokeWidth="3.5"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        className={
                          report.riskScore >= 75
                            ? 'text-red-500'
                            : report.riskScore >= 50
                            ? 'text-amber-500'
                            : report.riskScore >= 25
                            ? 'text-blue-500'
                            : 'text-teal-500'
                        }
                        strokeDasharray={`${report.riskScore}, 100`}
                        strokeWidth="3.5"
                        strokeLinecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <span className="absolute text-sm font-bold font-mono text-slate-900 dark:text-white">
                      {report.riskScore}
                    </span>
                  </div>
                  <div>
                    <span
                      className={`text-xs font-bold ${
                        report.riskLevel === 'Critical'
                          ? 'text-red-600 dark:text-red-400'
                          : report.riskLevel === 'High'
                          ? 'text-amber-600 dark:text-amber-400'
                          : report.riskLevel === 'Medium'
                          ? 'text-blue-600 dark:text-blue-400'
                          : 'text-teal-600 dark:text-teal-400'
                      }`}
                    >
                      {report.riskLevel} Risk Profile
                    </span>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Derived strictly from verified observations.
                    </p>
                  </div>
                </div>

                {/* Data Completeness Bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] text-slate-500">
                    <span>Telemetry Completeness</span>
                    <span className="font-mono">{report.dataCompleteness}%</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-teal-500 h-1.5 rounded-full"
                      style={{ width: `${report.dataCompleteness}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Observed Risk Factors ({report.riskFactors.length}):
                  </span>
                  {report.riskFactors.length === 0 ? (
                    <p className="text-xs text-slate-400 italic">No adverse risk factors observed in active probes.</p>
                  ) : (
                    report.riskFactors.map((factor, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 text-[11px] text-slate-700 dark:text-slate-300 leading-snug"
                      >
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{factor}</span>
                      </div>
                    ))
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => setActiveTab('scoring')}
                  className="w-full mt-2 py-2 text-xs text-teal-600 hover:text-teal-700 dark:text-teal-400 font-semibold bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition flex items-center justify-center gap-1 border border-slate-200/80 dark:border-slate-700/80"
                >
                  <span>View Full Scoring Breakdown</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* TAB 2: DETERMINISTIC SCORING BREAKDOWN */}
          {activeTab === 'scoring' && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      Deterministic Risk Formula & Factor Attribution
                    </h3>
                    <p className="text-xs text-slate-400">
                      Score is strictly mathematical, transparent, and derived without heuristic guesswork.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">Base Score:</span>
                    <span className="text-sm font-mono font-bold text-slate-900 dark:text-white px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                      {report.riskScore} / 100
                    </span>
                  </div>
                </div>

                {/* Factors Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                        <th className="py-2.5 px-3">Category</th>
                        <th className="py-2.5 px-3">Contributing Factor</th>
                        <th className="py-2.5 px-3">Observed Telemetry</th>
                        <th className="py-2.5 px-3 text-center">Weight</th>
                        <th className="py-2.5 px-3">Mitigation / Recommendation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                      {report.riskFactorDetails.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-4 text-center text-slate-400 italic">
                            No penalty points added. All observable baseline checks passed.
                          </td>
                        </tr>
                      ) : (
                        report.riskFactorDetails.map((f) => (
                          <tr key={f.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                            <td className="py-3 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                                {f.category}
                              </span>
                            </td>
                            <td className="py-3 px-3">
                              <p className="font-semibold text-slate-800 dark:text-slate-200">{f.title}</p>
                              <p className="text-[11px] text-slate-400 mt-0.5">{f.rationale}</p>
                            </td>
                            <td className="py-3 px-3 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                              {f.observedValue}
                            </td>
                            <td className="py-3 px-3 text-center font-mono font-bold text-red-600 dark:text-red-400">
                              +{f.weight}
                            </td>
                            <td className="py-3 px-3 text-[11px] text-slate-600 dark:text-slate-400">
                              {f.mitigation}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Explicit Scoring Limitations Banner */}
                <div className="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200/80 dark:border-slate-700/80 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-800 dark:text-slate-200">
                    <Info className="w-4 h-4 text-teal-600 shrink-0" />
                    <span>Scientific Doctrine & Defensible Limitations:</span>
                  </div>
                  <ul className="list-disc pl-5 space-y-1 text-slate-500 dark:text-slate-400 text-xs">
                    {report.scoringLimitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: DNS RECORDS */}
          {activeTab === 'dns' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Authoritative DNS Records</h3>
                  <p className="text-xs text-slate-400">Directly resolved via asynchronous system queries.</p>
                </div>
                {renderProvenanceBadge(report.provenance.dns)}
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Resolved Value</th>
                      <th className="py-2.5 px-3">Resolver / Details</th>
                      <th className="py-2.5 px-3 text-right">Attach Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-xs">
                    {report.dnsRecords.a.map((ip, i) => (
                      <tr key={`a-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-blue-600">A (IPv4)</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{ip}</td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">System Local Resolver</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              onAttachEvidence(ip, 'ip', ip, `Resolved IPv4 from ${report.domain}`, {
                                source: 'DNS A Lookup',
                                confidence: 'Observed',
                              })
                            }
                            className="text-[11px] text-teal-600 hover:text-teal-700 dark:text-teal-400 font-sans font-semibold hover:underline"
                          >
                            + Attach IP
                          </button>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.aaaa.map((ip, i) => (
                      <tr key={`aaaa-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-indigo-600">AAAA (IPv6)</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{ip}</td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">System Local Resolver</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              onAttachEvidence(ip, 'ip', ip, `Resolved IPv6 from ${report.domain}`, {
                                source: 'DNS AAAA Lookup',
                                confidence: 'Observed',
                              })
                            }
                            className="text-[11px] text-teal-600 hover:text-teal-700 dark:text-teal-400 font-sans font-semibold hover:underline"
                          >
                            + Attach IP
                          </button>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.mx.map((mx, i) => (
                      <tr key={`mx-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-purple-600">MX</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">
                          {mx.exchange} (Priority: {mx.priority})
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">Mail Exchanger</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              onAttachEvidence(mx.exchange, 'domain', mx.exchange, `Mail server for ${report.domain}`, {
                                source: 'DNS MX Lookup',
                                confidence: 'Observed',
                              })
                            }
                            className="text-[11px] text-teal-600 hover:text-teal-700 dark:text-teal-400 font-sans font-semibold hover:underline"
                          >
                            + Attach MX
                          </button>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.ns.map((ns, i) => (
                      <tr key={`ns-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-teal-600">NS</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{ns}</td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">Authoritative Nameserver</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              onAttachEvidence(ns, 'domain', ns, `Nameserver for ${report.domain}`, {
                                source: 'DNS NS Lookup',
                                confidence: 'Observed',
                              })
                            }
                            className="text-[11px] text-teal-600 hover:text-teal-700 dark:text-teal-400 font-sans font-semibold hover:underline"
                          >
                            + Attach NS
                          </button>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.cname?.map((cn, i) => (
                      <tr key={`cn-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-emerald-600">CNAME</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{cn}</td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">Canonical Alias</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              onAttachEvidence(cn, 'domain', cn, `Canonical alias for ${report.domain}`, {
                                source: 'DNS CNAME Lookup',
                                confidence: 'Observed',
                              })
                            }
                            className="text-[11px] text-teal-600 hover:text-teal-700 dark:text-teal-400 font-sans font-semibold hover:underline"
                          >
                            + Attach CNAME
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: TLS CERTIFICATE */}
          {activeTab === 'tls' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">TLS / SSL Handshake Inspection</h3>
                  <p className="text-xs text-slate-400">Verified cryptographic trust chain and SAN hostname matching.</p>
                </div>
                {renderProvenanceBadge(report.provenance.tls)}
              </div>

              {report.tlsCertificate ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-2 border border-slate-200/60 dark:border-slate-700/60">
                    <span className="text-slate-400 block text-[11px]">Certificate Trust & Status</span>
                    <div className="flex items-center gap-2">
                      {report.tlsCertificate.valid ? (
                        <CheckCircle className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-red-500" />
                      )}
                      <span className="font-semibold text-slate-900 dark:text-white text-sm">
                        {report.tlsCertificate.valid ? 'Valid & Trusted' : 'Untrusted / Expired'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 space-y-1 pt-1">
                      <p>Days Remaining: <span className="font-mono font-bold text-slate-800 dark:text-slate-200">{report.tlsCertificate.daysRemaining ?? 'N/A'}</span></p>
                      <p>
                        Hostname Match: {report.tlsCertificate.hostnameMatched ? (
                          <span className="text-emerald-600 font-semibold">Matched Certificate SAN/CN</span>
                        ) : (
                          <span className="text-red-500 font-semibold">Mismatch / Wildcard Mismatch</span>
                        )}
                      </p>
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-2 border border-slate-200/60 dark:border-slate-700/60">
                    <span className="text-slate-400 block text-[11px]">Negotiated Cipher & Protocol</span>
                    <p className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                      {report.tlsCertificate.protocol || 'Unknown'}
                    </p>
                    <p className="font-mono text-[11px] text-slate-500">{report.tlsCertificate.cipher || 'Default Cipher'}</p>
                    {report.tlsCertificate.daysRemaining !== undefined && report.tlsCertificate.daysRemaining <= 14 && (
                      <p className="text-[11px] text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Impending expiration within 14 days</span>
                      </p>
                    )}
                  </div>

                  <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl col-span-full space-y-2 border border-slate-200/60 dark:border-slate-700/60">
                    <span className="text-slate-400 block text-[11px]">Subject & Issuer Details</span>
                    <p className="font-mono text-slate-800 dark:text-slate-200 text-xs">
                      <span className="text-slate-400 font-sans">Subject:</span> {report.tlsCertificate.subject || 'Not specified'}
                    </p>
                    <p className="font-mono text-slate-600 dark:text-slate-400 text-xs">
                      <span className="text-slate-400 font-sans">Issuer:</span> {report.tlsCertificate.issuer || 'Not specified'}
                    </p>
                    <div className="flex gap-4 text-[11px] text-slate-500 font-mono pt-1">
                      <span>Valid From: {report.tlsCertificate.validFrom || 'N/A'}</span>
                      <span>Valid To: {report.tlsCertificate.validTo || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-6 bg-slate-50 dark:bg-slate-800/50 rounded-xl text-center text-xs text-slate-400">
                  No TLS certificate returned on port 443 during socket handshake.
                </div>
              )}
            </div>
          )}

          {/* TAB 5: HTTP SECURITY HEADERS */}
          {activeTab === 'headers' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">HTTP Security Headers & Hardening Audit</h3>
                  <p className="text-xs text-slate-400">Case-insensitive evaluation against defense-in-depth best practices.</p>
                </div>
                {renderProvenanceBadge(report.provenance.http)}
              </div>

              {/* Explanatory Doctrine Note */}
              <div className="p-3 bg-teal-50/70 dark:bg-teal-950/40 rounded-xl border border-teal-200/60 dark:border-teal-800/60 flex items-start gap-2.5 text-xs text-teal-900 dark:text-teal-200">
                <Info className="w-4 h-4 text-teal-600 shrink-0 mt-0.5" />
                <p className="text-[11px] leading-relaxed">
                  <strong>Defensible Hardening Doctrine:</strong> Missing security headers represent configuration hardening opportunities and defense-in-depth observations. They do <em>not</em> independently prove technical exploitability or probability of compromise.
                </p>
              </div>

              {/* Headers Table */}
              <div className="space-y-3">
                {report.httpProbe?.headerObservations.map((obs) => (
                  <div
                    key={obs.header}
                    className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-700/60 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {obs.status === 'Present' ? (
                          <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : obs.status === 'Missing' ? (
                          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                        ) : (
                          <span className="w-4 h-4 rounded-full bg-slate-300 dark:bg-slate-700 flex items-center justify-center text-[10px] text-slate-600 dark:text-slate-400 font-bold">?</span>
                        )}
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 text-xs">
                          {obs.header}
                        </span>
                      </div>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          obs.status === 'Present'
                            ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                            : obs.status === 'Missing'
                            ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                            : 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300'
                        }`}
                      >
                        {obs.status}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-500 dark:text-slate-400 pl-6 space-y-1">
                      <p>
                        <span className="font-medium text-slate-700 dark:text-slate-300">Observed Value: </span>
                        {obs.value ? (
                          <span className="font-mono text-slate-800 dark:text-slate-200 bg-white dark:bg-slate-900 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                            {obs.value}
                          </span>
                        ) : (
                          <span className="italic text-slate-400">Header not returned in response</span>
                        )}
                      </p>
                      <p>
                        <span className="font-medium text-slate-700 dark:text-slate-300">Role: </span>
                        {obs.hardeningRole}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 6: RDAP / REGISTRATION */}
          {activeTab === 'rdap' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Registration Data Access Protocol (RDAP)</h3>
                  <p className="text-xs text-slate-400">Authoritative ICANN registry records. No inferred or guessed registrar data.</p>
                </div>
                {renderProvenanceBadge(report.provenance.rdap)}
              </div>

              {/* Explicit Handling of 403 or Rate-Limited */}
              {report.rdap?.status === 'Forbidden' && (
                <div className="p-4 bg-amber-50 dark:bg-amber-950/60 rounded-xl border border-amber-200 dark:border-amber-800 flex items-start gap-3 text-xs text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-bold">RDAP Registry Access Forbidden (HTTP 403)</p>
                    <p className="text-[11px] leading-relaxed mt-0.5">
                      The authoritative RDAP registry rejected this automated query without credentials. In accordance with defensible forensics standards, registrar and registrant identity will not be inferred or guessed.
                    </p>
                    <p className="text-[10px] font-mono text-slate-400 mt-1">Source URL: {report.rdap.sourceUrl}</p>
                  </div>
                </div>
              )}

              {report.rdap?.status === 'RateLimited' && (
                <div className="p-4 bg-amber-50 dark:bg-amber-950/60 rounded-xl border border-amber-200 dark:border-amber-800 flex items-start gap-3 text-xs text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-bold">RDAP Upstream Rate Limit Exceeded (HTTP 429)</p>
                    <p className="text-[11px] leading-relaxed mt-0.5">
                      The public RDAP registry has temporarily throttled automated lookups. Please retry after a brief delay.
                    </p>
                  </div>
                </div>
              )}

              {/* RDAP Fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-1">
                  <span className="text-slate-400 block text-[11px]">Authoritative Registrar</span>
                  <p className="font-semibold text-slate-800 dark:text-slate-200">
                    {report.rdap?.registrar || 'Not available from authoritative registry'}
                  </p>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-1">
                  <span className="text-slate-400 block text-[11px]">Registry Handle</span>
                  <p className="font-mono text-slate-800 dark:text-slate-200">
                    {report.rdap?.handle || 'None'}
                  </p>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-1">
                  <span className="text-slate-400 block text-[11px]">Registration Date</span>
                  <p className="font-mono text-slate-800 dark:text-slate-200">
                    {report.rdap?.registrationDate || 'Not specified'}
                  </p>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-1">
                  <span className="text-slate-400 block text-[11px]">Expiration Date</span>
                  <p className="font-mono text-slate-800 dark:text-slate-200">
                    {report.rdap?.expirationDate || 'Not specified'}
                  </p>
                </div>
              </div>
            </div>
          )}
          </div>
        )}

          {/* Interactive AI Copilot Consultation Section */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-xl bg-purple-50 dark:bg-purple-950/80 text-purple-600 dark:text-purple-400 border border-purple-200 dark:border-purple-800">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                    Interactive AI Copilot Consultation & Hardening Advisor
                  </h3>
                  <p className="text-xs text-slate-400">
                    Ask questions, generate custom Nginx/Apache configuration directives, or explore defensive attack scenarios for <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{report.domain}</span>.
                  </p>
                </div>
              </div>
            </div>

            <GeminiForensicsChat
              investigationContext={{
                domain: report.domain,
                missingHeaders: report.httpProbe?.missingSecurityHeaders,
                serverBanner: report.httpProbe?.serverBanner,
                riskScore: report.riskScore,
                riskLevel: report.riskLevel,
              }}
              isCompact
            />
          </div>
        </div>
      )}
    </div>
  );
};
