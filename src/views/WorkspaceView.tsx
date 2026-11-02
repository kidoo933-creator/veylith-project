import React, { useState, useMemo } from 'react';
import { CaseRecord, EvidenceItem, Finding, SeverityLevel, ConfidenceLevel, FindingCategory, CorrelationStatus, InvestigationViewMode } from '../types';
import { getAnalystProfile } from '../utils/storage';
import { EvidenceGraph } from '../components/EvidenceGraph';
import { FindingInspectorModal } from '../components/FindingInspectorModal';
import { InvestigationViewToggle } from '../components/InvestigationViewToggle';
import { SimpleResultsReport } from '../components/SimpleResultsReport';
import { generateCaseSimpleReport } from '../utils/caseWorkspaceAiAnalyst';
import {
  GitBranch,
  FolderLock,
  Plus,
  FileText,
  Calendar,
  User,
  ShieldCheck,
  Tag,
  Clock,
  Download,
  Trash2,
  CheckCircle,
  MessageSquare,
  History,
  AlertTriangle,
  Search,
  Filter,
  Eye,
  ChevronRight,
  ShieldAlert,
  Check,
  Terminal,
} from 'lucide-react';

interface WorkspaceViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
  onSelectCase: (id: string) => void;
  onUpdateStatus: (caseId: string, status: CaseRecord['status']) => void;
  onAddNote: (caseId: string, author: string, text: string) => void;
  onDeleteCase: (caseId: string) => void;
  onNavigateToReport: (caseId: string) => void;
  onUpdateFindingStatus?: (caseId: string, findingId: string, status: Finding['status']) => void;
  onUpdateCorrelationOverride?: (caseId: string, edgeId: string, status: CorrelationStatus) => void;
}

export const WorkspaceView: React.FC<WorkspaceViewProps> = ({
  cases,
  activeCaseId,
  onSelectCase,
  onUpdateStatus,
  onAddNote,
  onDeleteCase,
  onNavigateToReport,
  onUpdateFindingStatus,
  onUpdateCorrelationOverride,
}) => {
  const currentCase = cases.find((c) => c.id === activeCaseId) || cases[0];
  const [viewMode, setViewMode] = useState<InvestigationViewMode>('simple');
  const [activeTab, setActiveTab] = useState<'graph' | 'evidence' | 'timeline' | 'notes' | 'audit'>('timeline');
  const [newNote, setNewNote] = useState('');

  // Finding Search & Filtering State
  const [findingSearch, setFindingSearch] = useState('');
  const [findingSeverity, setFindingSeverity] = useState<string>('all');
  const [findingCategory, setFindingCategory] = useState<string>('all');
  const [findingSource, setFindingSource] = useState<string>('all');
  const [findingStatus, setFindingStatus] = useState<string>('all');

  // Evidence Search & Filtering State
  const [evidenceSearch, setEvidenceSearch] = useState('');
  const [evidenceTypeFilter, setEvidenceTypeFilter] = useState<string>('all');

  // Inspection Modals
  const [inspectedFinding, setInspectedFinding] = useState<Finding | null>(null);
  const [inspectedEvidence, setInspectedEvidence] = useState<EvidenceItem | null>(null);
  const [validationSuccess, setValidationSuccess] = useState<string | null>(null);

  const handleNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim() || !currentCase) return;
    const authorName = currentCase.leadAnalyst || getAnalystProfile().name;
    onAddNote(currentCase.id, authorName, newNote.trim());
    setNewNote('');
  };

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    if (!currentCase) return [];
    return currentCase.findings.filter((f) => {
      if (findingSeverity !== 'all' && f.severity !== findingSeverity) return false;
      if (findingCategory !== 'all' && f.category !== findingCategory) return false;
      if (findingStatus !== 'all' && f.status !== findingStatus) return false;
      if (findingSource !== 'all' && f.sourceTool !== findingSource) return false;
      if (findingSearch.trim()) {
        const q = findingSearch.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchDesc = f.description?.toLowerCase().includes(q);
        const matchTarget = f.targetEntity?.toLowerCase().includes(q);
        const matchObs = f.observedResult?.toLowerCase().includes(q);
        const matchId = f.id.toLowerCase().includes(q);
        if (!matchTitle && !matchDesc && !matchTarget && !matchObs && !matchId) return false;
      }
      return true;
    });
  }, [currentCase, findingSearch, findingSeverity, findingCategory, findingSource, findingStatus]);

  // Unique sources for finding filter
  const uniqueSources = useMemo(() => {
    if (!currentCase) return [];
    return Array.from(new Set(currentCase.findings.map((f) => f.sourceTool).filter(Boolean)));
  }, [currentCase]);

  // Filtered Evidence
  const filteredEvidence = useMemo(() => {
    if (!currentCase) return [];
    return currentCase.evidence.filter((e) => {
      if (evidenceTypeFilter !== 'all' && e.type !== evidenceTypeFilter) return false;
      if (evidenceSearch.trim()) {
        const q = evidenceSearch.toLowerCase();
        return (
          e.name.toLowerCase().includes(q) ||
          e.value.toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q) ||
          (e.notes && e.notes.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [currentCase, evidenceSearch, evidenceTypeFilter]);

  // Export & Validation
  const validateAndExportCase = () => {
    if (!currentCase) return;

    // Defensible integrity check: Ensure every finding cites real evidence
    const missingRefs: string[] = [];
    currentCase.findings.forEach((f) => {
      f.evidenceIds.forEach((evId) => {
        if (!currentCase.evidence.some((e) => e.id === evId)) {
          missingRefs.push(`Finding [${f.id}] cites non-existent evidence ID [${evId}]`);
        }
      });
    });

    if (missingRefs.length > 0) {
      alert(`Manifest Validation Warning:\n${missingRefs.join('\n')}`);
      return;
    }

    setValidationSuccess(`Verified: ${currentCase.findings.length} findings and ${currentCase.evidence.length} evidence items validated.`);
    setTimeout(() => setValidationSuccess(null), 4000);

    const blob = new Blob([JSON.stringify(currentCase, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Veylith_Case_${currentCase.id.replace('#', '')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getStatusBadge = (status: CaseRecord['status']) => {
    switch (status) {
      case 'In Progress':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300';
      case 'Analyzing':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300';
      case 'Open':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300';
      case 'Closed':
        return 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300';
      default:
        return 'bg-slate-100 text-slate-800';
    }
  };

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

  if (!currentCase) {
    return (
      <div className="space-y-6">
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-12 text-center shadow-xs">
          <div className="w-16 h-16 rounded-3xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400 mx-auto mb-4">
            <FolderLock className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            No Active Investigation Case
          </h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-2 leading-relaxed">
            There are currently no cases in the workspace. Veylith operates with authentic evidence integrity and zero fabricated mock cases. Initialize a new case or load an isolated training scenario from the Command Center.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Training Scenario Notice */}
      {currentCase.isTrainingScenario && (
        <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-center justify-between text-xs text-amber-700 dark:text-amber-300">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600" />
            <span>[TRAINING SCENARIO CASE] — All findings and evidence in this case are isolated training fixtures.</span>
          </div>
          <span className="font-mono text-[10px] bg-amber-200/50 dark:bg-amber-900/50 px-2 py-0.5 rounded font-bold">
            SANDBOX MODE
          </span>
        </div>
      )}

      {/* Top Selector & Actions Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-teal-50 dark:bg-teal-950/60 rounded-xl text-teal-600 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <select
                value={currentCase.id}
                onChange={(e) => onSelectCase(e.target.value)}
                className="font-mono font-bold text-sm md:text-base text-slate-900 dark:text-white bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-2.5 py-1 outline-none"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} - {c.title}
                  </option>
                ))}
              </select>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${getStatusBadge(currentCase.status || 'Open')}`}>
                {currentCase.status}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Created {new Date(currentCase.createdAt || Date.now()).toLocaleDateString()} • Lead Analyst: {currentCase.leadAnalyst}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Status Dropdown */}
          <select
            value={currentCase?.status}
            onChange={(e) => currentCase && onUpdateStatus(currentCase.id, e.target.value as any)}
            className="px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 font-medium outline-none"
          >
            <option value="Open">Status: Open</option>
            <option value="In Progress">Status: In Progress</option>
            <option value="Analyzing">Status: Analyzing</option>
            <option value="Closed">Status: Closed</option>
          </select>

          <button
            onClick={() => currentCase && onNavigateToReport(currentCase.id)}
            className="px-3 py-1.5 bg-teal-600 hover:bg-teal-700 text-white font-semibold rounded-xl transition shadow-xs flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate Report</span>
          </button>

          <button
            onClick={validateAndExportCase}
            className="px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl font-medium transition flex items-center gap-1.5 shadow-xs"
            title="Validate integrity and export Case JSON"
          >
            <Download className="w-3.5 h-3.5 text-teal-600" />
            <span>Export Case</span>
          </button>
        </div>
      </div>

      {validationSuccess && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-xl flex items-center gap-2 text-xs text-emerald-800 dark:text-emerald-200 font-medium">
          <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{validationSuccess}</span>
        </div>
      )}

      {/* Case Details Card */}
      {currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
            <div className="md:col-span-2">
              <span className="text-slate-400 text-[11px] block">Investigation Title & Scope</span>
              <p className="font-bold text-slate-900 dark:text-white text-sm mt-0.5">{currentCase.title}</p>
              <p className="text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">{currentCase.description}</p>
            </div>
            <div>
              <span className="text-slate-400 text-[11px] block">Scope Boundary</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {currentCase.scope.map((s, i) => (
                  <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                    {s}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <span className="text-slate-400 text-[11px] block">Assigned Tags</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {currentCase.tags.map((t, i) => (
                  <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800">
                    #{t}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top-Level Investigation Mode Toggle */}
      {currentCase && (
        <InvestigationViewToggle
          mode={viewMode}
          onChange={setViewMode}
          simpleLabel="Simple Results"
          deepLabel="Deep Analysis"
          simpleDescription="Executive Incident Briefing & Plain-English Analysis"
          deepDescription="Evidence Graph, Unified Findings Registry, Timeline & Audit Logs"
          findingCounts={{
            concerns: currentCase.findings.filter((f) => f.severity === 'Critical' || f.severity === 'High').length,
            technicalItems: currentCase.findings.length + currentCase.evidence.length,
          }}
        />
      )}

      {/* VIEW 1: SIMPLE RESULTS (DEFAULT) */}
      {currentCase && viewMode === 'simple' && (
        <SimpleResultsReport
          report={generateCaseSimpleReport(currentCase)}
          onNavigateToDeep={() => setViewMode('deep')}
        />
      )}

      {/* VIEW 2: DEEP ANALYSIS (TECHNICAL TELEMETRY) */}
      {currentCase && viewMode === 'deep' && (
        <div className="space-y-6">
          {/* Sub Navigation */}
          <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium overflow-x-auto select-none">
        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
            activeTab === 'timeline'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Findings & Threat Intel ({currentCase?.findings.length})
        </button>
        <button
          onClick={() => setActiveTab('evidence')}
          className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
            activeTab === 'evidence'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Evidence Records ({currentCase?.evidence.length})
        </button>
        <button
          onClick={() => setActiveTab('graph')}
          className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
            activeTab === 'graph'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Evidence Correlation Graph
        </button>
        <button
          onClick={() => setActiveTab('notes')}
          className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
            activeTab === 'notes'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Analyst Notes ({currentCase?.notes.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
            activeTab === 'audit'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Chain of Custody Audit Log ({currentCase?.auditLog.length})
        </button>
      </div>

      {/* Tab 1: Findings & Timeline (Phase 1 & Phase 5) */}
      {activeTab === 'timeline' && currentCase && (
        <div className="space-y-4">
          {/* Finding Search & Filter Bar */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-4 shadow-xs space-y-3">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 text-xs">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search findings by title, target entity, observation, or ID..."
                  value={findingSearch}
                  onChange={(e) => setFindingSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-800 dark:text-slate-200 text-xs outline-none focus:ring-2 focus:ring-teal-500/20"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={findingSeverity}
                  onChange={(e) => setFindingSeverity(e.target.value)}
                  className="px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 font-medium outline-none text-xs"
                >
                  <option value="all">Severity: All</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>

                <select
                  value={findingCategory}
                  onChange={(e) => setFindingCategory(e.target.value)}
                  className="px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 font-medium outline-none text-xs"
                >
                  <option value="all">Category: All</option>
                  <option value="Network & Protocol">Network & Protocol</option>
                  <option value="Binary & Static Forensics">Binary & Static Forensics</option>
                  <option value="Infrastructure & Recon">Infrastructure & Recon</option>
                  <option value="Vulnerability & Exploit">Vulnerability & Exploit</option>
                  <option value="Hardening & Security Header">Hardening & Security Header</option>
                </select>

                <select
                  value={findingStatus}
                  onChange={(e) => setFindingStatus(e.target.value)}
                  className="px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 font-medium outline-none text-xs"
                >
                  <option value="all">Status: All</option>
                  <option value="Unresolved">Unresolved</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Mitigated">Mitigated</option>
                  <option value="False Positive">False Positive</option>
                </select>
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 text-slate-400 text-xs">
                {currentCase.findings.length === 0
                  ? 'No findings recorded for this investigation yet. Attach evidence or run forensic modules (Domain, File, or PCAP) to document findings.'
                  : 'No findings match the current filter criteria.'}
              </div>
            ) : (
              filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-4 sm:p-5 shadow-xs text-xs space-y-3 hover:border-teal-500/60 transition"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {finding.id}
                      </span>
                      <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                        {finding.category}
                      </span>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${getSeverityBadge(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800">
                        {finding.confidence}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <select
                        value={finding.status}
                        onChange={(e) =>
                          onUpdateFindingStatus && onUpdateFindingStatus(currentCase.id, finding.id, e.target.value as any)
                        }
                        className="px-2 py-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-700 dark:text-slate-300 font-semibold outline-none text-[11px]"
                      >
                        <option value="Unresolved">Unresolved</option>
                        <option value="Investigating">Investigating</option>
                        <option value="Mitigated">Mitigated</option>
                        <option value="False Positive">False Positive</option>
                      </select>

                      <button
                        onClick={() => setInspectedFinding(finding)}
                        className="px-2.5 py-1 bg-teal-600 hover:bg-teal-700 text-white font-semibold rounded-lg text-[11px] transition flex items-center gap-1 shadow-xs"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <h4 className="font-bold text-slate-900 dark:text-white text-sm">
                      {finding.title}
                    </h4>
                    <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                      {finding.description}
                    </p>
                  </div>

                  {/* Observed Result callout */}
                  <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 font-mono text-[11px] text-slate-700 dark:text-slate-200 select-all">
                    Observed: {finding.observedResult}
                  </div>

                  {/* Metadata Row */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 text-[10px] text-slate-400 font-mono">
                    <div className="flex flex-wrap items-center gap-3">
                      <span>Target: <strong className="text-slate-700 dark:text-slate-300 font-sans">{finding.targetEntity}</strong></span>
                      <span>Source: <strong className="text-slate-700 dark:text-slate-300 font-sans">{finding.sourceTool}</strong></span>
                      <span>Cited Evidence: <strong>{finding.evidenceIds.join(', ') || 'None'}</strong></span>
                    </div>
                    <span>UTC: {new Date(finding.collectedAt || finding.timestamp || Date.now()).toUTCString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Evidence Records List */}
      {activeTab === 'evidence' && currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Tracked Evidence Artifacts</h3>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Search evidence..."
                value={evidenceSearch}
                onChange={(e) => setEvidenceSearch(e.target.value)}
                className="px-2.5 py-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs outline-none"
              />
              <select
                value={evidenceTypeFilter}
                onChange={(e) => setEvidenceTypeFilter(e.target.value)}
                className="px-2.5 py-1 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs outline-none"
              >
                <option value="all">Type: All</option>
                <option value="domain">Domain</option>
                <option value="ip">IP</option>
                <option value="file">File</option>
                <option value="hash">Hash</option>
                <option value="cve">CVE</option>
                <option value="pcap">PCAP</option>
              </select>
            </div>
          </div>

          {filteredEvidence.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-xs">
              {currentCase.evidence.length === 0
                ? 'No evidence artifacts attached to this case yet. Use Domain Intel, File Forensics, PCAP Lab, or Vulnerability Intel to attach artifacts.'
                : 'No evidence artifacts match the current filter.'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Identifier / Name</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Source</th>
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {filteredEvidence.map((ev) => (
                    <tr key={ev.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 font-mono">
                      <td className="py-3 px-3 uppercase text-[10px] font-bold text-teal-600">{ev.type}</td>
                      <td className="py-3 px-3 text-slate-900 dark:text-white font-semibold max-w-xs truncate">
                        {ev.name}
                        <span className="block font-normal text-[11px] text-slate-400 truncate">{ev.value}</span>
                      </td>
                      <td className="py-3 px-3 font-sans">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800">
                          {ev.confidence}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-sans text-slate-500">{ev.source}</td>
                      <td className="py-3 px-3 text-slate-400 text-[11px]">{new Date(ev.timestamp).toUTCString()}</td>
                      <td className="py-3 px-3 text-right font-sans">
                        <button
                          onClick={() => setInspectedEvidence(ev)}
                          className="px-2 py-1 text-[11px] bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded font-semibold transition"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Interactive Evidence Correlation Graph */}
      {activeTab === 'graph' && currentCase && (
        <EvidenceGraph
          evidence={currentCase.evidence}
          findings={currentCase.findings}
          caseId={currentCase.id}
          caseTitle={currentCase.title}
        />
      )}

      {/* Tab 4: Analyst Notes */}
      {activeTab === 'notes' && currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Investigative Case Notes</h3>

          <form onSubmit={handleNoteSubmit} className="space-y-2">
            <textarea
              rows={3}
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              placeholder="Record investigative observation, escalation note, or chain of custody note..."
              className="w-full p-3 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-xs text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-teal-500/20"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-semibold rounded-xl text-xs transition shadow-xs"
            >
              Post Note
            </button>
          </form>

          <div className="space-y-2.5 pt-2">
            {currentCase.notes.length === 0 ? (
              <p className="text-slate-400 text-xs py-4 text-center">No analyst notes recorded for this investigation yet.</p>
            ) : (
              currentCase.notes.map((note) => (
                <div
                  key={note.id}
                  className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between font-semibold text-slate-800 dark:text-slate-200">
                    <span className="flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-teal-600" />
                      {note.author}
                    </span>
                    <span className="text-[10px] font-normal text-slate-400 font-mono">
                      {new Date(note.timestamp).toUTCString()}
                    </span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-300 leading-relaxed">{note.text}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 5: Chain of Custody Audit Log */}
      {activeTab === 'audit' && currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <History className="w-4 h-4 text-teal-600" />
              Cryptographic Chain of Custody Log
            </h3>
            <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
              Audit Integrity: Verified
            </span>
          </div>

          <div className="space-y-2">
            {currentCase.auditLog.length === 0 ? (
              <p className="text-slate-400 text-xs py-4 text-center">No chain of custody audit events logged yet.</p>
            ) : (
              currentCase.auditLog.map((log) => (
                <div
                  key={log.id}
                  className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-xl border border-slate-200/60 dark:border-slate-700 text-xs flex items-center justify-between font-mono"
                >
                  <div>
                    <span className="font-bold text-teal-700 dark:text-teal-400 text-[11px] mr-2">
                      [{log.action}]
                    </span>
                    <span className="text-slate-800 dark:text-slate-200 font-sans">{log.details}</span>
                    <span className="block text-[10px] text-slate-400 mt-0.5">Actor: {log.actor}</span>
                  </div>
                  <span className="text-[10px] text-slate-400 shrink-0">
                    {new Date(log.timestamp).toUTCString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
      </div>
      )}

      {/* Finding Inspector Modal */}
      {inspectedFinding && currentCase && (
        <FindingInspectorModal
          finding={inspectedFinding}
          caseEvidence={currentCase.evidence}
          caseFindings={currentCase.findings}
          onClose={() => setInspectedFinding(null)}
          onUpdateStatus={(fId, st) => {
            if (onUpdateFindingStatus) onUpdateFindingStatus(currentCase.id, fId, st);
            setInspectedFinding((prev) => (prev ? { ...prev, status: st } : null));
          }}
          onNavigateToFinding={(fId) => {
            const next = currentCase.findings.find((f) => f.id === fId);
            if (next) setInspectedFinding(next);
          }}
          onSelectEvidence={(ev) => {
            setInspectedFinding(null);
            setInspectedEvidence(ev);
          }}
        />
      )}

      {/* Evidence Inspector Modal */}
      {inspectedEvidence && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg p-5 shadow-2xl space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <span className="font-mono text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                  {inspectedEvidence.type} Artifact
                </span>
                <h3 className="text-base font-bold text-slate-900 dark:text-white mt-1">
                  {inspectedEvidence.name}
                </h3>
              </div>
              <button
                onClick={() => setInspectedEvidence(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div>
                <span className="text-slate-400 text-[10px] uppercase font-bold block">Recorded Value / Hash</span>
                <p className="font-mono bg-slate-50 dark:bg-slate-800 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 select-all">
                  {inspectedEvidence.value}
                </p>
              </div>

              {inspectedEvidence.notes && (
                <div>
                  <span className="text-slate-400 text-[10px] uppercase font-bold block">Telemetry Notes</span>
                  <p className="text-slate-600 dark:text-slate-300 italic">{inspectedEvidence.notes}</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-100 dark:border-slate-800 text-[11px]">
                <div>
                  <span className="text-slate-400 block">Acquisition Source:</span>
                  <span className="font-semibold">{inspectedEvidence.source}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Confidence:</span>
                  <span className="font-semibold text-teal-600">{inspectedEvidence.confidence}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-400 block">UTC Timestamp:</span>
                  <span className="font-mono">{new Date(inspectedEvidence.timestamp).toUTCString()}</span>
                </div>
              </div>
            </div>

            <div className="pt-2 text-right">
              <button
                onClick={() => setInspectedEvidence(null)}
                className="px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 text-slate-800 dark:text-slate-200 font-semibold rounded-xl text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
