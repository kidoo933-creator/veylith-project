import React, { useState } from 'react';
import { CaseRecord, ViewTab, SeverityLevel } from '../types';
import {
  ShieldAlert,
  FileCheck2,
  Share2,
  FolderLock,
  PlusCircle,
  Globe,
  Upload,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  Clock,
  ExternalLink,
} from 'lucide-react';
import {
  getActiveCasesCount,
  getUniqueEvidenceCount,
  getIndicatorsReviewedCount,
  getReportsGeneratedCount,
  getAnalystProfile,
} from '../utils/storage';

interface OverviewViewProps {
  cases: CaseRecord[];
  onNavigate: (tab: ViewTab) => void;
  onSelectCase: (caseId: string) => void;
  onCreateCase: (data: {
    title: string;
    description: string;
    priority: SeverityLevel;
    leadAnalyst: string;
    scope: string[];
    tags: string[];
  }) => void;
  onLoadTrainingScenario?: () => void;
  onClearCases?: () => void;
  onExitTrainingMode?: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  cases,
  onNavigate,
  onSelectCase,
  onCreateCase,
  onLoadTrainingScenario,
  onClearCases,
  onExitTrainingMode,
}) => {
  const currentAnalyst = getAnalystProfile();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState<SeverityLevel>('High');
  const [leadAnalystInput, setLeadAnalystInput] = useState(currentAnalyst.name);
  const [newScope, setNewScope] = useState('Perimeter, DNS, Endpoint');
  const [newTags, setNewTags] = useState('threat_intel, incident_response');

  // Derive ground-truth statistics from stored operational/training records
  const isTrainingMode = cases.some((c) => c.isTrainingScenario);
  const activeCases = getActiveCasesCount(cases);
  const totalEvidence = getUniqueEvidenceCount(cases);
  const totalIndicators = getIndicatorsReviewedCount(cases);
  const reportsGenerated = getReportsGeneratedCount(isTrainingMode ? 'training' : 'operational');

  // Extract real indicators and real activity logs
  const allEvidence = cases.flatMap((c) => c.evidence || []);
  const allAuditLogs = cases
    .flatMap((c) => (c.auditLog || []).map((l) => ({ ...l, caseTitle: c.title, caseId: c.id })))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const topEvidenceItems = allEvidence.slice(0, 5);
  const recentActivity = allAuditLogs.slice(0, 5);

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    onCreateCase({
      title: newTitle.trim(),
      description: newDesc.trim() || 'No detailed scope provided.',
      priority: newPriority,
      leadAnalyst: leadAnalystInput.trim() || currentAnalyst.name,
      scope: newScope.split(',').map((s) => s.trim()).filter(Boolean),
      tags: newTags.split(',').map((t) => t.trim()).filter(Boolean),
    });
    setShowCreateModal(false);
    setNewTitle('');
    setNewDesc('');
    onNavigate('investigation-workspace');
  };

  const getStatusBadge = (status: CaseRecord['status']) => {
    switch (status) {
      case 'In Progress':
        return 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border-blue-200 dark:border-blue-800';
      case 'Analyzing':
        return 'bg-purple-50 text-purple-700 dark:bg-purple-950/60 dark:text-purple-300 border-purple-200 dark:border-purple-800';
      case 'Open':
        return 'bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 border-amber-200 dark:border-amber-800';
      case 'Closed':
        return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700';
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Training Mode Banner */}
      {isTrainingMode && (
        <div className="p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs animate-in fade-in">
          <div className="flex items-center gap-2.5 text-amber-700 dark:text-amber-400 font-semibold">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600" />
            <span>TRAINING SCENARIO MODE: Displaying isolated verification fixtures. This data is not operational customer telemetry.</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {onExitTrainingMode && (
              <button
                onClick={onExitTrainingMode}
                className="px-3 py-1 bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-xs font-bold transition"
              >
                Exit Training Mode
              </button>
            )}
            {onClearCases && (
              <button
                onClick={onClearCases}
                className="px-3 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-800 dark:text-amber-200 rounded-lg text-xs font-bold transition"
              >
                Clear to Clean Slate (0 Cases)
              </button>
            )}
          </div>
        </div>
      )}

      {/* Header and Quick Actions Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-200/80 dark:border-slate-800">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
            Command Center
          </h1>
          <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">
            Enterprise threat intelligence, digital forensics verification, and defensible case oversight.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onNavigate('domain-intel')}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
          >
            <Globe className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
            <span>Investigate Domain</span>
          </button>
          <button
            onClick={() => onNavigate('file-forensics')}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
          >
            <Upload className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            <span>Analyze File</span>
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-xl transition shadow-sm"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Create Case</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Row (from stored records) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Active Investigations</span>
            <div className="p-2 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400">
              <FolderLock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono">{activeCases}</div>
          <p className="text-[11px] text-teal-600 dark:text-teal-400 font-medium mt-1 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" /> Real-time active cases
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Evidence Items</span>
            <div className="p-2 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400">
              <Share2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono">{totalEvidence}</div>
          <p className="text-[11px] text-teal-600 dark:text-teal-400 font-medium mt-1">
            Tracked with cryptographic hashes
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Indicators Reviewed</span>
            <div className="p-2 rounded-xl bg-teal-50 dark:bg-teal-950/60 text-teal-600 dark:text-teal-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono">{totalIndicators}</div>
          <p className="text-[11px] text-slate-400 mt-1">Domains, IPs, CVEs, file hashes</p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Reports Generated</span>
            <div className="p-2 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400">
              <FileCheck2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono">{reportsGenerated}</div>
          <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium mt-1">
            Auditable, defensible summaries
          </p>
        </div>
      </div>

      {/* Main Grid: Recent Investigations & Side Widgets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Recent Investigations */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Recent Investigations</h3>
              <p className="text-xs text-slate-400">Active threat cases under forensic examination</p>
            </div>
            <button
              onClick={() => onNavigate('investigation-workspace')}
              className="text-xs font-semibold text-teal-600 dark:text-teal-400 hover:underline flex items-center gap-1"
            >
              <span>View all</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-100 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-3">Case ID</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Priority</th>
                  <th className="py-2.5 px-3">Updated</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
                {cases.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center">
                      <div className="flex flex-col items-center justify-center gap-2 max-w-sm mx-auto">
                        <div className="w-12 h-12 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-400 mb-1">
                          <FolderLock className="w-6 h-6" />
                        </div>
                        <p className="text-sm font-bold text-slate-800 dark:text-slate-200">
                          No operational investigations yet
                        </p>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          Active Investigations: 0. Veylith never fabricates data or defaults to mock telemetry. Initialize your first case or load an isolated training scenario.
                        </p>
                        <div className="flex items-center gap-2 mt-3">
                          <button
                            onClick={() => setShowCreateModal(true)}
                            className="px-3.5 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl font-semibold text-xs transition shadow-xs flex items-center gap-1.5"
                          >
                            <PlusCircle className="w-3.5 h-3.5" />
                            <span>Create Case</span>
                          </button>
                          {onLoadTrainingScenario && (
                            <button
                              onClick={onLoadTrainingScenario}
                              className="px-3.5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl font-semibold text-xs transition border border-slate-300 dark:border-slate-700"
                            >
                              Load Training Sandbox
                            </button>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : (
                  cases.map((c) => (
                    <tr
                      key={c.id}
                      onClick={() => {
                        onSelectCase(c.id);
                        onNavigate('investigation-workspace');
                      }}
                      className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 cursor-pointer transition group"
                    >
                      <td className="py-3 px-3 font-mono font-medium text-slate-900 dark:text-white">
                        {c.id}
                      </td>
                      <td className="py-3 px-3 font-semibold text-slate-800 dark:text-slate-200 max-w-[200px] truncate">
                        {c.title}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            c.priority === 'Critical'
                              ? 'bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300'
                              : c.priority === 'High'
                              ? 'bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300'
                              : 'bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                          }`}
                        >
                          {c.priority}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-500 dark:text-slate-400 text-[11px]">
                        {new Date(c.updatedAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`text-[10px] font-medium px-2 py-0.5 rounded-md border ${getStatusBadge(
                            c.status
                          )}`}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-teal-600 dark:group-hover:text-teal-400 inline" />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Col: Investigation Activity & Top Indicators */}
        <div className="space-y-6">
          {/* Key Risk Summary */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-1">Key Insights</h3>
            <p className="text-xs text-slate-400 mb-4">Correlation overview across stored evidence</p>

            {/* Top Indicators */}
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
              Top Priority Indicators
            </h4>
            <div className="space-y-2">
              {topEvidenceItems.length > 0 ? (
                topEvidenceItems.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-center justify-between p-2 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/50 dark:border-slate-700/50 text-xs"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          item.confidence === 'Confirmed'
                            ? 'bg-red-500'
                            : item.confidence === 'Observed'
                            ? 'bg-amber-500'
                            : 'bg-teal-500'
                        }`}
                      />
                      <span className="font-mono text-slate-800 dark:text-slate-200 truncate">
                        {item.name}
                      </span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                      {item.type}
                    </span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-400 py-2">No verified indicators available</p>
              )}
            </div>
          </div>

          {/* Activity Feed */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Investigation Activity</h3>
            {recentActivity.length > 0 ? (
              <div className="relative pl-5 space-y-4 border-l-2 border-slate-200 dark:border-slate-800 text-xs">
                {recentActivity.map((log) => (
                  <div key={log.id} className="relative">
                    <span className="absolute -left-[27px] top-1 w-3 h-3 rounded-full bg-teal-500 ring-4 ring-white dark:ring-slate-900" />
                    <p className="font-semibold text-slate-800 dark:text-slate-200">
                      {log.action.replace(/_/g, ' ')}
                    </p>
                    <p className="text-[11px] text-slate-400">{log.details}</p>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {log.actor}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 py-2">No recorded activity</p>
            )}
          </div>
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 dark:border-slate-800 space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <PlusCircle className="w-4 h-4 text-teal-600" />
                Create New Investigation Case
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-sm font-semibold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Case Title *
                </label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Cobalt Strike C2 Stager Detection"
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-teal-500/20"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Description & Incident Hypothesis
                </label>
                <textarea
                  rows={3}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Initial observations, affected systems, triggers, and hypothesis..."
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-teal-500/20"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Priority Level
                  </label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Lead Analyst
                  </label>
                  <input
                    type="text"
                    value={leadAnalystInput}
                    onChange={(e) => setLeadAnalystInput(e.target.value)}
                    placeholder="Analyst Name or Callsign"
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-teal-500/20"
                  />
                </div>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Scope (comma separated)
                </label>
                <input
                  type="text"
                  value={newScope}
                  onChange={(e) => setNewScope(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-200 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-xl transition shadow-xs"
                >
                  Create & Launch Workspace
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
