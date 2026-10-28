import React, { useState } from 'react';
import { CaseRecord, EvidenceItem, Finding, SeverityLevel, ConfidenceLevel } from '../types';
import { EvidenceGraph } from '../components/EvidenceGraph';
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
} from 'lucide-react';

interface WorkspaceViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
  onSelectCase: (id: string) => void;
  onUpdateStatus: (caseId: string, status: CaseRecord['status']) => void;
  onAddNote: (caseId: string, author: string, text: string) => void;
  onDeleteCase: (caseId: string) => void;
  onNavigateToReport: (caseId: string) => void;
}

export const WorkspaceView: React.FC<WorkspaceViewProps> = ({
  cases,
  activeCaseId,
  onSelectCase,
  onUpdateStatus,
  onAddNote,
  onDeleteCase,
  onNavigateToReport,
}) => {
  const currentCase = cases.find((c) => c.id === activeCaseId) || cases[0];
  const [activeTab, setActiveTab] = useState<'graph' | 'evidence' | 'timeline' | 'notes' | 'audit'>('graph');
  const [newNote, setNewNote] = useState('');

  const handleNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim() || !currentCase) return;
    onAddNote(currentCase.id, 'Alex Carter', newNote.trim());
    setNewNote('');
  };

  const exportCaseJson = () => {
    if (!currentCase) return;
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

  return (
    <div className="space-y-6">
      {/* Top Selector & Actions Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-teal-50 dark:bg-teal-950/60 rounded-xl text-teal-600 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <select
                value={currentCase?.id}
                onChange={(e) => onSelectCase(e.target.value)}
                className="font-mono font-bold text-sm md:text-base text-slate-900 dark:text-white bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-2.5 py-1 outline-none"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} - {c.title}
                  </option>
                ))}
              </select>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${getStatusBadge(currentCase?.status || 'Open')}`}>
                {currentCase?.status}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Created {new Date(currentCase?.createdAt || Date.now()).toLocaleDateString()} • Lead Analyst: {currentCase?.leadAnalyst}
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
            onClick={exportCaseJson}
            className="p-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl transition"
            title="Export Case Package (JSON)"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

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

      {/* Sub Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium">
        <button
          onClick={() => setActiveTab('graph')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'graph'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Evidence Graph
        </button>
        <button
          onClick={() => setActiveTab('evidence')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'evidence'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Evidence Records ({currentCase?.evidence.length})
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'timeline'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Findings & Timeline ({currentCase?.findings.length})
        </button>
        <button
          onClick={() => setActiveTab('notes')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'notes'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Analyst Notes ({currentCase?.notes.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-3 py-1.5 rounded-lg transition ${
            activeTab === 'audit'
              ? 'bg-teal-600 text-white font-semibold'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Chain of Custody Audit Log ({currentCase?.auditLog.length})
        </button>
      </div>

      {/* Tab 1: Interactive Evidence Graph */}
      {activeTab === 'graph' && currentCase && (
        <div className="space-y-4">
          <EvidenceGraph evidence={currentCase.evidence} caseId={currentCase.id} />
        </div>
      )}

      {/* Tab 2: Evidence Records List */}
      {activeTab === 'evidence' && currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Tracked Evidence Items</h3>
          {currentCase.evidence.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-xs">
              No evidence attached to this case yet. Use Domain Intel or Evidence Lab to attach artifacts.
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
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {currentCase.evidence.map((ev) => (
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
                      <td className="py-3 px-3 text-slate-400 text-[11px]">{new Date(ev.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Timeline & Findings */}
      {activeTab === 'timeline' && currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Investigation Findings Timeline</h3>
          {currentCase.findings.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-xs">
              No formal findings recorded yet for this case.
            </div>
          ) : (
            <div className="space-y-3">
              {currentCase.findings.map((finding) => (
                <div
                  key={finding.id}
                  className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 text-xs space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900 dark:text-white text-sm">{finding.title}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                        {finding.severity}
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                        [{finding.confidence}]
                      </span>
                    </div>
                  </div>
                  <p className="text-slate-600 dark:text-slate-300 leading-relaxed">{finding.description}</p>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-700/60 font-mono">
                    <span>Source Tool: {finding.sourceTool}</span>
                    <span>Collected: {new Date(finding.collectedAt).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
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
            {currentCase.notes.map((note) => (
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
                    {new Date(note.timestamp).toLocaleString()}
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed">{note.text}</p>
              </div>
            ))}
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
            {currentCase.auditLog.map((log) => (
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
                  {new Date(log.timestamp).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
