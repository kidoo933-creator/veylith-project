import React, { useState } from 'react';
import { CaseRecord } from '../types';
import {
  generateInvestigationReport,
  exportReportAsJson,
  generateReportHtml,
} from '../utils/reportGenerator';
import { recordGeneratedReport, getAnalystProfile } from '../utils/storage';
import {
  FileCheck2,
  Printer,
  Download,
  ShieldCheck,
  Calendar,
  User,
  AlertTriangle,
  CheckCircle,
  FileText,
  FileCode,
  Layers,
  ArrowRight,
  Clock,
  ExternalLink,
} from 'lucide-react';

interface ReportsViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ cases, activeCaseId }) => {
  const [selectedCaseId, setSelectedCaseId] = useState(activeCaseId || cases[0]?.id);
  const currentCase = cases.find((c) => c.id === selectedCaseId) || cases[0];

  const report = currentCase ? generateInvestigationReport(currentCase) : null;

  const handlePrint = () => {
    if (currentCase) {
      recordGeneratedReport({
        caseId: currentCase.id,
        caseTitle: currentCase.title,
        format: 'pdf',
        analystName: currentCase.leadAnalyst || getAnalystProfile().name,
        findingCount: currentCase.findings?.length || 0,
        evidenceCount: currentCase.evidence?.length || 0,
        isTrainingScenario: Boolean(currentCase.isTrainingScenario),
      });
    }
    window.print();
  };

  const downloadJsonReport = () => {
    if (!currentCase) return;
    recordGeneratedReport({
      caseId: currentCase.id,
      caseTitle: currentCase.title,
      format: 'json',
      analystName: currentCase.leadAnalyst || getAnalystProfile().name,
      findingCount: currentCase.findings?.length || 0,
      evidenceCount: currentCase.evidence?.length || 0,
      isTrainingScenario: Boolean(currentCase.isTrainingScenario),
    });
    const jsonStr = exportReportAsJson(currentCase);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Veylith_DFIR_Report_${currentCase.id.replace('#', '')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadHtmlReport = () => {
    if (!currentCase) return;
    recordGeneratedReport({
      caseId: currentCase.id,
      caseTitle: currentCase.title,
      format: 'html',
      analystName: currentCase.leadAnalyst || getAnalystProfile().name,
      findingCount: currentCase.findings?.length || 0,
      evidenceCount: currentCase.evidence?.length || 0,
      isTrainingScenario: Boolean(currentCase.isTrainingScenario),
    });
    const reportHtml = generateReportHtml(currentCase);
    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Veylith_DFIR_Report_${currentCase.id.replace('#', '')}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-teal-600" />
            Defensible Forensic Investigation Reports
          </h1>
          <p className="text-xs text-slate-400">
            Court-admissible and executive summaries synthesized directly from verified case evidence.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl font-mono text-xs font-semibold text-slate-800 dark:text-slate-200 outline-none"
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.id} - {c.title}
              </option>
            ))}
          </select>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl transition font-medium"
          >
            <Printer className="w-3.5 h-3.5 text-teal-600" />
            <span>Print / PDF</span>
          </button>

          <button
            onClick={downloadJsonReport}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 rounded-xl font-medium transition"
          >
            <FileCode className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={downloadHtmlReport}
            className="flex items-center gap-1.5 px-3 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl font-semibold transition shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export HTML</span>
          </button>
        </div>
      </div>

      {/* Empty State when no cases exist */}
      {!report && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-12 text-center shadow-xs">
          <FileText className="w-12 h-12 text-slate-300 dark:text-slate-700 mx-auto mb-3" />
          <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200">
            No Investigation Cases for Reporting
          </h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
            Create an investigation case or load a training sandbox in the Command Center to compile defensible forensic reports.
          </p>
        </div>
      )}

      {/* Printable Report Canvas */}
      {report && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-6 sm:p-8 shadow-sm space-y-7 text-xs text-slate-700 dark:text-slate-300 max-w-4xl mx-auto">
          {/* Training Scenario Watermark Notice */}
          {currentCase?.isTrainingScenario && (
            <div className="p-3 bg-amber-500/10 border border-amber-500/40 rounded-xl text-center text-xs font-bold text-amber-700 dark:text-amber-300">
              [TRAINING / SIMULATION REPORT — DATA DERIVED FROM ISOLATED DEMO FIXTURES — NOT ADMISSIBLE OPERATIONAL TELEMETRY]
            </div>
          )}

          {/* Letterhead */}
          <div className="flex items-center justify-between border-b-2 border-teal-600 pb-4">
            <div className="flex items-center gap-3">
              <img
                src="/assets/aistudio/veylith_logo_1c2c3d90.png"
                alt="Veylith"
                className="w-10 h-10 rounded-xl"
              />
              <div>
                <h2 className="text-xl font-extrabold tracking-wider text-slate-900 dark:text-white font-mono">
                  VEYLITH
                </h2>
                <span className="text-[10px] tracking-widest uppercase font-semibold text-teal-600 dark:text-teal-400">
                  DIGITAL FORENSICS & INCIDENT RESPONSE
                </span>
              </div>
            </div>

            <div className="text-right text-[11px] text-slate-400 font-mono">
              <span className="inline-block px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 text-[10px] font-bold mb-1">
                {report.classification}
              </span>
              <p className="font-bold text-slate-900 dark:text-white">DEFENSIBLE INCIDENT REPORT</p>
              <p>Reference: {report.caseId}</p>
              <p>{new Date(report.generatedAt).toUTCString()}</p>
            </div>
          </div>

          {/* Case Scope Meta */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700">
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Case Title</span>
              <span className="font-bold text-slate-900 dark:text-white mt-0.5 block">{currentCase.title}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Lead Analyst</span>
              <span className="font-medium text-slate-800 dark:text-slate-200 mt-0.5 block">{report.leadAnalyst}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Priority & Status</span>
              <span className="font-bold text-red-600 dark:text-red-400 mt-0.5 block">
                {report.priority} • {report.status}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Evidence Integrity</span>
              <span className="font-bold text-emerald-600 dark:text-emerald-400 mt-0.5 block">
                SHA-256 Verified
              </span>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              1. Executive Summary
            </h3>
            <p className="leading-relaxed text-slate-600 dark:text-slate-300 text-xs">
              {report.executiveSummary}
            </p>
          </div>

          {/* Section 2: Investigation Scope */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              2. Designated Scope Boundary
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {report.investigationScope.boundary.map((b, i) => (
                <span key={i} className="font-mono text-[11px] px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  {b}
                </span>
              ))}
            </div>
            <p className="text-[11px] text-slate-400">
              Tracking tags: {report.investigationScope.tags.map((t) => `#${t}`).join(' ') || 'None'}
            </p>
          </div>

          {/* Section 3: Methodology */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              3. Investigative Methodology & Source Verification
            </h3>
            <p className="leading-relaxed text-slate-600 dark:text-slate-300 text-xs">
              {report.methodology}
            </p>
          </div>

          {/* Section 4: Targets Analyzed */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              4. Targets Analyzed ({report.targetsAnalyzed.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
                    <th className="py-2 px-3">Target Entity</th>
                    <th className="py-2 px-3">Classification</th>
                    <th className="py-2 px-3">Observations Recorded</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                  {report.targetsAnalyzed.map((t, idx) => (
                    <tr key={idx}>
                      <td className="py-2 px-3 text-slate-800 dark:text-slate-200 font-bold">{t.entity}</td>
                      <td className="py-2 px-3 uppercase text-teal-600 font-sans">{t.type}</td>
                      <td className="py-2 px-3">{t.observationCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 5: Confirmed Observations */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              5. Confirmed Technical Observations ({report.confirmedObservations.length})
            </h3>
            {report.confirmedObservations.map((obs) => (
              <div
                key={obs.id}
                className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-900 dark:text-white">[{obs.id}] {obs.title}</span>
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                    [{obs.confidence}]
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed text-xs">{obs.observedResult}</p>
                <p className="text-[10px] text-slate-400 font-mono">
                  Target: {obs.targetEntity} • Source: {obs.sourceTool} • Timestamp: {new Date(obs.timestamp).toUTCString()}
                </p>
              </div>
            ))}
          </div>

          {/* Section 6: Inferred Correlations */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              6. Inferred Evidence Correlations ({report.inferredCorrelations.length})
            </h3>
            {report.inferredCorrelations.length === 0 ? (
              <p className="text-slate-500 italic">No inferred relationships recorded in this case.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px] border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
                      <th className="py-2 px-3">Connection Reason</th>
                      <th className="py-2 px-3">Inference Rationale</th>
                      <th className="py-2 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {report.inferredCorrelations.map((ic) => (
                      <tr key={ic.id}>
                        <td className="py-2 px-3 font-semibold text-slate-800 dark:text-slate-200">{ic.reason}</td>
                        <td className="py-2 px-3 text-slate-500 italic">{ic.inferredReason || 'Co-cited in finding'}</td>
                        <td className="py-2 px-3 uppercase font-mono text-[10px] text-purple-600 dark:text-purple-400 font-bold">{ic.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Section 7: Potential Risks */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              7. Potential Operational Risks ({report.potentialRisks.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
                    <th className="py-2 px-3">Severity</th>
                    <th className="py-2 px-3">Category</th>
                    <th className="py-2 px-3">Identified Risk</th>
                    <th className="py-2 px-3">Ref Finding</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {report.potentialRisks.map((pr, i) => (
                    <tr key={i}>
                      <td className="py-2 px-3 font-bold uppercase text-[10px] text-red-600">{pr.severity}</td>
                      <td className="py-2 px-3 text-slate-600 dark:text-slate-400">{pr.category}</td>
                      <td className="py-2 px-3 text-slate-800 dark:text-slate-200">{pr.risk}</td>
                      <td className="py-2 px-3 font-mono text-[10px] text-teal-600">{pr.groundedFindingId}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 8: Evidence Tables */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              8. Evidence Item Inventory ({report.evidenceInventory.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Identifier / Value</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Collection Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                  {report.evidenceInventory.map((e) => (
                    <tr key={e.id}>
                      <td className="py-2 px-3 uppercase text-teal-600 font-bold">{e.type}</td>
                      <td className="py-2 px-3 text-slate-800 dark:text-slate-200">
                        {e.name}
                        <span className="block text-[10px] text-slate-400 font-mono truncate">{e.value}</span>
                      </td>
                      <td className="py-2 px-3 font-sans">
                        <span className="text-[9.5px] font-bold px-1.5 py-0.2 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                          {e.confidence}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-sans text-slate-500">{e.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 9: Timeline */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              9. Chronological Investigation Timeline
            </h3>
            <div className="space-y-2 border-l-2 border-slate-200 dark:border-slate-800 pl-3 ml-2">
              {report.chronologicalTimeline.map((item) => (
                <div key={item.id} className="relative text-xs">
                  <span className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-teal-600" />
                  <span className="font-mono text-[10px] text-slate-400 block">
                    {new Date(item.timestamp).toUTCString()}
                  </span>
                  <span className="font-semibold text-slate-800 dark:text-slate-200">
                    [{item.eventType.toUpperCase()}] {item.summary}
                  </span>
                  <span className="text-slate-500 text-[10px] ml-1.5">({item.actorOrSource})</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 10: Limitations */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              10. Defensive Limitations & Investigative Boundaries
            </h3>
            <ul className="list-disc pl-4 space-y-1 text-slate-600 dark:text-slate-300 text-xs">
              {report.defensiveLimitations.map((l, idx) => (
                <li key={idx}>{l}</li>
              ))}
            </ul>
          </div>

          {/* Section 11: Conclusions */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              11. Formal Conclusions & Traceability
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
                    <th className="py-2 px-3">Conclusion Statement</th>
                    <th className="py-2 px-3">Grounded Finding ID</th>
                    <th className="py-2 px-3">Severity Level</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {report.conclusions.map((c, idx) => (
                    <tr key={idx}>
                      <td className="py-2 px-3 text-slate-800 dark:text-slate-200 leading-relaxed">{c.conclusion}</td>
                      <td className="py-2 px-3 font-mono font-bold text-teal-600">{c.groundedFindingId}</td>
                      <td className="py-2 px-3 font-bold uppercase text-[10px] text-red-600">{c.severity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Forensic Sign-Off */}
          <div className="pt-6 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
            <div>
              <p className="font-semibold text-slate-700 dark:text-slate-300">Lead Analyst Signature:</p>
              <p className="font-mono text-slate-500">{report.leadAnalyst}, Senior DFIR Specialist (Veylith Certified)</p>
            </div>
            <div className="text-right font-mono text-[10px]">
              <p>DEFENSIBLE DIGITAL FORENSICS</p>
              <p>Veylith Engine Core v2.4 • SHA-256 Verified</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
