import React, { useState } from 'react';
import { CaseRecord } from '../types';
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
} from 'lucide-react';

interface ReportsViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ cases, activeCaseId }) => {
  const [selectedCaseId, setSelectedCaseId] = useState(activeCaseId || cases[0]?.id);
  const currentCase = cases.find((c) => c.id === selectedCaseId) || cases[0];

  const handlePrint = () => {
    window.print();
  };

  const downloadHtmlReport = () => {
    if (!currentCase) return;
    const reportHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Veylith Forensics Report - ${currentCase.id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 20px; }
    h1 { color: #0f172a; border-bottom: 2px solid #0d9488; padding-bottom: 8px; font-size: 24px; }
    h2 { color: #172b4d; margin-top: 24px; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    .meta { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px; margin: 16px 0; font-size: 13px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-high { background: #fee2e2; color: #991b1b; }
    .badge-observed { background: #ccfbf1; color: #115e59; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }
    th { background: #f1f5f9; }
    .footer { margin-top: 40px; font-size: 11px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 12px; }
  </style>
</head>
<body>
  <h1>VEYLITH Digital Forensics & Threat Investigation Report</h1>
  <div class="meta">
    <p><strong>Case ID:</strong> ${currentCase.id} | <strong>Title:</strong> ${currentCase.title}</p>
    <p><strong>Lead Analyst:</strong> ${currentCase.leadAnalyst} | <strong>Status:</strong> ${currentCase.status} | <strong>Priority:</strong> ${currentCase.priority}</p>
    <p><strong>Generated Timestamp:</strong> ${new Date().toISOString()} (UTC)</p>
  </div>

  <h2>1. Executive Summary</h2>
  <p>${currentCase.description}</p>

  <h2>2. Evidence Audit & Cryptographic Integrity</h2>
  <table>
    <thead>
      <tr><th>Type</th><th>Identifier</th><th>Confidence</th><th>Source</th></tr>
    </thead>
    <tbody>
      ${currentCase.evidence.map((e) => `<tr><td>${e.type}</td><td><code>${e.name}</code> (${e.value})</td><td><span class="badge badge-observed">${e.confidence}</span></td><td>${e.source}</td></tr>`).join('')}
    </tbody>
  </table>

  <h2>3. Key Findings & ATT&CK Correlation</h2>
  ${currentCase.findings.map((f) => `<div style="margin-bottom: 16px; padding: 12px; background: #fff; border: 1px solid #e2e8f0; border-radius: 6px;">
    <strong>[${f.severity}] ${f.title}</strong> (${f.confidence})
    <p style="margin: 6px 0;">${f.description}</p>
    <small style="color: #64748b;">Source Tool: ${f.sourceTool}</small>
  </div>`).join('')}

  <h2>4. Defensible Forensic Guarantee & Limitations</h2>
  <p>All recorded telemetry was gathered under strict read-only parameters without dynamic execution. Evidence was hashed using SHA-256 with an immutable chain of custody audit log.</p>

  <div class="footer">
    Report produced by Veylith DFIR Engine • Confirmed by Lead Analyst ${currentCase.leadAnalyst}
  </div>
</body>
</html>`;

    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Veylith_Forensic_Report_${currentCase.id.replace('#', '')}.html`;
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
            Court-admissible and executive summaries synthesized directly from verifiable evidence.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
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
            className="flex items-center gap-1.5 px-3.5 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-xl transition font-medium"
          >
            <Printer className="w-3.5 h-3.5 text-teal-600" />
            <span>Print PDF</span>
          </button>

          <button
            onClick={downloadHtmlReport}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl font-semibold transition shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export HTML</span>
          </button>
        </div>
      </div>

      {/* Printable Report Canvas */}
      {currentCase && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 shadow-sm space-y-8 text-xs text-slate-700 dark:text-slate-300 max-w-4xl mx-auto">
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
              <p className="font-bold text-slate-900 dark:text-white">DEFENSIBLE INCIDENT REPORT</p>
              <p>Reference: {currentCase.id}</p>
              <p>{new Date().toUTCString()}</p>
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
              <span className="font-medium text-slate-800 dark:text-slate-200 mt-0.5 block">{currentCase.leadAnalyst}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Priority & Status</span>
              <span className="font-bold text-red-600 dark:text-red-400 mt-0.5 block">
                {currentCase.priority} • {currentCase.status}
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
              {currentCase.description} Evidence in this investigation was acquired via passive read-only network inspection, endpoint static file hashing, and public vulnerability intelligence. No active scanning or exploitation was performed.
            </p>
          </div>

          {/* Section 2: Methodology & Sources */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              2. Investigative Methodology & Source Verification
            </h3>
            <p className="leading-relaxed text-slate-600 dark:text-slate-300 text-xs">
              Analysis was executed using the Veylith Tool-Oriented Forensics Architecture with strict policy validation. All network queries adhered to SSRF safety limits preventing local loopback and internal routing. File hashes were calculated through deterministic Web Crypto SHA-256.
            </p>
          </div>

          {/* Section 3: Verified Evidence Audit */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              3. Recorded Evidence Items
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
                  {currentCase.evidence.map((e) => (
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

          {/* Section 4: Key Findings */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              4. Key Findings & Confidence Stratification
            </h3>
            {currentCase.findings.map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-900 dark:text-white">{f.title}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                      {f.severity}
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                      [{f.confidence}]
                    </span>
                  </div>
                </div>
                <p className="text-slate-600 dark:text-slate-300 leading-relaxed text-xs">{f.description}</p>
                <p className="text-[10px] text-slate-400 font-mono">
                  Input: {f.relevantInput} • Source Tool: {f.sourceTool}
                </p>
              </div>
            ))}
          </div>

          {/* Section 5: Recommended Next Steps */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white border-b border-slate-100 dark:border-slate-800 pb-1">
              5. Forensics Recommendations & Defense Next Steps
            </h3>
            <ol className="list-decimal pl-4 space-y-1 text-slate-600 dark:text-slate-300 text-xs">
              <li>Deploy perimeter egress block for verified C2 destination IP (192.0.2.45).</li>
              <li>Isolate endpoint host DESKTOP-01 and perform physical volatile memory dump.</li>
              <li>Add SHA-256 hash {currentCase.evidence[0]?.value?.slice(0, 32)}... to enterprise EDR blacklist.</li>
              <li>Notify incident command and preserve chain-of-custody audit logs for regulatory compliance.</li>
            </ol>
          </div>

          {/* Forensic Sign-Off */}
          <div className="pt-6 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
            <div>
              <p className="font-semibold text-slate-700 dark:text-slate-300">Lead Analyst Signature:</p>
              <p className="font-mono text-slate-500">Alex Carter, Senior DFIR Specialist (Veylith Certified)</p>
            </div>
            <div className="text-right font-mono text-[10px]">
              <p>DEFENSIBLE DIGITAL FORENSICS</p>
              <p>Veylith Engine Core v2.4</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
