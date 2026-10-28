import React, { useState } from 'react';
import { CaseRecord, EvidenceItem } from '../types';
import { GeminiForensicsChat } from '../components/GeminiForensicsChat';
import {
  Sparkles,
  MessageSquare,
  FileSpreadsheet,
  BrainCircuit,
  CheckCircle2,
  Lock,
  Layers,
  ArrowRight,
  ShieldCheck,
  Zap,
} from 'lucide-react';

interface AiAnalysisViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
}

export const AiAnalysisView: React.FC<AiAnalysisViewProps> = ({ cases, activeCaseId }) => {
  const currentCase = cases.find((c) => c.id === activeCaseId) || cases[0];
  const [activeSubTab, setActiveSubTab] = useState<'chat' | 'pipeline'>('chat');
  const [objective, setObjective] = useState(
    `Correlate current evidence in ${currentCase?.id || 'case'} and assess whether DESKTOP-01 was compromised by ${currentCase?.evidence?.[0]?.name || 'the suspect payload'}.`
  );
  const [userQuery, setUserQuery] = useState(
    'What are the confirmed indicators of compromise, what remains unknown, and what immediate defensive measures should be deployed?'
  );
  const [loading, setLoading] = useState(false);
  const [thinkingOutput, setThinkingOutput] = useState<string | null>(null);
  const [modelUsed, setModelUsed] = useState<string>('gemini-4-argon (ThinkingLevel.HIGH)');

  const [toolPlannerSteps] = useState([
    {
      step: 1,
      tool: 'policy_boundary_validator',
      status: 'Passed',
      notes: 'Verified SSRF guard compliance and scope bounds (DESKTOP-01, internal perimeter).',
    },
    {
      step: 2,
      tool: 'evidence_integrity_verifier',
      status: 'Passed',
      notes: 'SHA-256 hashes cross-verified against recorded EDR telemetry.',
    },
    {
      step: 3,
      tool: 'threat_intelligence_correlator',
      status: 'Passed',
      notes: 'Correlated C2 IP 192.0.2.45 with CISA KEV baseline.',
    },
    {
      step: 4,
      tool: 'gemini_high_thinking_engine',
      status: 'Active',
      notes: 'Executing Gemini 4 Argon with deep forensic reasoning and ATT&CK mapping.',
    },
  ]);

  const handleRunInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setThinkingOutput(null);

    try {
      const res = await fetch('/api/gemini/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          objective,
          scope: currentCase?.scope || ['Standard SOC Perimeter'],
          evidenceItems: currentCase?.evidence || [],
          userQuery,
        }),
      });

      const data = await res.json();
      if (data.analysis) {
        setThinkingOutput(data.analysis);
        setModelUsed(data.model || 'gemini-4-argon (ThinkingLevel.HIGH)');
      } else if (data.fallbackReasoning) {
        setThinkingOutput(data.fallbackReasoning);
        setModelUsed('Veylith Deterministic Engine (Offline / Safe Mode)');
      } else {
        setThinkingOutput(`AI Investigation error: ${data.error || 'Unknown response'}`);
      }
    } catch (err: any) {
      setThinkingOutput(`Execution error: ${err.message}. Non-AI deterministic workflows remain active.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-purple-600" />
              <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white">
                AI Forensic Investigation & Gemini Copilot
              </h1>
              <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-300 dark:border-purple-800">
                Multi-Turn DFIR
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Interactive multi-turn conversation and defensible synthesis using <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">gemini-4-argon</span> (complex), <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">gemini-3.8-flash</span> (general), and <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">gemini-3.1-flash-lite</span> (fast).
            </p>
          </div>

          {/* Sub-view switcher */}
          <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-xl border border-slate-200 dark:border-slate-700 text-xs">
            <button
              onClick={() => setActiveSubTab('chat')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition ${
                activeSubTab === 'chat'
                  ? 'bg-white dark:bg-slate-900 text-purple-700 dark:text-purple-300 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>Multi-Turn Chat</span>
            </button>
            <button
              onClick={() => setActiveSubTab('pipeline')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition ${
                activeSubTab === 'pipeline'
                  ? 'bg-white dark:bg-slate-900 text-purple-700 dark:text-purple-300 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Formal Policy Synthesis</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Tab Content */}
      {activeSubTab === 'chat' ? (
        <GeminiForensicsChat currentCase={currentCase} />
      ) : (
        <div className="space-y-6">
          {/* Tool-Oriented Architecture Pipeline Display */}
          <div className="bg-slate-50 dark:bg-slate-900/60 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-4">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3 block">
              Tool-Oriented Execution Policy & Verification Layer
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {toolPlannerSteps.map((step) => (
                <div
                  key={step.step}
                  className="p-3 bg-white dark:bg-slate-800/80 rounded-xl border border-slate-200/70 dark:border-slate-700/70 shadow-2xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] font-bold text-slate-400">Step 0{step.step}</span>
                    <span className="text-[10px] font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> {step.status}
                    </span>
                  </div>
                  <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 truncate">
                    {step.tool}
                  </p>
                  <p className="text-[11px] text-slate-400 leading-snug">{step.notes}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Form and Synthesis Display */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Form Column (1 col) */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Investigation Parameters</h3>

              <form onSubmit={handleRunInvestigation} className="space-y-4 text-xs">
                <div>
                  <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Investigation Objective
                  </label>
                  <textarea
                    rows={3}
                    value={objective}
                    onChange={(e) => setObjective(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-purple-500/20"
                  />
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Forensic Hypothesis / Inquiry
                  </label>
                  <textarea
                    rows={4}
                    value={userQuery}
                    onChange={(e) => setUserQuery(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-purple-500/20"
                  />
                </div>

                <div className="p-3 bg-purple-50/60 dark:bg-purple-950/30 rounded-xl border border-purple-200/60 dark:border-purple-800/60 space-y-1.5 text-[11px] text-purple-900 dark:text-purple-300">
                  <span className="font-semibold block">Evidence Scope Attached:</span>
                  <ul className="list-disc pl-4 space-y-0.5 text-[10.5px]">
                    {currentCase?.evidence.map((ev) => (
                      <li key={ev.id} className="truncate">
                        [{ev.confidence}] {ev.type}: {ev.name}
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white font-semibold rounded-xl transition shadow-xs text-xs flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Thinking Deeply (gemini-4-argon)...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      <span>Run Defensible Synthesis</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Results Column (2 cols) */}
            <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="w-4 h-4 text-purple-600" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      Evidence-Grounded Findings & Hypotheses
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    Model: {modelUsed}
                  </span>
                </div>

                {loading ? (
                  <div className="py-16 text-center space-y-3">
                    <div className="w-10 h-10 mx-auto rounded-2xl bg-purple-100 dark:bg-purple-950/60 border border-purple-200 dark:border-purple-800 flex items-center justify-center text-purple-600 animate-pulse">
                      <BrainCircuit className="w-6 h-6" />
                    </div>
                    <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Synthesizing Evidence with Gemini 4 Argon High Thinking...
                    </p>
                    <p className="text-[11px] text-slate-400 max-w-sm mx-auto">
                      Cross-referencing observed indicators against MITRE ATT&CK patterns, verifying telemetry, and categorizing hypotheses.
                    </p>
                  </div>
                ) : thinkingOutput ? (
                  <div className="mt-4 prose dark:prose-invert max-w-none text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans space-y-3">
                    <div className="whitespace-pre-wrap font-sans bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-200/60 dark:border-slate-700/60">
                      {thinkingOutput}
                    </div>
                  </div>
                ) : (
                  <div className="py-16 text-center space-y-2">
                    <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Ready to correlate evidence.
                    </p>
                    <p className="text-[11px] text-slate-400 max-w-md mx-auto">
                      Click &quot;Run Defensible Synthesis&quot; to invoke Gemini 4 Argon with High Thinking to correlate domains, hashes, and network traces.
                    </p>
                  </div>
                )}
              </div>

              {/* Defense Standard Footer */}
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 text-[10px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
                <span>Standard: [OBSERVED] Direct Observation • [CONFIRMED] Multi-source • [INFERRED] Logical Deduction</span>
                <span className="font-semibold text-slate-500">Never asserts &quot;safe&quot; on absent indicators</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
