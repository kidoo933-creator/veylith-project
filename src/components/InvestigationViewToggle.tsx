import React from 'react';
import { InvestigationViewMode } from '../types';
import { Sparkles, Terminal, Shield, Cpu, ChevronRight, Activity } from 'lucide-react';

interface InvestigationViewToggleProps {
  mode: InvestigationViewMode;
  onChange: (mode: InvestigationViewMode) => void;
  simpleLabel?: string;
  deepLabel?: string;
  simpleDescription?: string;
  deepDescription?: string;
  findingCounts?: {
    concerns?: number;
    technicalItems?: number;
  };
  className?: string;
}

export const InvestigationViewToggle: React.FC<InvestigationViewToggleProps> = ({
  mode,
  onChange,
  simpleLabel = 'Simple Results',
  deepLabel = 'Deep Analysis',
  simpleDescription = 'Human-Readable Analyst Report',
  deepDescription = 'Raw Evidence & Deep Telemetry',
  findingCounts,
  className = '',
}) => {
  return (
    <div
      className={`bg-white dark:bg-slate-900 border border-slate-200/90 dark:border-slate-800 rounded-2xl p-2.5 shadow-xs ${className}`}
      role="region"
      aria-label="Investigation view mode selector"
    >
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Context Information */}
        <div className="flex items-center gap-2.5 px-1.5">
          <div className="w-8 h-8 rounded-xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200/80 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400 shrink-0">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                Investigation Perspective
              </span>
              <span className="text-[10px] text-teal-600 dark:text-teal-400 font-semibold bg-teal-50 dark:bg-teal-950/60 border border-teal-200/70 dark:border-teal-800/80 px-2 py-0.5 rounded-full">
                Instant Toggle
              </span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              {mode === 'simple'
                ? 'Plain-English cybersecurity executive briefing'
                : 'Raw telemetry, byte inspector, and granular forensic records'}
            </p>
          </div>
        </div>

        {/* Segmented Switch Buttons */}
        <div
          role="tablist"
          aria-label="View Mode"
          className="flex items-center bg-slate-100/90 dark:bg-slate-950/80 p-1 rounded-xl border border-slate-200 dark:border-slate-800/90"
        >
          {/* Simple Results Button */}
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'simple'}
            onClick={() => onChange('simple')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all duration-150 ${
              mode === 'simple'
                ? 'bg-white dark:bg-slate-800 text-teal-700 dark:text-teal-300 shadow-xs border border-slate-200/80 dark:border-slate-700'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-white/40 dark:hover:bg-slate-800/40'
            }`}
          >
            <Sparkles
              className={`w-3.5 h-3.5 ${
                mode === 'simple' ? 'text-teal-600 dark:text-teal-400' : 'text-slate-400'
              }`}
            />
            <div className="flex flex-col text-left leading-tight">
              <span className="font-bold">{simpleLabel}</span>
              <span className="text-[9px] text-slate-400 font-normal hidden md:inline">
                Plain English
              </span>
            </div>
            {findingCounts?.concerns !== undefined && findingCounts.concerns > 0 && (
              <span
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full ml-1 ${
                  mode === 'simple'
                    ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                    : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                }`}
              >
                {findingCounts.concerns} {findingCounts.concerns === 1 ? 'flag' : 'flags'}
              </span>
            )}
          </button>

          {/* Deep Analysis Button */}
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'deep'}
            onClick={() => onChange('deep')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all duration-150 ${
              mode === 'deep'
                ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-blue-300 shadow-xs border border-slate-200/80 dark:border-slate-700'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-white/40 dark:hover:bg-slate-800/40'
            }`}
          >
            <Terminal
              className={`w-3.5 h-3.5 ${
                mode === 'deep' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400'
              }`}
            />
            <div className="flex flex-col text-left leading-tight">
              <span className="font-bold">{deepLabel}</span>
              <span className="text-[9px] text-slate-400 font-normal hidden md:inline">
                Technical Raw
              </span>
            </div>
            {findingCounts?.technicalItems !== undefined && findingCounts.technicalItems > 0 && (
              <span
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full ml-1 ${
                  mode === 'deep'
                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                    : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                }`}
              >
                {findingCounts.technicalItems}
              </span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
