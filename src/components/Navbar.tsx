import React from 'react';
import { ViewTab } from '../types';
import {
  Search,
  Bell,
  Sun,
  Moon,
  Smartphone,
  Monitor,
  ShieldCheck,
  CheckCircle2,
  Sparkles,
} from 'lucide-react';

interface NavbarProps {
  currentTab: ViewTab;
  onNavigate: (tab: ViewTab) => void;
  isDark: boolean;
  onToggleTheme: () => void;
  viewMode: 'desktop' | 'mobile';
  onToggleViewMode: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  isDark,
  onToggleTheme,
  viewMode,
  onToggleViewMode,
  searchQuery,
  onSearchChange,
  onNavigate,
}) => {
  return (
    <header className="h-16 px-4 md:px-6 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4 sticky top-0 z-30 transition-colors">
      {/* Brand & Mobile Hamburger */}
      <div className="flex items-center gap-3">
        <div
          onClick={() => onNavigate('overview')}
          className="flex items-center gap-2.5 cursor-pointer group select-none"
        >
          <img
            src="/assets/aistudio/veylith_logo_1c2c3d90.png"
            alt="Veylith"
            className="w-8 h-8 rounded-lg shadow-sm group-hover:scale-105 transition-transform"
          />
          <div className="hidden sm:block">
            <span className="font-extrabold text-lg tracking-wider text-slate-900 dark:text-white flex items-center gap-1.5 font-mono">
              VEYLITH
              <span className="text-[10px] font-sans font-semibold px-1.5 py-0.2 bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-400 border border-teal-200 dark:border-teal-800 rounded">
                DFIR
              </span>
            </span>
          </div>
        </div>
      </div>

      {/* Global Search Bar */}
      <div className="flex-1 max-w-xl mx-2">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search domains, files, hashes, IPs, or CVEs..."
            className="w-full pl-9 pr-4 py-2 text-xs md:text-sm bg-slate-100/80 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500 transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Right Controls: Device Mode Toggle, Theme, Notifications, Analyst Profile */}
      <div className="flex items-center gap-2 md:gap-3">
        {/* Device Mode Switcher */}
        <div className="hidden lg:flex items-center bg-slate-100 dark:bg-slate-800 p-0.5 rounded-xl border border-slate-200 dark:border-slate-700">
          <button
            onClick={() => {
              if (viewMode !== 'desktop') onToggleViewMode();
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg transition ${
              viewMode === 'desktop'
                ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
            title="Desktop SOC Console"
          >
            <Monitor className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
            <span>SOC View</span>
          </button>
          <button
            onClick={() => {
              if (viewMode !== 'mobile') onToggleViewMode();
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg transition ${
              viewMode === 'mobile'
                ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
            title="Android Native App Simulator"
          >
            <Smartphone className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
            <span>Android Mode</span>
          </button>
        </div>

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="p-2 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
          title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
        >
          {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
        </button>

        {/* System Online Badge */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 font-medium bg-emerald-50 dark:bg-emerald-950/40 px-2.5 py-1 rounded-full border border-emerald-200 dark:border-emerald-800">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>System Online</span>
        </div>

        {/* AI Copilot Quick Launcher */}
        <button
          onClick={() => onNavigate('ai-analysis')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-50 hover:bg-purple-100 dark:bg-purple-950/60 dark:hover:bg-purple-900/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 text-xs font-semibold transition shadow-xs"
          title="Open Gemini Forensics Chat"
        >
          <Sparkles className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
          <span className="hidden md:inline">AI Copilot</span>
        </button>

        {/* Notification Bell */}
        <button
          onClick={() => onNavigate('investigation-workspace')}
          className="relative p-2 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
          title="Investigation Alerts"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-teal-500" />
        </button>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2 pl-1 border-l border-slate-200 dark:border-slate-800">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-teal-600 to-blue-600 flex items-center justify-center text-white font-semibold text-xs shadow-xs">
            AC
          </div>
          <div className="hidden xl:block text-left">
            <p className="text-xs font-semibold text-slate-900 dark:text-white leading-tight">Alex Carter</p>
            <p className="text-[10px] text-slate-500 dark:text-slate-400">Security Analyst</p>
          </div>
        </div>
      </div>
    </header>
  );
};
