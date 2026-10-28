import React from 'react';
import { ViewTab } from '../types';
import {
  LayoutDashboard,
  Globe,
  FileSearch,
  Network,
  GitBranch,
  ShieldAlert,
  Sparkles,
  FileCheck,
  Database,
  Settings,
  Code2,
} from 'lucide-react';

interface SidebarProps {
  currentTab: ViewTab;
  onNavigate: (tab: ViewTab) => void;
  caseCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onNavigate, caseCount }) => {
  const navItems: { id: ViewTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    {
      id: 'overview',
      label: 'Command Center',
      icon: <LayoutDashboard className="w-4 h-4" />,
    },
    {
      id: 'domain-intel',
      label: 'Domain Intelligence',
      icon: <Globe className="w-4 h-4" />,
    },
    {
      id: 'file-forensics',
      label: 'Evidence Lab',
      icon: <FileSearch className="w-4 h-4" />,
    },
    {
      id: 'pcap-lab',
      label: 'PCAP Lab',
      icon: <Network className="w-4 h-4" />,
    },
    {
      id: 'investigation-workspace',
      label: 'Investigation Workspace',
      icon: <GitBranch className="w-4 h-4" />,
      badge: String(caseCount),
    },
    {
      id: 'vulnerability-intel',
      label: 'Vulnerability Intelligence',
      icon: <ShieldAlert className="w-4 h-4" />,
    },
    {
      id: 'ai-analysis',
      label: 'AI Investigation',
      icon: <Sparkles className="w-4 h-4 text-purple-500" />,
      badge: 'Thinking',
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: <FileCheck className="w-4 h-4" />,
    },
    {
      id: 'data-sources',
      label: 'Data Sources',
      icon: <Database className="w-4 h-4" />,
    },
    {
      id: 'android-project',
      label: 'Android Native & APK',
      icon: <Code2 className="w-4 h-4 text-teal-600 dark:text-teal-400" />,
      badge: 'Kotlin',
    },
    {
      id: 'settings',
      label: 'Settings & Privacy',
      icon: <Settings className="w-4 h-4" />,
    },
  ];

  return (
    <aside className="w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col justify-between p-3 select-none transition-colors">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-bold tracking-wider uppercase text-slate-400 dark:text-slate-500">
          Navigation
        </div>

        {navItems.map((item) => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                isActive
                  ? 'bg-teal-50 dark:bg-teal-950/70 text-teal-700 dark:text-teal-300 font-semibold shadow-xs border border-teal-200/60 dark:border-teal-800/80'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <span className={isActive ? 'text-teal-600 dark:text-teal-400' : 'text-slate-400 dark:text-slate-500'}>
                  {item.icon}
                </span>
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    item.badge === 'Thinking'
                      ? 'bg-purple-100 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800'
                      : item.badge === 'Kotlin'
                      ? 'bg-teal-100 dark:bg-teal-950/80 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer System Info */}
      <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200/80 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
        <div className="flex items-center justify-between font-semibold text-slate-700 dark:text-slate-300">
          <span>VEYLITH v2.4</span>
          <span className="text-[10px] text-teal-600 dark:text-teal-400 font-mono">STABLE</span>
        </div>
        <p className="text-[10px] text-slate-400 leading-snug">
          SSRF Guard Active • Zero Dynamic Execution
        </p>
      </div>
    </aside>
  );
};
