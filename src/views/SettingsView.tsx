import React, { useState } from 'react';
import {
  Settings,
  Shield,
  Sun,
  Moon,
  Trash2,
  Download,
  AlertTriangle,
  Lock,
  CheckCircle,
  HardDrive,
  FileCode,
} from 'lucide-react';
import { CaseRecord } from '../types';

interface SettingsViewProps {
  isDark: boolean;
  onToggleTheme: () => void;
  cases: CaseRecord[];
  onResetDatabase: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  isDark,
  onToggleTheme,
  cases,
  onResetDatabase,
}) => {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const exportAllData = () => {
    const data = {
      app: 'VEYLITH',
      version: '2.4.0',
      exportedAt: new Date().toISOString(),
      cases,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Veylith_Full_Backup_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-teal-600" />
          Settings, Policy & Privacy Standards
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Enterprise configuration, SSRF destination rules, and local forensics data management.
        </p>
      </div>

      {/* Theme Settings */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4 text-xs">
        <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
          {isDark ? <Moon className="w-4 h-4 text-purple-400" /> : <Sun className="w-4 h-4 text-amber-500" />}
          Interface Theme & Display
        </h3>
        <p className="text-slate-500 dark:text-slate-400">
          Veylith uses a restrained enterprise cybersecurity palette (Canvas #F5F7FA, Surface #FFFFFF, Primary Navy #172B4D, Accent Teal #0D9488) and an optional dark SOC console theme.
        </p>
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleTheme}
            className="px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold rounded-xl transition flex items-center gap-2"
          >
            {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-slate-600" />}
            <span>Toggle to {isDark ? 'Light Enterprise' : 'Dark SOC'} Mode</span>
          </button>
        </div>
      </div>

      {/* SSRF Protection Policy */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4 text-xs">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-teal-600" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Mandatory SSRF Policy & Network Boundaries
          </h3>
        </div>
        <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
          To prevent Server-Side Request Forgery and unauthorized internal reconnaissance, Veylith enforces strict automated network guards prior to executing any probe:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-[11px]">
          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700 space-y-1">
            <span className="font-bold text-red-600 dark:text-red-400">Prohibited IPv4 Destinations</span>
            <ul className="text-slate-500 space-y-0.5">
              <li>• 127.0.0.0/8 (Loopback / Localhost)</li>
              <li>• 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Private)</li>
              <li>• 169.254.0.0/16 (Link-Local & Cloud Metadata)</li>
              <li>• 224.0.0.0/4 (Multicast), 240.0.0.0/4 (Reserved)</li>
            </ul>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/60 dark:border-slate-700 space-y-1">
            <span className="font-bold text-red-600 dark:text-red-400">Prohibited IPv6 & Internal Domains</span>
            <ul className="text-slate-500 space-y-0.5">
              <li>• ::1, :: (IPv6 Loopback / Unspecified)</li>
              <li>• fe80::/10 (Link-Local)</li>
              <li>• fc00::/7, fd00:: (Unique Local Addresses)</li>
              <li>• *.internal, *.local, metadata.google.internal</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Local Forensics Storage & Data Controls */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4 text-xs">
        <div className="flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-teal-600" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Local Storage & Case Management Database
          </h3>
        </div>
        <p className="text-slate-600 dark:text-slate-300">
          Cases, evidence, and audit logs are persisted securely in local browser storage (IndexedDB/localStorage). Current database contains <span className="font-bold font-mono text-slate-900 dark:text-white">{cases.length} cases</span>.
        </p>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={exportAllData}
            className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-semibold rounded-xl transition shadow-xs flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Complete Backup (JSON)</span>
          </button>

          {!confirmDelete ? (
            <button
              onClick={() => setConfirmDelete(true)}
              className="px-4 py-2 bg-red-50 hover:bg-red-100 dark:bg-red-950/60 dark:hover:bg-red-900/60 text-red-700 dark:text-red-300 font-semibold rounded-xl border border-red-200 dark:border-red-800 transition flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Reset / Wipe Local Database</span>
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  onResetDatabase();
                  setConfirmDelete(false);
                }}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-bold rounded-xl transition shadow-xs"
              >
                Confirm Wipe
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="px-3 py-2 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 font-medium"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Privacy Pledge */}
      <div className="p-4 bg-teal-50/60 dark:bg-teal-950/30 border border-teal-200 dark:border-teal-800 rounded-2xl text-xs space-y-2 text-slate-700 dark:text-slate-300">
        <div className="flex items-center gap-2 font-bold text-teal-900 dark:text-teal-200">
          <Lock className="w-4 h-4 text-teal-600" />
          <span>Veylith Privacy & Operational Security Standard</span>
        </div>
        <p className="leading-relaxed">
          Default to local processing: File binaries, private network logs, and proprietary case notes are processed client-side without transmission to third-party services. Network queries are transparently visible and auditable.
        </p>
      </div>
    </div>
  );
};
