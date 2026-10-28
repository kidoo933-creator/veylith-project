import React, { useState, useEffect } from 'react';
import { ViewTab, CaseRecord, SeverityLevel } from './types';
import {
  getStoredCases,
  saveCases,
  getActiveCaseId,
  setActiveCaseId,
  createCase,
  addEvidenceToCase,
  addNoteToCase,
  updateCaseStatus,
  deleteCase,
  INITIAL_CASES,
} from './utils/storage';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { MobileFrame } from './components/MobileFrame';
import { OverviewView } from './views/OverviewView';
import { DomainIntelView } from './views/DomainIntelView';
import { FileForensicsView } from './views/FileForensicsView';
import { PcapLabView } from './views/PcapLabView';
import { WorkspaceView } from './views/WorkspaceView';
import { VulnerabilityIntelView } from './views/VulnerabilityIntelView';
import { AiAnalysisView } from './views/AiAnalysisView';
import { ReportsView } from './views/ReportsView';
import { DataSourcesView } from './views/DataSourcesView';
import { SettingsView } from './views/SettingsView';
import { AndroidProjectView } from './views/AndroidProjectView';
import {
  LayoutDashboard,
  Globe,
  FileSearch,
  GitBranch,
  ShieldAlert,
  Sparkles,
  FileCheck,
  CheckCircle,
  Smartphone,
  Monitor,
  Menu,
  X,
} from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<ViewTab>('overview');
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [activeCaseId, setActiveCase] = useState<string>('#VY-2025-0047');
  const [isDark, setIsDark] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'desktop' | 'mobile'>('desktop');
  const [searchQuery, setSearchQuery] = useState('');
  const [notification, setNotification] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Initialize data and dark mode
  useEffect(() => {
    const stored = getStoredCases();
    setCases(stored);
    const active = getActiveCaseId();
    setActiveCase(active);

    // Check system preference or saved
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (prefersDark) {
      setIsDark(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  const toggleTheme = () => {
    setIsDark((prev) => {
      const next = !prev;
      if (next) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      return next;
    });
  };

  const showToast = (message: string) => {
    setNotification(message);
    setTimeout(() => {
      setNotification(null);
    }, 3500);
  };

  const handleCreateCase = (data: {
    title: string;
    description: string;
    priority: SeverityLevel;
    leadAnalyst: string;
    scope: string[];
    tags: string[];
  }) => {
    const created = createCase(data);
    setCases(getStoredCases());
    setActiveCase(created.id);
    showToast(`Case ${created.id} initialized successfully.`);
  };

  const handleAttachEvidence = (
    name: string,
    type: 'domain' | 'ip' | 'file' | 'hash' | 'cve' | 'pcap' | 'header' | 'finding',
    value: string,
    notes: string
  ) => {
    try {
      addEvidenceToCase(activeCaseId, {
        name,
        type,
        value,
        confidence: 'Observed',
        source: 'Veylith Core Telemetry',
        notes,
      });
      setCases(getStoredCases());
      showToast(`Attached ${type.toUpperCase()} evidence to case ${activeCaseId}.`);
    } catch (err: any) {
      showToast(`Error: ${err.message}`);
    }
  };

  const handleUpdateCaseStatus = (caseId: string, status: CaseRecord['status']) => {
    updateCaseStatus(caseId, status);
    setCases(getStoredCases());
    showToast(`Case ${caseId} updated to ${status}.`);
  };

  const handleAddNote = (caseId: string, author: string, text: string) => {
    addNoteToCase(caseId, author, text);
    setCases(getStoredCases());
    showToast('Analyst note saved to immutable audit trail.');
  };

  const handleDeleteCase = (caseId: string) => {
    deleteCase(caseId);
    const updated = getStoredCases();
    setCases(updated);
    if (updated.length > 0) {
      setActiveCase(updated[0].id);
      setActiveCaseId(updated[0].id);
    }
    showToast(`Case ${caseId} removed.`);
  };

  const handleResetDatabase = () => {
    saveCases(INITIAL_CASES);
    setCases(INITIAL_CASES);
    setActiveCase(INITIAL_CASES[0].id);
    setActiveCaseId(INITIAL_CASES[0].id);
    showToast('Database reset to baseline verified intelligence.');
  };

  // Render the core view content
  const renderViewContent = () => {
    switch (currentTab) {
      case 'overview':
        return (
          <OverviewView
            cases={cases}
            onNavigate={(tab) => setCurrentTab(tab)}
            onSelectCase={(id) => {
              setActiveCase(id);
              setActiveCaseId(id);
            }}
            onCreateCase={handleCreateCase}
          />
        );
      case 'domain-intel':
        return (
          <DomainIntelView
            onAttachEvidence={handleAttachEvidence}
            activeCaseId={activeCaseId}
          />
        );
      case 'file-forensics':
        return (
          <FileForensicsView
            onAttachEvidence={handleAttachEvidence}
            activeCaseId={activeCaseId}
          />
        );
      case 'pcap-lab':
        return (
          <PcapLabView
            onAttachEvidence={handleAttachEvidence}
            activeCaseId={activeCaseId}
          />
        );
      case 'investigation-workspace':
        return (
          <WorkspaceView
            cases={cases}
            activeCaseId={activeCaseId}
            onSelectCase={(id) => {
              setActiveCase(id);
              setActiveCaseId(id);
            }}
            onUpdateStatus={handleUpdateCaseStatus}
            onAddNote={handleAddNote}
            onDeleteCase={handleDeleteCase}
            onNavigateToReport={(id) => {
              setActiveCase(id);
              setCurrentTab('reports');
            }}
          />
        );
      case 'vulnerability-intel':
        return (
          <VulnerabilityIntelView
            onAttachEvidence={handleAttachEvidence}
            activeCaseId={activeCaseId}
          />
        );
      case 'ai-analysis':
        return <AiAnalysisView cases={cases} activeCaseId={activeCaseId} />;
      case 'reports':
        return <ReportsView cases={cases} activeCaseId={activeCaseId} />;
      case 'data-sources':
        return <DataSourcesView />;
      case 'settings':
        return (
          <SettingsView
            isDark={isDark}
            onToggleTheme={toggleTheme}
            cases={cases}
            onResetDatabase={handleResetDatabase}
          />
        );
      case 'android-project':
        return <AndroidProjectView />;
      default:
        return (
          <OverviewView
            cases={cases}
            onNavigate={(tab) => setCurrentTab(tab)}
            onSelectCase={(id) => setActiveCase(id)}
            onCreateCase={handleCreateCase}
          />
        );
    }
  };

  return (
    <div className={`min-h-screen bg-[#F5F7FA] dark:bg-[#0B132B] text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-200`}>
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        onNavigate={(tab) => setCurrentTab(tab)}
        isDark={isDark}
        onToggleTheme={toggleTheme}
        viewMode={viewMode}
        onToggleViewMode={() => setViewMode((m) => (m === 'desktop' ? 'mobile' : 'desktop'))}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
      />

      {/* Toast Notification Banner */}
      {notification && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white dark:bg-white dark:text-slate-900 text-xs font-semibold px-4 py-3 rounded-xl shadow-2xl flex items-center gap-2 border border-slate-700 dark:border-slate-200 animate-in slide-in-from-bottom duration-200">
          <CheckCircle className="w-4 h-4 text-teal-400 dark:text-teal-600" />
          <span>{notification}</span>
        </div>
      )}

      {/* Main Layout Area */}
      {viewMode === 'desktop' ? (
        <div className="flex-1 flex overflow-hidden">
          {/* Desktop Sidebar */}
          <div className="hidden lg:block">
            <Sidebar
              currentTab={currentTab}
              onNavigate={(tab) => setCurrentTab(tab)}
              caseCount={cases.length}
            />
          </div>

          {/* Main Desktop Content */}
          <main className="flex-1 overflow-y-auto p-4 md:p-8 max-w-7xl mx-auto w-full">
            {renderViewContent()}
          </main>
        </div>
      ) : (
        /* Android Native Mobile Simulator Mode */
        <div className="flex-1 flex flex-col items-center justify-center p-2 sm:p-4">
          <div className="text-center mb-2">
            <span className="text-xs font-bold text-teal-600 dark:text-teal-400 uppercase tracking-widest">
              Android Native Experience Simulator (Material 3)
            </span>
          </div>

          <MobileFrame isDark={isDark}>
            {/* Mobile Inset Header */}
            <div className="px-4 py-3 bg-white dark:bg-slate-900 border-b border-slate-200/80 dark:border-slate-800 flex items-center justify-between sticky top-0 z-30">
              <div className="flex items-center gap-2">
                <img
                  src="/assets/aistudio/veylith_logo_1c2c3d90.png"
                  alt="Veylith"
                  className="w-6 h-6 rounded-md"
                />
                <span className="font-extrabold text-sm tracking-wider text-slate-900 dark:text-white font-mono">
                  VEYLITH
                </span>
              </div>
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300"
              >
                {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </button>
            </div>

            {/* Mobile Dropdown Menu if expanded */}
            {mobileMenuOpen && (
              <div className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 p-2 grid grid-cols-2 gap-1 text-xs">
                {[
                  { id: 'overview', label: 'Dashboard' },
                  { id: 'domain-intel', label: 'Domain Intel' },
                  { id: 'file-forensics', label: 'Evidence Lab' },
                  { id: 'pcap-lab', label: 'PCAP Lab' },
                  { id: 'investigation-workspace', label: 'Workspace' },
                  { id: 'vulnerability-intel', label: 'Vulnerabilities' },
                  { id: 'ai-analysis', label: 'AI Investigation' },
                  { id: 'reports', label: 'Reports' },
                  { id: 'data-sources', label: 'Data Sources' },
                  { id: 'android-project', label: 'Android Code' },
                  { id: 'settings', label: 'Settings' },
                ].map((item) => (
                  <button
                    key={item.id}
                    onClick={() => {
                      setCurrentTab(item.id as ViewTab);
                      setMobileMenuOpen(false);
                    }}
                    className={`p-2 rounded-lg text-left truncate font-medium ${
                      currentTab === item.id
                        ? 'bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-300 font-bold'
                        : 'text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            )}

            {/* Content inside Mobile Scroll Container */}
            <div className="p-3.5 space-y-4 flex-1">
              {renderViewContent()}
            </div>

            {/* Material 3 Mobile Bottom Navigation Bar */}
            <div className="h-16 bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 flex items-center justify-around px-2 sticky bottom-0 z-30 select-none">
              <button
                onClick={() => setCurrentTab('overview')}
                className={`flex flex-col items-center gap-1 text-[10px] font-medium transition ${
                  currentTab === 'overview'
                    ? 'text-teal-600 dark:text-teal-400 font-bold'
                    : 'text-slate-400'
                }`}
              >
                <LayoutDashboard className="w-4 h-4" />
                <span>Home</span>
              </button>
              <button
                onClick={() => setCurrentTab('investigation-workspace')}
                className={`flex flex-col items-center gap-1 text-[10px] font-medium transition ${
                  currentTab === 'investigation-workspace'
                    ? 'text-teal-600 dark:text-teal-400 font-bold'
                    : 'text-slate-400'
                }`}
              >
                <GitBranch className="w-4 h-4" />
                <span>Cases</span>
              </button>
              <button
                onClick={() => setCurrentTab('domain-intel')}
                className={`flex flex-col items-center gap-1 text-[10px] font-medium transition ${
                  currentTab === 'domain-intel'
                    ? 'text-teal-600 dark:text-teal-400 font-bold'
                    : 'text-slate-400'
                }`}
              >
                <Globe className="w-4 h-4" />
                <span>Domains</span>
              </button>
              <button
                onClick={() => setCurrentTab('ai-analysis')}
                className={`flex flex-col items-center gap-1 text-[10px] font-medium transition ${
                  currentTab === 'ai-analysis'
                    ? 'text-purple-600 dark:text-purple-400 font-bold'
                    : 'text-slate-400'
                }`}
              >
                <Sparkles className="w-4 h-4" />
                <span>AI</span>
              </button>
              <button
                onClick={() => setCurrentTab('settings')}
                className={`flex flex-col items-center gap-1 text-[10px] font-medium transition ${
                  currentTab === 'settings'
                    ? 'text-teal-600 dark:text-teal-400 font-bold'
                    : 'text-slate-400'
                }`}
              >
                <Smartphone className="w-4 h-4" />
                <span>More</span>
              </button>
            </div>
          </MobileFrame>
        </div>
      )}
    </div>
  );
}
