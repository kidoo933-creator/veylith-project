import React, { useState } from 'react';
import { FileAnalysisResult } from '../types';
import { analyzeFile, MAX_FILE_SIZE_BYTES } from '../utils/forensics';
import {
  Upload,
  FileText,
  ShieldAlert,
  Hash,
  Binary,
  Layers,
  AlertTriangle,
  CheckCircle,
  Copy,
  Plus,
  Eye,
  Info,
  Activity,
  Terminal,
  ShieldCheck,
  ShieldX,
  Lock,
  Code2,
  FileCode,
  FolderArchive,
  BarChart2,
} from 'lucide-react';

interface FileForensicsViewProps {
  onAttachEvidence: (name: string, type: 'file' | 'hash' | 'finding', value: string, notes: string) => void;
  activeCaseId: string;
}

type ForensicsTab = 'summary' | 'metadata' | 'entropy' | 'strings' | 'apk' | 'unavailable';

export const FileForensicsView: React.FC<FileForensicsViewProps> = ({ onAttachEvidence, activeCaseId }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ForensicsTab>('summary');
  const [stringFilter, setStringFilter] = useState<'all' | 'url' | 'ip' | 'api' | 'command' | 'registry' | 'path'>('all');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [result, setResult] = useState<FileAnalysisResult | null>(null);

  const handleFileDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  const processFile = async (file: File) => {
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const res = await analyzeFile(file);
      setResult(res);
      // Auto switch to APK tab if it's an APK
      if (res.apkDetails?.isApk) {
        setActiveTab('apk');
      } else {
        setActiveTab('summary');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Forensic analysis failed.');
    } finally {
      setAnalyzing(false);
    }
  };

  // Preset sample testing files with authentic magic bytes
  const loadSyntheticSample = async (type: 'disguised-pdf' | 'sample-apk' | 'linux-elf' | 'clean-doc') => {
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      let mockFile: File;
      if (type === 'disguised-pdf') {
        // Create bytes that have MZ header but .pdf extension!
        const b = new Uint8Array(2048);
        b[0] = 0x4d; // M
        b[1] = 0x5a; // Z
        b[0x3c] = 0x80; // PE offset at 128
        b[128] = 0x50; // P
        b[129] = 0x45; // E
        b[130] = 0x00;
        b[131] = 0x00;
        b[132] = 0x64; // AMD64
        b[133] = 0x86;
        b[134] = 0x03; // 3 sections
        const text = 'MZ\x90\x00 VirtualAlloc CreateRemoteThread WriteProcessMemory powershell -enc JABzACAAPQAgAE5ldw... https://c2-stager.cc/beacon.bin HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
        for (let i = 0; i < text.length; i++) b[i + 200] = text.charCodeAt(i);
        mockFile = new File([b], 'Quarterly_Tax_Statement.pdf', { type: 'application/pdf' });
      } else if (type === 'sample-apk') {
        const b = new Uint8Array(4096);
        b[0] = 0x50; // P
        b[1] = 0x4b; // K
        b[2] = 0x03;
        b[3] = 0x04;
        const text = 'PK\x03\x04 AndroidManifest.xml classes.dex classes2.dex META-INF/CERT.RSA lib/arm64-v8a/libnative.so android.permission.INTERNET android.permission.READ_SMS android.permission.RECORD_AUDIO android.permission.SYSTEM_ALERT_WINDOW android.permission.REQUEST_INSTALL_PACKAGES android:debuggable="true"';
        for (let i = 0; i < text.length; i++) b[i + 50] = text.charCodeAt(i);
        mockFile = new File([b], 'banking_security_token.apk', { type: 'application/vnd.android.package-archive' });
      } else if (type === 'linux-elf') {
        const b = new Uint8Array(2048);
        b[0] = 0x7f;
        b[1] = 0x45; // E
        b[2] = 0x4c; // L
        b[3] = 0x46; // F
        b[4] = 2; // 64-bit
        b[5] = 1; // Little-endian
        b[7] = 3; // Linux ABI
        b[16] = 2; // ET_EXEC
        const text = '/bin/bash mprotect ptrace execve socket connect /tmp/.dropper_lock http://198.51.100.12/stage2';
        for (let i = 0; i < text.length; i++) b[i + 100] = text.charCodeAt(i);
        mockFile = new File([b], 'kworker_daemon.elf', { type: 'application/octet-stream' });
      } else {
        const b = new Uint8Array(1024);
        b[0] = 0x25; // %
        b[1] = 0x50; // P
        b[2] = 0x44; // D
        b[3] = 0x46; // F
        b[4] = 0x2d; // -
        b[5] = 0x31; // 1
        b[6] = 0x2e; // .
        b[7] = 0x37; // 7
        const text = '%PDF-1.7 standard documentation text content without active macros, javascript, or embedded payloads.';
        for (let i = 0; i < text.length; i++) b[i + 20] = text.charCodeAt(i);
        mockFile = new File([b], 'security_baseline_policy.pdf', { type: 'application/pdf' });
      }

      const res = await analyzeFile(mockFile);
      setResult(res);
      if (type === 'sample-apk') setActiveTab('apk');
      else setActiveTab('summary');
    } finally {
      setAnalyzing(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const filteredStrings = result?.printableStrings.extracted.filter((s) => {
    if (stringFilter === 'all') return true;
    return s.category === stringFilter;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Header & File Picker Zone */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Binary className="w-5 h-5 text-purple-600" />
              Evidence Lab & Static File Forensics
            </h1>
            <p className="text-xs text-slate-400">
              Deterministic file hashing, magic byte verification, bounded strings, Shannon entropy estimates, and APK inspection.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Test Artifacts:</span>
            <button
              onClick={() => loadSyntheticSample('disguised-pdf')}
              className="px-2.5 py-1 rounded-lg bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-medium hover:bg-red-100 transition"
            >
              Disguised PE (.pdf)
            </button>
            <button
              onClick={() => loadSyntheticSample('sample-apk')}
              className="px-2.5 py-1 rounded-lg bg-teal-50 dark:bg-teal-950/60 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800 font-medium hover:bg-teal-100 transition"
            >
              Android .APK
            </button>
            <button
              onClick={() => loadSyntheticSample('linux-elf')}
              className="px-2.5 py-1 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-medium hover:bg-blue-100 transition"
            >
              Linux .ELF
            </button>
            <button
              onClick={() => loadSyntheticSample('clean-doc')}
              className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 font-medium hover:bg-slate-200 transition"
            >
              Clean PDF
            </button>
          </div>
        </div>

        {/* Drag and Drop Zone */}
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleFileDrop}
          className="relative border-2 border-dashed border-slate-300 dark:border-slate-700 hover:border-teal-500 dark:hover:border-teal-400 rounded-2xl p-8 text-center transition bg-slate-50/50 dark:bg-slate-950/40 flex flex-col items-center justify-center cursor-pointer group"
        >
          <input
            type="file"
            onChange={handleFileInput}
            className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
          />
          <div className="w-12 h-12 rounded-2xl bg-teal-50 dark:bg-teal-950/80 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400 mb-3 group-hover:scale-110 transition-transform">
            <Upload className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-1">
            Drag & drop suspect file here, or click to browse
          </p>
          <p className="text-xs text-slate-400 max-w-md">
            Max file size: <span className="font-semibold text-slate-600 dark:text-slate-300">50 MB</span>. Files remain strictly on-device. <span className="text-teal-600 dark:text-teal-400 font-semibold">Zero binary execution</span>.
          </p>
        </div>

        {/* Error Alert (e.g. Size Limit Exceeded) */}
        {errorMessage && (
          <div className="mt-4 p-4 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-3 text-xs text-red-700 dark:text-red-300">
            <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-sm">Forensic Safety Constraint Triggered</p>
              <p className="text-xs leading-relaxed mt-0.5">{errorMessage}</p>
            </div>
          </div>
        )}
      </div>

      {!result && !analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-3 shadow-xs">
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            No file currently loaded for inspection
          </p>
          <p className="text-[11px] text-slate-400 max-w-md mx-auto">
            Drag any local document, binary, archive, or script into the dropzone above, or click one of the sample presets to run genuine Web Crypto SHA-256/SHA-1 and Shannon entropy calculations.
          </p>
        </div>
      )}

      {analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-3 shadow-xs">
          <div className="w-8 h-8 border-2 border-teal-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            Computing cryptographic hashes, section headers, and Shannon entropy...
          </p>
        </div>
      )}

      {/* Analysis Results View */}
      {result && !analyzing && (
        <div className="space-y-6">
          {/* Target File Card */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-purple-50 dark:bg-purple-950/60 border border-purple-200 dark:border-purple-800 flex items-center justify-center text-purple-600 dark:text-purple-400">
                <FileText className="w-6 h-6" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base md:text-lg font-bold text-slate-900 dark:text-white font-mono">
                    {result.fileName}
                  </h2>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                    {result.fileSizeFormatted}
                  </span>
                  {result.formatMismatch ? (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300 dark:border-red-800 animate-pulse">
                      Masquerading Detected!
                    </span>
                  ) : (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                      Extension Aligned
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Detected Signature: <span className="font-semibold text-slate-700 dark:text-slate-200">{result.detectedFormat}</span> ({result.magicBytes})
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                onAttachEvidence(
                  result.fileName,
                  'file',
                  result.sha256,
                  `SHA-256: ${result.sha256}. Entropy: ${result.entropy}. Format: ${result.detectedFormat}`
                );
              }}
              className="flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
            >
              <Plus className="w-3.5 h-3.5 text-teal-600" />
              <span>Attach Hash to Case ({activeCaseId})</span>
            </button>
          </div>

          {/* Extension Mismatch Warning */}
          {result.formatMismatch && (
            <div className="p-4 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-2xl flex items-start gap-3 text-xs text-red-700 dark:text-red-300">
              <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-sm">Masquerading / Signature Mismatch Detected</p>
                <p className="text-xs leading-relaxed mt-1">{result.mismatchDescription}</p>
              </div>
            </div>
          )}

          {/* Sub Navigation Tabs */}
          <div className="flex items-center gap-1.5 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium overflow-x-auto select-none">
            <button
              onClick={() => setActiveTab('summary')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'summary'
                  ? 'bg-purple-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Hashes & Identification
            </button>
            <button
              onClick={() => setActiveTab('metadata')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'metadata'
                  ? 'bg-purple-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Structural Metadata
            </button>
            <button
              onClick={() => setActiveTab('entropy')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'entropy'
                  ? 'bg-purple-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Entropy Meter & Distribution ({result.entropy})
            </button>
            <button
              onClick={() => setActiveTab('strings')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'strings'
                  ? 'bg-purple-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Bounded Strings ({result.printableStrings.extracted.length})
            </button>
            {result.apkDetails && (
              <button
                onClick={() => setActiveTab('apk')}
                className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                  activeTab === 'apk'
                    ? 'bg-purple-600 text-white font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                APK Manifest & Permissions ({result.metadata?.apkMetadata?.permissions?.length || 0})
              </button>
            )}
            <button
              onClick={() => setActiveTab('unavailable')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 flex items-center gap-1 ${
                activeTab === 'unavailable'
                  ? 'bg-purple-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Unavailable Checks</span>
            </button>
          </div>

          {/* Tab 1: Hashes and File Identification */}
          {activeTab === 'summary' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Hashes Card */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Hash className="w-4 h-4 text-purple-600" />
                  Cryptographic Hashes
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                      <span>SHA-256 (Primary Court-Admissible Hash)</span>
                      <button
                        onClick={() => copyToClipboard(result.sha256, 'sha256')}
                        className="text-teal-600 hover:underline flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" />
                        <span>{copiedKey === 'sha256' ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="p-2.5 bg-slate-50 dark:bg-slate-800 rounded-xl font-mono text-[11px] text-slate-800 dark:text-slate-200 break-all select-all">
                      {result.sha256}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                      <span>SHA-1</span>
                      <button
                        onClick={() => copyToClipboard(result.sha1, 'sha1')}
                        className="text-teal-600 hover:underline flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" />
                        <span>{copiedKey === 'sha1' ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="p-2.5 bg-slate-50 dark:bg-slate-800 rounded-xl font-mono text-[11px] text-slate-800 dark:text-slate-200 break-all select-all">
                      {result.sha1}
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                      <span>MD5 (Legacy Triage Reference)</span>
                      <button
                        onClick={() => copyToClipboard(result.md5, 'md5')}
                        className="text-teal-600 hover:underline flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" />
                        <span>{copiedKey === 'md5' ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="p-2.5 bg-slate-50 dark:bg-slate-800 rounded-xl font-mono text-[11px] text-slate-800 dark:text-slate-200 break-all select-all">
                      {result.md5}
                    </div>
                  </div>
                </div>
              </div>

              {/* Identification & File Boundaries */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-purple-600" />
                  Format & Size Boundary Inspection
                </h3>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[11px] block">Magic Byte Hex</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200 text-sm">
                      {result.magicBytes}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[11px] block">Detected Format</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 text-xs truncate block">
                      {result.detectedFormat}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[11px] block">Actual File Size</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200 text-sm">
                      {result.fileSizeFormatted}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[11px] block">Memory Safety Limit</span>
                    <span className="font-semibold text-emerald-600 dark:text-emerald-400 text-xs">
                      50 MB Enforced
                    </span>
                  </div>
                </div>

                <div className="p-3 bg-teal-50/70 dark:bg-teal-950/40 border border-teal-200 dark:border-teal-800 rounded-xl text-[11px] text-teal-900 dark:text-teal-300 space-y-1">
                  <span className="font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                    Zero Dynamic Execution Guarantee
                  </span>
                  <p className="text-[10.5px] leading-relaxed">
                    This file was not launched, loaded into system process memory, or dynamically invoked. Analysis is purely static using Web Crypto and ArrayBuffer parsers.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Structural Metadata */}
          {activeTab === 'metadata' && (
            <div className="space-y-6">
              {/* If PE executable */}
              {result.metadata?.peMetadata && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Binary className="w-4 h-4 text-purple-600" />
                    PE Header & Section Details (Portable Executable)
                  </h3>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Target Architecture</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono">
                        {result.metadata.peMetadata.machine}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">PE Header Offset</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono">
                        0x{result.metadata.peMetadata.peHeaderOffset?.toString(16).toUpperCase()}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Compilation Date</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200 truncate block">
                        {result.metadata.peMetadata.compileTimestamp}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Section Count</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono">
                        {result.metadata.peMetadata.numberOfSections} Sections
                      </span>
                    </div>
                  </div>

                  {result.metadata.peMetadata.sections && result.metadata.peMetadata.sections.length > 0 && (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 text-[11px]">
                            <th className="py-2 px-3">Section Name</th>
                            <th className="py-2 px-3">Virtual Size</th>
                            <th className="py-2 px-3">Raw Size</th>
                            <th className="py-2 px-3">Section Entropy</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                          {result.metadata.peMetadata.sections.map((sec, idx) => (
                            <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                              <td className="py-2.5 px-3 font-bold text-teal-600 dark:text-teal-400">{sec.name}</td>
                              <td className="py-2.5 px-3 text-slate-600 dark:text-slate-300">{sec.virtualSize} bytes</td>
                              <td className="py-2.5 px-3 text-slate-600 dark:text-slate-300">{sec.rawSize} bytes</td>
                              <td className="py-2.5 px-3">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  sec.entropy > 7.2 ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300' : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                                }`}>
                                  {sec.entropy.toFixed(3)} bits/byte
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* If ELF binary */}
              {result.metadata?.elfMetadata && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-purple-600" />
                    ELF Binary Headers (Linux / Unix Executable)
                  </h3>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Bitness</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200">{result.metadata.elfMetadata.bitness}</span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Endianness</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200">{result.metadata.elfMetadata.endianness}</span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">OS ABI</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200">{result.metadata.elfMetadata.osAbi}</span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Object Type</span>
                      <span className="font-semibold text-slate-800 dark:text-slate-200">{result.metadata.elfMetadata.type}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* If PDF document */}
              {result.metadata?.pdfMetadata && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-purple-600" />
                    PDF Structural Elements & Action Indicators
                  </h3>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">PDF Version</span>
                      <span className="font-bold text-slate-800 dark:text-slate-200 font-mono">v{result.metadata.pdfMetadata.version}</span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Embedded JavaScript</span>
                      <span className={`font-bold text-xs ${result.metadata.pdfMetadata.hasJavaScript ? 'text-red-600 dark:text-red-400' : 'text-emerald-600'}`}>
                        {result.metadata.pdfMetadata.hasJavaScript ? 'DETECTED (/JS)' : 'None'}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Launch Actions</span>
                      <span className={`font-bold text-xs ${result.metadata.pdfMetadata.hasLaunchActions ? 'text-red-600 dark:text-red-400' : 'text-emerald-600'}`}>
                        {result.metadata.pdfMetadata.hasLaunchActions ? 'DETECTED (/Launch)' : 'None'}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                      <span className="text-slate-400 text-[10px] uppercase block">Embedded Files</span>
                      <span className={`font-bold text-xs ${result.metadata.pdfMetadata.hasEmbeddedFiles ? 'text-amber-600' : 'text-emerald-600'}`}>
                        {result.metadata.pdfMetadata.hasEmbeddedFiles ? 'Present (/Filespec)' : 'None'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* If no specific structural metadata parser applies */}
              {!result.metadata?.peMetadata && !result.metadata?.elfMetadata && !result.metadata?.pdfMetadata && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-2 shadow-xs">
                  <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    No specialized structural container parser for this format
                  </p>
                  <p className="text-[11px] text-slate-400 max-w-md mx-auto">
                    Static file hashing, Shannon entropy, and bounded strings analysis are fully available across all file types.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Entropy Meter & Sliding Block Distribution */}
          {activeTab === 'entropy' && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <BarChart2 className="w-4 h-4 text-purple-600" />
                      Shannon Entropy Score: {result.entropy.toFixed(4)} bits/byte
                    </h3>
                    <p className="text-xs text-slate-400">
                      Evaluated on a theoretical scale from 0.0000 (uniform byte repetition) to 8.0000 (perfect randomness).
                    </p>
                  </div>
                  <span
                    className={`text-xs font-bold px-3 py-1 rounded-full ${
                      result.entropyEvaluation.status === 'High'
                        ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300'
                        : result.entropyEvaluation.status === 'Moderate'
                        ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300'
                        : 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300 border border-teal-300'
                    }`}
                  >
                    {result.entropyEvaluation.status} Entropy
                  </span>
                </div>

                {/* Main Entropy Progress Bar */}
                <div className="space-y-1">
                  <div className="w-full h-4 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex">
                    <div
                      className={`h-full transition-all duration-500 ${
                        result.entropy > 7.2
                          ? 'bg-red-500'
                          : result.entropy > 6.0
                          ? 'bg-amber-500'
                          : 'bg-teal-500'
                      }`}
                      style={{ width: `${(result.entropy / 8.0) * 100}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                    <span>0.0 (Uniform)</span>
                    <span>4.0 (Text)</span>
                    <span>6.0 (Code)</span>
                    <span>7.2 (Packed / Encrypted)</span>
                    <span>8.0 (Maximum)</span>
                  </div>
                </div>

                {/* Sliding Block Entropy Chart */}
                {result.entropyBlocks && result.entropyBlocks.length > 0 && (
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">
                      Sliding Block Entropy Distribution (16 File Segments)
                    </span>
                    <div className="grid grid-cols-8 md:grid-cols-16 gap-1.5 h-20 items-end bg-slate-50 dark:bg-slate-800/40 p-2.5 rounded-xl border border-slate-200/60 dark:border-slate-700/60">
                      {result.entropyBlocks.map((block) => (
                        <div
                          key={block.blockIndex}
                          title={`Segment ${block.blockIndex}: ${block.entropy.toFixed(3)} bits/byte (Offset ${block.offset})`}
                          className="h-full flex flex-col justify-end items-center group cursor-pointer"
                        >
                          <div
                            className={`w-full rounded-xs transition-all ${
                              block.entropy > 7.2
                                ? 'bg-red-500 group-hover:bg-red-600'
                                : block.entropy > 6.0
                                ? 'bg-amber-500 group-hover:bg-amber-600'
                                : 'bg-teal-500 group-hover:bg-teal-600'
                            }`}
                            style={{ height: `${(block.entropy / 8.0) * 100}%` }}
                          />
                          <span className="text-[8px] font-mono text-slate-400 mt-1 opacity-60">
                            {block.blockIndex}
                          </span>
                        </div>
                      ))}
                    </div>
                    <p className="text-[10px] text-slate-400 text-right font-mono">
                      Left to right: File start (header) to File end (overlay / resources)
                    </p>
                  </div>
                )}

                {/* Limitations & False Positives Callout */}
                <div className="p-4 bg-amber-50/70 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-xl space-y-1.5 text-xs text-amber-900 dark:text-amber-200">
                  <span className="font-bold flex items-center gap-1.5">
                    <Info className="w-4 h-4 text-amber-600" />
                    Entropy Limitations & False Positives Advisory
                  </span>
                  <p className="text-[11px] leading-relaxed">
                    {result.entropyEvaluation.explanation}
                  </p>
                  <p className="text-[10.5px] text-amber-700 dark:text-amber-300">
                    <strong>Defensive Doctrine:</strong> High entropy is naturally exhibited by benign formats including ZIP, PNG, MP4, and JPEG due to compression algorithms. Conversely, sophisticated low-profile stagers can maintain low entropy by using sparse or text-based payloads. Never classify a file as malicious solely on entropy.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Bounded Strings Extraction */}
          {activeTab === 'strings' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-purple-600" />
                    Bounded Printable Strings & IOC Heuristics
                  </h3>
                  <p className="text-xs text-slate-400">
                    Showing {filteredStrings.length} extracted strings (bounded to first 4 MB to prevent memory exhaustion).
                  </p>
                </div>

                {/* Filter chips */}
                <div className="flex flex-wrap items-center gap-1 text-[11px]">
                  {(['all', 'url', 'ip', 'command', 'api', 'registry', 'path'] as const).map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setStringFilter(cat)}
                      className={`px-2.5 py-1 rounded-lg uppercase font-semibold transition ${
                        stringFilter === cat
                          ? 'bg-purple-600 text-white'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5 max-h-96 overflow-y-auto font-mono text-xs p-3 bg-slate-900 text-slate-100 rounded-xl border border-slate-800">
                {filteredStrings.length > 0 ? (
                  filteredStrings.map((s, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between py-1 px-2 rounded hover:bg-slate-800 transition group"
                    >
                      <span className="truncate mr-4 text-slate-200">{s.value}</span>
                      <span
                        className={`text-[9px] uppercase px-1.5 py-0.2 rounded font-bold shrink-0 ${
                          s.category === 'url'
                            ? 'bg-blue-900 text-blue-200'
                            : s.category === 'ip'
                            ? 'bg-red-900 text-red-200'
                            : s.category === 'command'
                            ? 'bg-amber-900 text-amber-200'
                            : s.category === 'api'
                            ? 'bg-purple-900 text-purple-200'
                            : s.category === 'registry'
                            ? 'bg-emerald-900 text-emerald-200'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {s.category}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 py-4 text-center">No strings found matching current category filter.</p>
                )}
              </div>
            </div>
          )}

          {/* Tab 5: Android APK Manifest & Permissions */}
          {activeTab === 'apk' && result.metadata?.apkMetadata && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FolderArchive className="w-5 h-5 text-teal-600" />
                    <div>
                      <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                        Android APK Static Structure Inspection
                      </h3>
                      <p className="text-xs text-slate-400">
                        Package: <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{result.metadata.apkMetadata.packageName}</span>
                      </p>
                    </div>
                  </div>
                  {result.metadata.apkMetadata.hasDebuggableFlag && (
                    <span className="px-2.5 py-1 rounded-full bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 text-[10px] font-bold border border-red-300 animate-pulse">
                      Debuggable Flag Active!
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[10px] uppercase block">DEX Executables</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 font-mono">
                      {result.metadata.apkMetadata.dexFilesFound} DEX Files
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[10px] uppercase block">Native Architectures</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-200 truncate block">
                      {result.metadata.apkMetadata.nativeArchitectures?.join(', ') || 'Pure Java/Kotlin'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[10px] uppercase block">Signing Signature</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      {result.metadata.apkMetadata.hasCertificates ? 'META-INF Present' : 'Unsigned / Stripped'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl">
                    <span className="text-slate-400 text-[10px] uppercase block">Sensitive Permissions</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 font-mono">
                      {result.metadata.apkMetadata.permissions?.length || 0} Permissions
                    </span>
                  </div>
                </div>

                {/* Permissions Breakdown Table */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">
                    Detected Android Permissions & Risk Ratings
                  </span>
                  <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200/80 dark:border-slate-800 rounded-xl overflow-hidden text-xs">
                    {result.metadata.apkMetadata.permissions && result.metadata.apkMetadata.permissions.length > 0 ? (
                      result.metadata.apkMetadata.permissions.map((p, idx) => (
                        <div key={idx} className="p-3 bg-white dark:bg-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div>
                            <span className="font-mono font-bold text-slate-800 dark:text-slate-200">{p.name}</span>
                            <p className="text-[11px] text-slate-400 mt-0.5">{p.description}</p>
                          </div>
                          <span
                            className={`px-2.5 py-0.5 rounded text-[10px] font-bold shrink-0 self-start sm:self-auto ${
                              p.risk === 'Dangerous'
                                ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300'
                                : p.risk === 'Privacy'
                                ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                            }`}
                          >
                            {p.risk} Risk
                          </span>
                        </div>
                      ))
                    ) : (
                      <p className="p-4 text-center text-xs text-slate-400">No sensitive permissions requested in manifest.</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 6: Unavailable Checks & Defensive Guarantees */}
          {activeTab === 'unavailable' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-teal-600" />
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                    Defensive Security Boundaries & Unavailable Checks
                  </h3>
                  <p className="text-xs text-slate-400">
                    Transparent accounting of omitted dynamic actions and their corresponding safe forensic alternatives.
                  </p>
                </div>
              </div>

              <div className="space-y-3">
                {result.unavailableChecks.map((check, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30 space-y-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <ShieldX className="w-4 h-4 text-red-500" />
                        {check.name}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                        {check.category}
                      </span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                      <strong>Policy Restriction:</strong> {check.reason}
                    </p>
                    <p className="text-teal-700 dark:text-teal-300 text-[11px] leading-relaxed">
                      <strong>Safe Alternative:</strong> {check.defensiveAlternative}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
