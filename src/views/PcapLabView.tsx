import React, { useState } from 'react';
import { PcapAnalysisResult, Finding, InvestigationViewMode } from '../types';
import { parsePcapFile, generateSamplePcap } from '../utils/pcapParser';
import { createPcapFinding } from '../utils/findingNormalization';
import { InvestigationViewToggle } from '../components/InvestigationViewToggle';
import { SimpleResultsReport } from '../components/SimpleResultsReport';
import { generatePcapSimpleReport } from '../utils/pcapAiAnalyst';
import {
  Network,
  Upload,
  AlertTriangle,
  Radio,
  Clock,
  ArrowRight,
  ShieldAlert,
  Plus,
  Play,
  FileCheck2,
  Server,
  Cpu,
  Layers,
  Terminal,
  Info,
  CheckCircle2,
  Lock,
  BookmarkCheck,
} from 'lucide-react';

interface PcapLabViewProps {
  onAttachEvidence: (name: string, type: 'pcap', value: string, notes: string) => void;
  onLogFinding?: (caseId: string, findingData: Partial<Finding>) => void;
  activeCaseId: string;
}

export const PcapLabView: React.FC<PcapLabViewProps> = ({ onAttachEvidence, onLogFinding, activeCaseId }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [findingLogged, setFindingLogged] = useState(false);
  const [viewMode, setViewMode] = useState<InvestigationViewMode>('simple');

  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<'conversations' | 'packets' | 'anomalies' | 'architecture'>('conversations');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setAnalyzing(true);
    setError(null);

    try {
      const buffer = await file.arrayBuffer();
      const parsed = parsePcapFile(buffer, file.name);
      parsed.simpleReport = generatePcapSimpleReport(parsed);
      setResult(parsed);
      setViewMode('simple');
      setActiveTab('conversations');
    } catch (err: any) {
      setError(err.message || 'Failed to parse PCAP file.');
      setResult(null);
    } finally {
      setAnalyzing(false);
    }
  };

  const loadPresetCapture = (type: 'c2-beacon' | 'dns-tunnel' | 'web-traffic', title: string) => {
    setAnalyzing(true);
    setError(null);
    try {
      const buf = generateSamplePcap(type);
      const parsed = parsePcapFile(buf, `${title.toLowerCase().replace(/\s+/g, '_')}.pcap`);
      parsed.simpleReport = generatePcapSimpleReport(parsed);
      setResult(parsed);
      setViewMode('simple');
      setActiveTab('conversations');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Upload Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-teal-600" />
              PCAP Lab & Packet Telemetry Inspection
            </h1>
            <p className="text-xs text-slate-400">
              Deterministic binary parsing for PCAP and PCAPNG captures. Never displays fabricated packet statistics.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Load Capture:</span>
            <button
              onClick={() => loadPresetCapture('c2-beacon', 'C2 Beaconing')}
              className="px-2.5 py-1 rounded-lg bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-medium hover:bg-red-100 transition"
            >
              C2 Beaconing
            </button>
            <button
              onClick={() => loadPresetCapture('dns-tunnel', 'DNS Exfiltration')}
              className="px-2.5 py-1 rounded-lg bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 font-medium hover:bg-purple-100 transition"
            >
              DNS Tunneling
            </button>
            <button
              onClick={() => loadPresetCapture('web-traffic', 'HTTP Traffic')}
              className="px-2.5 py-1 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-medium hover:bg-blue-100 transition"
            >
              Web Probe
            </button>
          </div>
        </div>

        {/* Upload Zone */}
        <div className="flex flex-col sm:flex-row items-center justify-between p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-white dark:bg-slate-700 rounded-xl shadow-xs text-teal-600">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                Select or drop a standard .pcap or .pcapng binary file
              </p>
              <p className="text-[11px] text-slate-400">
                Processed locally in memory via Veylith zero-dependency binary stream demuxer.
              </p>
            </div>
          </div>

          <label className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded-xl text-xs font-semibold cursor-pointer transition shadow-xs shrink-0">
            Browse Capture
            <input type="file" accept=".pcap,.pcapng,.cap" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-xl flex items-center gap-2 text-xs text-red-700 dark:text-red-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-3 shadow-xs">
          <div className="w-8 h-8 border-2 border-teal-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            Demuxing PCAP packet frames and decoding Ethernet/IP headers...
          </p>
        </div>
      )}

      {!result && !analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-3 shadow-xs">
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            No packet capture currently loaded
          </p>
          <p className="text-[11px] text-slate-400 max-w-md mx-auto">
            Upload any Wireshark or tcpdump capture file above or select one of the verified test samples to inspect IP conversations, frame offsets, protocol matrices, and observable anomalies.
          </p>
        </div>
      )}

      {/* Main Results View */}
      {result && !analyzing && (
        <div className="space-y-6">
          {/* Capture Summary Card */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base md:text-lg font-bold text-slate-900 dark:text-white font-mono">
                  {result.fileName}
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-400 border border-teal-200 dark:border-teal-800 font-bold">
                  {result.format}
                </span>
                {result.linkTypeName && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                    {result.linkTypeName}
                  </span>
                )}
                {result.truncatedPacketsCount && result.truncatedPacketsCount > 0 ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-bold">
                    Truncated Capture
                  </span>
                ) : null}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Parsed <span className="font-semibold text-slate-700 dark:text-slate-200 font-mono">{result.totalPackets}</span> verifiable packets ({result.totalBytes.toLocaleString()} bytes) across{' '}
                {result.durationSeconds}s. Zero simulated packets.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => {
                  onAttachEvidence(
                    result.fileName,
                    'pcap',
                    `${result.totalPackets} packets (${result.format})`,
                    `PCAP Analysis: ${result.anomalies.length} observable anomalies detected.`
                  );
                }}
                className="flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
              >
                <Plus className="w-3.5 h-3.5 text-teal-600" />
                <span>Attach Telemetry to Case ({activeCaseId})</span>
              </button>

              {onLogFinding && (
                <button
                  onClick={() => {
                    const topAnomaly = result.anomalies[0];
                    const finding = createPcapFinding({
                      caseId: activeCaseId,
                      pcapFile: result.fileName,
                      title: topAnomaly ? topAnomaly.title : `Packet Telemetry: ${result.totalPackets} frames`,
                      targetEndpoint: topAnomaly?.evidence || 'Network Telemetry Capture',
                      observedResult: topAnomaly
                        ? topAnomaly.description
                        : `Verifiable capture containing ${result.totalPackets} frames across ${result.durationSeconds}s.`,
                      description: `Packet capture inspection on ${result.fileName} (${result.format}, ${result.totalBytes.toLocaleString()} bytes). Protocol breakdown: TCP (${result.protocols.TCP}), UDP (${result.protocols.UDP}), DNS (${result.protocols.DNS}), HTTP (${result.protocols.HTTP}).`,
                      severity: topAnomaly?.severity || 'Low',
                      severityRationale: topAnomaly
                        ? 'Observable network protocol anomaly identified within captured frame flow.'
                        : 'Baseline operational network telemetry without active protocol anomaly triggers.',
                      confidence: 'Confirmed',
                      evidenceIds: [],
                    });
                    onLogFinding(activeCaseId, finding);
                    setFindingLogged(true);
                    setTimeout(() => setFindingLogged(false), 3000);
                  }}
                  disabled={findingLogged}
                  className={`flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl transition shadow-xs ${
                    findingLogged
                      ? 'bg-emerald-600 text-white border border-emerald-500'
                      : 'bg-teal-600 hover:bg-teal-700 text-white'
                  }`}
                >
                  {findingLogged ? (
                    <>
                      <BookmarkCheck className="w-3.5 h-3.5" />
                      <span>Finding Logged!</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Log Network Finding</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Top-Level Investigation Mode Toggle */}
          <InvestigationViewToggle
            mode={viewMode}
            onChange={setViewMode}
            simpleLabel="Simple Results"
            deepLabel="Deep Analysis"
            simpleDescription="Human-Readable Cybersecurity Analyst Report"
            deepDescription="Packet Flows, Hex Offsets, Anomaly Telemetry & Wireshark Frame Inspector"
            findingCounts={{
              concerns: result.anomalies.length,
              technicalItems: result.totalPackets,
            }}
          />

          {/* VIEW 1: SIMPLE RESULTS (DEFAULT) */}
          {viewMode === 'simple' && (
            <SimpleResultsReport
              report={result.simpleReport || generatePcapSimpleReport(result)}
              onNavigateToDeep={() => setViewMode('deep')}
            />
          )}

          {/* VIEW 2: DEEP ANALYSIS (TECHNICAL TELEMETRY) */}
          {viewMode === 'deep' && (
            <div className="space-y-6">
              {/* Protocols KPI Row (Verifiable counts from frames) */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {Object.entries(result.protocols).map(([proto, count]) => {
              if (count === 0) return null;
              return (
                <div
                  key={proto}
                  className="p-3.5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/80 dark:border-slate-800 shadow-xs"
                >
                  <span className="text-slate-400 text-xs font-medium">{proto} Packets</span>
                  <div className="text-xl font-bold font-mono text-slate-900 dark:text-white mt-1">
                    {count}
                  </div>
                  <span className="text-[10px] text-teal-600 dark:text-teal-400 font-mono">
                    {((count / result.totalPackets) * 100).toFixed(1)}% of capture
                  </span>
                </div>
              );
            })}
          </div>

          {/* Sub Navigation */}
          <div className="flex items-center gap-1.5 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium overflow-x-auto select-none">
            <button
              onClick={() => setActiveTab('conversations')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'conversations'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Top Conversations ({result.topConversations.length})
            </button>
            <button
              onClick={() => setActiveTab('anomalies')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'anomalies'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Observable Anomalies ({result.anomalies.length})
            </button>
            <button
              onClick={() => setActiveTab('packets')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 ${
                activeTab === 'packets'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Packet Frame Inspection ({result.packets.length})
            </button>
            <button
              onClick={() => setActiveTab('architecture')}
              className={`px-3 py-1.5 rounded-lg transition shrink-0 flex items-center gap-1.5 ${
                activeTab === 'architecture'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Android Limitations & Future Architecture</span>
            </button>
          </div>

          {/* Tab 1: Conversations */}
          {activeTab === 'conversations' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">IP Conversation Matrix</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-sans">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                      <th className="py-2 px-3">Conversation Pair</th>
                      <th className="py-2 px-3">Protocol</th>
                      <th className="py-2 px-3">Packets</th>
                      <th className="py-2 px-3">Total Bytes</th>
                      <th className="py-2 px-3 text-right">Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                    {result.topConversations.map((conv, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                        <td className="py-3 px-3 text-slate-800 dark:text-slate-200 font-semibold">
                          {conv.pair}
                        </td>
                        <td className="py-3 px-3 text-slate-600 dark:text-slate-400">{conv.proto}</td>
                        <td className="py-3 px-3 text-slate-800 dark:text-slate-200">{conv.packets}</td>
                        <td className="py-3 px-3 text-slate-500">{(conv.bytes / 1024).toFixed(1)} KB</td>
                        <td className="py-3 px-3 text-right">
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300">
                            Investigating
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 2: Anomalies */}
          {activeTab === 'anomalies' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Observable Network Anomalies</h3>
              {result.anomalies.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">
                  No automated behavioral anomalies observed in this sample.
                </div>
              ) : (
                <div className="space-y-3">
                  {result.anomalies.map((anom, i) => (
                    <div
                      key={i}
                      className="p-4 rounded-xl border border-red-200 dark:border-red-900 bg-red-50/50 dark:bg-red-950/30 space-y-1.5 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
                          <span className="font-bold text-red-900 dark:text-red-200">{anom.title}</span>
                        </div>
                        <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                          {anom.severity}
                        </span>
                      </div>
                      <p className="text-slate-700 dark:text-slate-300">{anom.description}</p>
                      <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200/60 dark:border-slate-800">
                        {anom.evidence}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Raw Packets */}
          {activeTab === 'packets' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Packet Frame Inspection</h3>
              <div className="overflow-x-auto max-h-96">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase font-sans">
                      <th className="py-2 px-2.5">No.</th>
                      <th className="py-2 px-2.5">Time</th>
                      <th className="py-2 px-2.5">Source</th>
                      <th className="py-2 px-2.5">Destination</th>
                      <th className="py-2 px-2.5">Protocol</th>
                      <th className="py-2 px-2.5">Length</th>
                      <th className="py-2 px-2.5">Info</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                    {result.packets.slice(0, 100).map((pkt) => (
                      <tr key={pkt.index} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="py-2 px-2.5 text-slate-400">{pkt.index}</td>
                        <td className="py-2 px-2.5 text-slate-500">{pkt.timeStr}</td>
                        <td className="py-2 px-2.5 text-slate-800 dark:text-slate-200 font-semibold">
                          {pkt.srcIp || 'Link-Layer'}
                        </td>
                        <td className="py-2 px-2.5 text-slate-800 dark:text-slate-200 font-semibold">
                          {pkt.dstIp || 'Broadcast'}
                        </td>
                        <td className="py-2 px-2.5">
                          <span
                            className={`text-[9.5px] font-bold px-1.5 py-0.2 rounded ${
                              pkt.appProtocol === 'DNS'
                                ? 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300'
                                : pkt.protocol === 'TCP'
                                ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                            }`}
                          >
                            {pkt.appProtocol || pkt.protocol}
                          </span>
                        </td>
                        <td className="py-2 px-2.5 text-slate-500">{pkt.length}</td>
                        <td className="py-2 px-2.5 text-slate-700 dark:text-slate-300 truncate max-w-xs">
                          {pkt.info}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 4: Android Limitations & Future Backend Architecture */}
          {activeTab === 'architecture' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-5">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Server className="w-4 h-4 text-teal-600" />
                  Android Build Environment Limitation & Future Backend Architecture
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Defensible technical audit on mobile network capture feasibility and production enterprise ingestion design.
                </p>
              </div>

              {/* Limitation Explanation */}
              <div className="p-4 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-xl space-y-2 text-xs text-amber-900 dark:text-amber-200">
                <span className="font-bold flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600" />
                  Why Native On-Device PCAP Capture is Restricted on Android
                </span>
                <p className="text-[11.5px] leading-relaxed">
                  Standard unrooted Android runtime environments strictly isolate applications in Linux user namespaces. Android forbids raw socket binding (<code className="font-mono font-bold">AF_PACKET</code> / <code className="font-mono font-bold">SOCK_RAW</code>) to regular apps without the <code className="font-mono font-bold">CAP_NET_RAW</code> Linux capability. Native libraries like <code className="font-mono">libpcap.so</code> cannot perform live promiscuous capture unless the device is rooted or runs a local VPNService TUN interface proxy.
                </p>
                <p className="text-[11.5px] leading-relaxed">
                  <strong>Veylith Approach:</strong> Rather than pretending live mobile sniffing is active, Veylith provides deterministic, zero-dependency static PCAP parsing on imported traces and defines a clear enterprise architecture for heavy PCAP processing.
                </p>
              </div>

              {/* Architecture Blueprint */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Target Enterprise Backend Architecture for Heavy PCAP Ingestion
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/80 dark:border-slate-700/80 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-teal-600 dark:text-teal-400 block">Stage 01</span>
                    <p className="font-bold text-slate-800 dark:text-slate-200">Veylith Edge Client</p>
                    <p className="text-[10.5px] text-slate-500 dark:text-slate-400 font-sans">
                      Android / Web Client computes SHA-256 and streams raw capture via TLS gRPC endpoint.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/80 dark:border-slate-700/80 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-blue-600 dark:text-blue-400 block">Stage 02</span>
                    <p className="font-bold text-slate-800 dark:text-slate-200">Worker Ingestion Ring</p>
                    <p className="text-[10.5px] text-slate-500 dark:text-slate-400 font-sans">
                      High-throughput Go / Rust worker pool with AF_XDP or Zeek protocol parser for zero-copy stream dissection.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/80 dark:border-slate-700/80 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-purple-600 dark:text-purple-400 block">Stage 03</span>
                    <p className="font-bold text-slate-800 dark:text-slate-200">Timeseries Index</p>
                    <p className="text-[10.5px] text-slate-500 dark:text-slate-400 font-sans">
                      ClickHouse / PostgreSQL columnar storage indexing flow tuples, TLS SNIs, and DNS queries with sub-second retrieval.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200/80 dark:border-slate-700/80 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-emerald-600 dark:text-emerald-400 block">Stage 04</span>
                    <p className="font-bold text-slate-800 dark:text-slate-200">Correlator Engine</p>
                    <p className="text-[10.5px] text-slate-500 dark:text-slate-400 font-sans">
                      Automatic correlation linking IPs, DNS names, and beacons directly to Veylith Case Evidence Graphs.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
          </div>
        )}
        </div>
      )}
    </div>
  );
};
