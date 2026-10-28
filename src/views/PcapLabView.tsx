import React, { useState } from 'react';
import { PcapAnalysisResult } from '../types';
import { parsePcapFile, generateSamplePcap } from '../utils/pcapParser';
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
} from 'lucide-react';

interface PcapLabViewProps {
  onAttachEvidence: (name: string, type: 'pcap', value: string, notes: string) => void;
  activeCaseId: string;
}

export const PcapLabView: React.FC<PcapLabViewProps> = ({ onAttachEvidence, activeCaseId }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<'conversations' | 'packets' | 'anomalies'>('conversations');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setAnalyzing(true);
    setError(null);

    try {
      const buffer = await file.arrayBuffer();
      const parsed = parsePcapFile(buffer, file.name);
      setResult(parsed);
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
      setResult(parsed);
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
              Deterministic binary parsing for PCAP and PCAPNG captures. Never uploads captures to cloud services.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Load Test Capture:</span>
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
                Upload PCAP / PCAPNG Trace File
              </p>
              <p className="text-[11px] text-slate-400">
                Supports Wireshark, tcpdump, and Zeek capture formats up to 50MB
              </p>
            </div>
          </div>

          <label className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white text-xs font-semibold rounded-xl cursor-pointer transition shadow-xs">
            <span>Select .PCAP File</span>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-2 text-xs text-red-700 dark:text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {!result && !analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-4 shadow-xs">
          <div className="w-12 h-12 mx-auto rounded-2xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Ready for PCAP Packet Analysis</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
              Upload any Wireshark/tcpdump PCAP or PCAPNG trace, or click a test button above to parse binary frame headers, IP conversation matrices, and observable protocol anomalies.
            </p>
          </div>
        </div>
      )}

      {analyzing && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-3 shadow-xs">
          <div className="w-8 h-8 border-2 border-teal-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            Parsing binary PCAP packets & frame offsets...
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
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-teal-50 dark:bg-teal-950 text-teal-700 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
                  {result.format}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Parsed {result.totalPackets} packets ({result.totalBytes.toLocaleString()} bytes) across{' '}
                {result.durationSeconds}s
              </p>
            </div>

            <button
              onClick={() => {
                onAttachEvidence(
                  result.fileName,
                  'pcap',
                  `${result.totalPackets} packets (${result.format})`,
                  `PCAP Analysis: ${result.anomalies.length} observable anomalies detected.`
                );
              }}
              className="flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
            >
              <Plus className="w-3.5 h-3.5 text-teal-600" />
              <span>Attach Telemetry to Case ({activeCaseId})</span>
            </button>
          </div>

          {/* Protocols KPI Row */}
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
                  <span className="text-[10px] text-teal-600 dark:text-teal-400">
                    {((count / result.totalPackets) * 100).toFixed(1)}% of capture
                  </span>
                </div>
              );
            })}
          </div>

          {/* Sub Navigation */}
          <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium">
            <button
              onClick={() => setActiveTab('conversations')}
              className={`px-3 py-1.5 rounded-lg transition ${
                activeTab === 'conversations'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Top Conversations ({result.topConversations.length})
            </button>
            <button
              onClick={() => setActiveTab('anomalies')}
              className={`px-3 py-1.5 rounded-lg transition ${
                activeTab === 'anomalies'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Observable Anomalies ({result.anomalies.length})
            </button>
            <button
              onClick={() => setActiveTab('packets')}
              className={`px-3 py-1.5 rounded-lg transition ${
                activeTab === 'packets'
                  ? 'bg-teal-600 text-white font-semibold'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Raw Packet Timeline ({result.packets.length})
            </button>
          </div>

          {/* Tab 1: Conversations */}
          {activeTab === 'conversations' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">IP Conversation Matrix</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
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
        </div>
      )}
    </div>
  );
};
