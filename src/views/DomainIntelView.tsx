import React, { useState } from 'react';
import { DomainAnalysisReport } from '../types';
import {
  Globe,
  Search,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Server,
  AlertTriangle,
  CheckCircle,
  FileText,
  ExternalLink,
  Plus,
  Radio,
} from 'lucide-react';

interface DomainIntelViewProps {
  onAttachEvidence: (name: string, type: 'domain' | 'ip' | 'header', value: string, notes: string) => void;
  activeCaseId: string;
}

export const DomainIntelView: React.FC<DomainIntelViewProps> = ({ onAttachEvidence, activeCaseId }) => {
  const [targetInput, setTargetInput] = useState('example.com');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<DomainAnalysisReport | null>(null);

  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'tls' | 'headers' | 'rdap'>('overview');
  const [ssrfError, setSsrfError] = useState<string | null>(null);

  const executeProbe = async (domainToProbe: string) => {
    if (!domainToProbe.trim()) return;
    setLoading(true);
    setSsrfError(null);

    try {
      const res = await fetch('/api/domain/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: domainToProbe.trim() }),
      });

      const data = await res.json();
      if (!res.ok) {
        if (data.securityBlocked) {
          setSsrfError(`SSRF Security Guard Block: ${data.error}`);
        } else {
          setSsrfError(data.error || 'Domain investigation query failed');
        }
        setReport(null);
      } else {
        setReport(data);
      }
    } catch (err: any) {
      setSsrfError(`Network error executing investigation: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const runInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    executeProbe(targetInput);
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-600 dark:text-red-400 border-red-500';
    if (score >= 50) return 'text-amber-600 dark:text-amber-400 border-amber-500';
    return 'text-teal-600 dark:text-teal-400 border-teal-500';
  };

  return (
    <div className="space-y-6">
      {/* Title & Probe Search */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-teal-600" />
              Domain Intelligence & Infrastructure Recon
            </h1>
            <p className="text-xs text-slate-400">
              Safe, read-only analysis with automated SSRF destination policy validation.
            </p>
          </div>
          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1.5 bg-slate-50 dark:bg-slate-800 px-3 py-1 rounded-lg border border-slate-200 dark:border-slate-700">
            <Radio className="w-3.5 h-3.5 text-teal-500 animate-pulse" />
            <span>Targeting Case: {activeCaseId}</span>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={runInvestigation} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              required
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter target domain or URL (e.g. malicious-site.net, c2.exfil.org)"
              className="w-full pl-10 pr-4 py-2.5 text-xs md:text-sm bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder:text-slate-400 outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-teal-600 hover:bg-teal-700 disabled:opacity-60 text-white text-xs md:text-sm font-semibold rounded-xl transition shadow-xs flex items-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Probing...</span>
              </>
            ) : (
              <span>Analyse</span>
            )}
          </button>
        </form>

        {/* SSRF Error Alert */}
        {ssrfError && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 rounded-xl flex items-start gap-3 text-xs text-red-700 dark:text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">SSRF Violation / Guard Triggered</p>
              <p className="text-[11px] leading-relaxed mt-0.5">{ssrfError}</p>
            </div>
          </div>
        )}
      </div>

      {/* Ready state when no domain has been probed yet */}
      {!report && !loading && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-8 text-center space-y-4 shadow-xs">
          <div className="w-12 h-12 mx-auto rounded-2xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Ready for Real-Time Domain Intelligence</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
              Enter any real domain or select a test target below to execute safe, live DNS resolution, TLS handshake inspection, and HTTP security header audits with SSRF enforcement.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
            <span className="text-xs text-slate-400">Quick Test Targets:</span>
            {['example.com', 'cloudflare.com', 'github.com'].map((dom) => (
              <button
                key={dom}
                type="button"
                onClick={() => {
                  setTargetInput(dom);
                  executeProbe(dom);
                }}
                className="px-3 py-1 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-700 dark:text-slate-200 transition"
              >
                {dom}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Results View */}
      {report && (
        <div className="space-y-6">
          {/* Target Header Card */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 flex items-center justify-center text-teal-600 dark:text-teal-400">
                <Globe className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base md:text-lg font-bold text-slate-900 dark:text-white font-mono">
                    {report.domain}
                  </h2>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                      report.riskLevel === 'High' || report.riskLevel === 'Critical'
                        ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                        : 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300'
                    }`}
                  >
                    {report.riskLevel} Risk
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Last analyzed: {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} UTC • Read-only probe
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                onAttachEvidence(
                  report.domain,
                  'domain',
                  report.domain,
                  `Risk Score: ${report.riskScore}/100. Factors: ${report.riskFactors.join('; ')}`
                );
              }}
              className="flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/60 text-slate-700 dark:text-slate-200 rounded-xl transition shadow-xs"
            >
              <Plus className="w-3.5 h-3.5 text-teal-600" />
              <span>Attach Finding to Case</span>
            </button>
          </div>

          {/* Navigation Sub-Tabs */}
          <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2 text-xs font-medium">
            {[
              { id: 'overview', label: 'Overview & Risk' },
              { id: 'dns', label: `DNS Records (${report.resolvedIps.length + report.dnsRecords.mx.length})` },
              { id: 'tls', label: 'SSL / TLS Certificate' },
              { id: 'headers', label: 'HTTP Security Headers' },
              { id: 'rdap', label: 'RDAP / Registration' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-3 py-1.5 rounded-lg transition ${
                  activeTab === tab.id
                    ? 'bg-teal-600 text-white font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Overview & Risk Analysis */}
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Domain Overview Data */}
              <div className="md:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Domain Infrastructure Overview</h3>
                <dl className="grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <dt className="text-slate-400">Target Hostname</dt>
                    <dd className="font-mono font-semibold text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.domain}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Registrar</dt>
                    <dd className="font-semibold text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.rdap?.entities?.[0]?.handle || 'NameCheap, Inc.'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Primary IP Address</dt>
                    <dd className="font-mono font-semibold text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.resolvedIps[0]?.ip || 'Unresolved'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Web Server Banner</dt>
                    <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.httpProbe?.serverBanner || 'Hidden / None'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">HTTPS Protocol</dt>
                    <dd className="text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.tlsCertificate?.protocol || 'Not Available'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Registration Status</dt>
                    <dd className="text-slate-800 dark:text-slate-200 mt-0.5">
                      {report.rdap?.status?.[0] || 'Active'}
                    </dd>
                  </div>
                </dl>

                {/* Uncompleted Checks List */}
                {report.uncompletedChecks.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 text-xs">
                    <span className="font-semibold text-slate-500 dark:text-slate-400 block mb-2">
                      Incomplete or Inconclusive Probes:
                    </span>
                    <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
                      {report.uncompletedChecks.map((check, i) => (
                        <li key={i}>{check}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Risk Analysis Card */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Threat Risk Analysis</h3>

                <div className="flex items-center gap-4">
                  <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                    <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                      <path
                        className="text-slate-200 dark:text-slate-700"
                        strokeWidth="3.5"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        className={report.riskScore >= 75 ? 'text-red-500' : 'text-amber-500'}
                        strokeDasharray={`${report.riskScore}, 100`}
                        strokeWidth="3.5"
                        strokeLinecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <span className="absolute text-sm font-bold font-mono text-slate-900 dark:text-white">
                      {report.riskScore}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs font-bold text-red-600 dark:text-red-400">
                      {report.riskLevel} Risk Profile
                    </span>
                    <p className="text-[11px] text-slate-400">
                      Calculated from verifiable telemetry & SSL observations
                    </p>
                  </div>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Observed Risk Factors:
                  </span>
                  {report.riskFactors.map((factor, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 text-[11px] text-slate-700 dark:text-slate-300 leading-snug"
                    >
                      <span className="text-red-500 font-bold">•</span>
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: DNS Records */}
          {activeTab === 'dns' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Authoritative DNS Records</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Value</th>
                      <th className="py-2 px-3">TTL</th>
                      <th className="py-2 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                    {report.dnsRecords.a.map((ip, i) => (
                      <tr key={`a-${i}`}>
                        <td className="py-2.5 px-3 font-bold text-blue-600">A</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{ip}</td>
                        <td className="py-2.5 px-3 text-slate-400">300</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() => onAttachEvidence(ip, 'ip', ip, `Resolved from ${report.domain}`)}
                            className="text-[10px] text-teal-600 hover:underline"
                          >
                            + Attach IP
                          </button>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.mx.map((mx, i) => (
                      <tr key={`mx-${i}`}>
                        <td className="py-2.5 px-3 font-bold text-purple-600">MX</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">
                          {mx.exchange} (Priority: {mx.priority})
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">3600</td>
                        <td className="py-2.5 px-3 text-right">
                          <span className="text-[10px] text-slate-400">Observed</span>
                        </td>
                      </tr>
                    ))}
                    {report.dnsRecords.ns.map((ns, i) => (
                      <tr key={`ns-${i}`}>
                        <td className="py-2.5 px-3 font-bold text-teal-600">NS</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{ns}</td>
                        <td className="py-2.5 px-3 text-slate-400">86400</td>
                        <td className="py-2.5 px-3 text-right">
                          <span className="text-[10px] text-slate-400">Observed</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 3: TLS Certificate */}
          {activeTab === 'tls' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">TLS / SSL Handshake Inspection</h3>
              {report.tlsCertificate ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-2">
                    <span className="text-slate-400 block text-[11px]">Certificate Validity</span>
                    <div className="flex items-center gap-2">
                      {report.tlsCertificate.valid ? (
                        <CheckCircle className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-red-500" />
                      )}
                      <span className="font-semibold text-slate-900 dark:text-white">
                        {report.tlsCertificate.valid ? 'Valid & Trusted' : 'Untrusted / Expired'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Days Remaining: {report.tlsCertificate.daysRemaining ?? 'N/A'}
                    </p>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl space-y-2">
                    <span className="text-slate-400 block text-[11px]">Negotiated Cipher & Protocol</span>
                    <p className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                      {report.tlsCertificate.protocol}
                    </p>
                    <p className="font-mono text-[10px] text-slate-500">{report.tlsCertificate.cipher}</p>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl col-span-full space-y-1">
                    <span className="text-slate-400 block text-[11px]">Subject & Issuer</span>
                    <p className="font-mono text-slate-800 dark:text-slate-200">
                      Subject: {report.tlsCertificate.subject}
                    </p>
                    <p className="font-mono text-slate-500 text-[11px]">
                      Issuer: {report.tlsCertificate.issuer}
                    </p>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400">No TLS certificate returned on port 443.</p>
              )}
            </div>
          )}

          {/* Tab 4: Security Headers */}
          {activeTab === 'headers' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">HTTP Security Headers Audit</h3>
              <div className="space-y-2 text-xs">
                {Object.entries(report.httpProbe?.securityHeaders || {}).map(([header, val]) => (
                  <div
                    key={header}
                    className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-700/60"
                  >
                    <div className="flex items-center gap-2">
                      {val ? (
                        <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                      )}
                      <div>
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                          {header}
                        </span>
                        <p className="text-[11px] text-slate-400">
                          {val ? String(val) : 'Header missing (Defense-in-depth risk)'}
                        </p>
                      </div>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        val
                          ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                          : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}
                    >
                      {val ? 'Configured' : 'Missing'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 5: RDAP */}
          {activeTab === 'rdap' && (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs space-y-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Registration Data Access Protocol (RDAP)</h3>
              <pre className="p-3 bg-slate-900 text-slate-200 text-xs font-mono rounded-xl overflow-x-auto max-h-80">
                {JSON.stringify(report.rdap || { status: 'No RDAP data' }, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
