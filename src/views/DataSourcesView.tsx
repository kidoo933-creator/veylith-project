import React from 'react';
import { Database, CheckCircle, Clock, AlertTriangle, ExternalLink, Shield } from 'lucide-react';

export const DataSourcesView: React.FC = () => {
  const sources = [
    {
      name: 'Veylith Deterministic Forensics Engine',
      type: 'On-Device Built-In',
      status: 'Active (Real-time)',
      statusColor: 'emerald',
      description: 'Web Crypto SHA-256/SHA-1 hashing, Shannon entropy calculation, file signature verification, and bounded strings extraction.',
      endpoint: 'Local Browser Memory & Worker',
      lastChecked: 'Continuous',
      authRequired: 'None (Local Processing)',
    },
    {
      name: 'Veylith SSRF Guard & Network Prober',
      type: 'Backend Service',
      status: 'Enforced',
      statusColor: 'emerald',
      description: 'Enforces strict RFC 1918, RFC 3927 link-local, multicast, loopback, and cloud metadata destination rejections prior to DNS and TLS probing.',
      endpoint: '/api/domain/investigate',
      lastChecked: 'Active',
      authRequired: 'Local Server Policy',
    },
    {
      name: 'CISA Known Exploited Vulnerabilities (KEV)',
      type: 'Authoritative Intelligence Feed',
      status: 'Online (Cached 1h)',
      statusColor: 'emerald',
      description: 'Official US Cybersecurity and Infrastructure Security Agency catalog of actively exploited vulnerabilities and binding remediation timelines.',
      endpoint: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      lastChecked: 'Automated 1-Hour Refresh',
      authRequired: 'Public Data Feed',
    },
    {
      name: 'NIST National Vulnerability Database (NVD)',
      type: 'Vulnerability Registry',
      status: 'Referenced (Direct Links)',
      statusColor: 'emerald',
      description: 'NIST NVD CVE detail repository, CVSS v3.1 vector calculation, and affected software configurations.',
      endpoint: 'https://nvd.nist.gov/vuln/detail/',
      lastChecked: 'On Demand',
      authRequired: 'Public Reference',
    },
    {
      name: 'Registration Data Access Protocol (RDAP)',
      type: 'Public Domain Registry',
      status: 'Available',
      statusColor: 'emerald',
      description: 'Structured, standardized successor to WHOIS providing registrar identity, registration dates, and nameservers.',
      endpoint: 'https://rdap.org/domain/{target}',
      lastChecked: 'Per-investigation query',
      authRequired: 'Public Gateway',
    },
    {
      name: 'Google Gemini 4 Argon AI Engine',
      type: 'Cloud LLM (ThinkingLevel.HIGH)',
      status: 'Integrated via Server Proxy',
      statusColor: 'purple',
      description: 'Senior digital forensics reasoning engine utilizing gemini-4-argon with high thinking mode for deep correlation and MITRE ATT&CK mapping.',
      endpoint: '/api/gemini/investigate',
      lastChecked: 'On User Request',
      authRequired: 'Server Environment GEMINI_API_KEY',
    },
    {
      name: 'VirusTotal / ThreatFox / AbuseIPDB API',
      type: 'Third-Party Threat Feeds',
      status: 'Optional Integration Boundary',
      statusColor: 'amber',
      description: 'External threat aggregation APIs. By default, Veylith maintains privacy zero-upload mode and does not leak private user indicators without explicit user approval.',
      endpoint: 'Not Configured (Privacy Default)',
      lastChecked: 'N/A',
      authRequired: 'Optional API Key (Future)',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Database className="w-5 h-5 text-teal-600" />
          Data Sources & Intelligence Feeds Transparency
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Complete transparency on data origins, cache staleness, and network boundaries. Veylith never fabricates feeds or implies a check was executed when it was not.
        </p>
      </div>

      <div className="space-y-3">
        {sources.map((src, i) => (
          <div
            key={i}
            className="p-5 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 shadow-xs space-y-3 text-xs"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${
                    src.statusColor === 'emerald'
                      ? 'bg-emerald-500'
                      : src.statusColor === 'purple'
                      ? 'bg-purple-500'
                      : 'bg-amber-500'
                  }`}
                />
                <h3 className="font-bold text-slate-900 dark:text-white text-sm">{src.name}</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                  {src.type}
                </span>
              </div>
              <span
                className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full ${
                  src.statusColor === 'emerald'
                    ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                    : src.statusColor === 'purple'
                    ? 'bg-purple-50 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-200 dark:border-purple-800'
                    : 'bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-200 dark:border-amber-800'
                }`}
              >
                {src.status}
              </span>
            </div>

            <p className="text-slate-600 dark:text-slate-300 leading-relaxed">{src.description}</p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-100 dark:border-slate-800 text-[11px] text-slate-400 font-mono">
              <span className="truncate">Endpoint: {src.endpoint}</span>
              <span>Cadence: {src.lastChecked}</span>
              <span>Auth: {src.authRequired}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
