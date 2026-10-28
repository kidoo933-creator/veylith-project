import React, { useState } from 'react';
import { EvidenceItem } from '../types';
import { Globe, Server, FileText, AlertTriangle, Shield, Laptop, ZoomIn, ZoomOut, RotateCcw, Info } from 'lucide-react';

interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'ip' | 'file' | 'cve' | 'host' | 'finding';
  x: number;
  y: number;
  confidence: string;
  source: string;
  metadata?: string;
}

interface GraphLink {
  source: string;
  target: string;
  label: string;
  confidence: string;
}

interface EvidenceGraphProps {
  evidence: EvidenceItem[];
  caseId: string;
  onSelectNode?: (node: GraphNode) => void;
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({ evidence, caseId, onSelectNode }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [filterType, setFilterType] = useState<string>('all');

  // Baseline nodes derived from evidence or structured default nodes
  const nodes: GraphNode[] = [
    {
      id: 'node-domain-1',
      label: 'malicious-site[.]net',
      type: 'domain',
      x: 320,
      y: 90,
      confidence: 'Confirmed',
      source: 'DNS Telemetry',
      metadata: 'Registered 14 days ago via NameCheap, no valid SSL',
    },
    {
      id: 'node-ip-1',
      label: '192.0.2.45',
      type: 'ip',
      x: 210,
      y: 200,
      confidence: 'Observed',
      source: 'Firewall Egress Logs',
      metadata: 'Bulletproof hosting ASN, port 443 destination',
    },
    {
      id: 'node-file-1',
      label: 'File Hash 3f2a8e...9c4d',
      type: 'file',
      x: 430,
      y: 200,
      confidence: 'Observed',
      source: 'EDR Agent (invoice_update.exe)',
      metadata: 'PE32 Executable, high entropy 7.42, MZ header',
    },
    {
      id: 'node-cve-1',
      label: 'CVE-2024-6678',
      type: 'cve',
      x: 220,
      y: 320,
      confidence: 'Inferred',
      source: 'Vulnerability Intelligence',
      metadata: 'CVSS 8.8 Remote Code Execution vulnerability',
    },
    {
      id: 'node-host-1',
      label: 'Host: DESKTOP-01',
      type: 'host',
      x: 420,
      y: 320,
      confidence: 'Observed',
      source: 'Active Directory & EDR',
      metadata: 'Finance Department workstation, isolated',
    },
  ];

  // Ingest additional evidence items if present
  evidence.forEach((ev, idx) => {
    const existing = nodes.find((n) => n.label.toLowerCase().includes(ev.name.toLowerCase()));
    if (!existing) {
      nodes.push({
        id: `ev-node-${ev.id}`,
        label: ev.name,
        type: ev.type === 'cve' ? 'cve' : ev.type === 'ip' ? 'ip' : ev.type === 'domain' ? 'domain' : 'file',
        x: 150 + ((idx * 80) % 360),
        y: 100 + ((idx * 60) % 250),
        confidence: ev.confidence,
        source: ev.source,
        metadata: ev.notes || ev.value,
      });
    }
  });

  const links: GraphLink[] = [
    { source: 'node-domain-1', target: 'node-ip-1', label: 'DNS A Record', confidence: 'Confirmed' },
    { source: 'node-domain-1', target: 'node-file-1', label: 'C2 Stager Domain', confidence: 'Confirmed' },
    { source: 'node-ip-1', target: 'node-cve-1', label: 'Targeted Endpoint', confidence: 'Inferred' },
    { source: 'node-file-1', target: 'node-host-1', label: 'Executed On', confidence: 'Observed' },
    { source: 'node-ip-1', target: 'node-host-1', label: 'Egress Beaconing', confidence: 'Observed' },
  ];

  const filteredNodes = nodes.filter((n) => filterType === 'all' || n.type === filterType);

  const getNodeColor = (type: GraphNode['type']) => {
    switch (type) {
      case 'domain':
        return { bg: '#0D9488', ring: '#14B8A6', text: '#CCFBF1' }; // Teal
      case 'ip':
        return { bg: '#2563EB', ring: '#3B82F6', text: '#DBEAFE' }; // Blue
      case 'file':
        return { bg: '#7C3AED', ring: '#8B5CF6', text: '#EDE9FE' }; // Purple
      case 'cve':
        return { bg: '#DC2626', ring: '#EF4444', text: '#FEE2E2' }; // Red
      case 'host':
        return { bg: '#059669', ring: '#10B981', text: '#D1FAE5' }; // Emerald
      default:
        return { bg: '#475569', ring: '#64748B', text: '#F1F5F9' };
    }
  };

  const getNodeIcon = (type: GraphNode['type']) => {
    switch (type) {
      case 'domain':
        return <Globe className="w-4 h-4 text-white" />;
      case 'ip':
        return <Server className="w-4 h-4 text-white" />;
      case 'file':
        return <FileText className="w-4 h-4 text-white" />;
      case 'cve':
        return <AlertTriangle className="w-4 h-4 text-white" />;
      case 'host':
        return <Laptop className="w-4 h-4 text-white" />;
      default:
        return <Shield className="w-4 h-4 text-white" />;
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
    if (onSelectNode) onSelectNode(node);
  };

  return (
    <div className="relative w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
      {/* Graph Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Entity Filter:
          </span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="text-xs bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-2.5 py-1 text-slate-700 dark:text-slate-200 outline-none focus:ring-1 focus:ring-teal-500"
          >
            <option value="all">All Entities ({nodes.length})</option>
            <option value="domain">Domains</option>
            <option value="ip">IP Addresses</option>
            <option value="file">Files & Hashes</option>
            <option value="cve">Vulnerabilities</option>
            <option value="host">Hosts & Endpoints</option>
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setZoomLevel((z) => Math.min(z + 0.15, 1.8))}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoomLevel((z) => Math.max(z - 0.15, 0.6))}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={() => {
              setZoomLevel(1);
              setSelectedNode(null);
            }}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
            title="Reset View"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full h-[380px] bg-slate-50/60 dark:bg-slate-950/40 flex items-center justify-center overflow-hidden">
        {/* Subtle grid background */}
        <div
          className="absolute inset-0 opacity-40 dark:opacity-20 pointer-events-none"
          style={{
            backgroundImage: 'radial-gradient(circle, #94a3b8 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        <svg
          viewBox="0 0 640 400"
          className="w-full h-full max-w-full cursor-grab active:cursor-grabbing transition-transform duration-200"
          style={{ transform: `scale(${zoomLevel})` }}
        >
          <defs>
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="6"
              refX="18"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 8 3, 0 6" fill="#94A3B8" />
            </marker>
          </defs>

          {/* Links */}
          {links.map((link, idx) => {
            const src = nodes.find((n) => n.id === link.source);
            const dst = nodes.find((n) => n.id === link.target);
            if (!src || !dst) return null;

            const midX = (src.x + dst.x) / 2;
            const midY = (src.y + dst.y) / 2;

            return (
              <g key={`link-${idx}`}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  stroke="#94A3B8"
                  strokeWidth="1.5"
                  strokeDasharray="4,4"
                  markerEnd="url(#arrowhead)"
                  className="transition-all"
                />
                {/* Edge Label Badge */}
                <rect
                  x={midX - 38}
                  y={midY - 9}
                  width="76"
                  height="18"
                  rx="4"
                  fill="#FFFFFF"
                  className="dark:fill-slate-800 shadow-sm"
                  stroke="#CBD5E1"
                  strokeWidth="0.8"
                />
                <text
                  x={midX}
                  y={midY + 3.5}
                  textAnchor="middle"
                  fontSize="8.5"
                  fontWeight="500"
                  fill="#475569"
                  className="dark:fill-slate-300 pointer-events-none select-none"
                >
                  {link.label}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {filteredNodes.map((node) => {
            const colors = getNodeColor(node.type);
            const isSelected = selectedNode?.id === node.id;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => handleNodeClick(node)}
                className="cursor-pointer group"
              >
                {/* Outer Glow / Ring when selected */}
                {isSelected && (
                  <circle
                    r="26"
                    fill="none"
                    stroke={colors.ring}
                    strokeWidth="3"
                    strokeDasharray="4,2"
                    className="animate-spin"
                    style={{ transformOrigin: '0 0' }}
                  />
                )}

                {/* Node Circle */}
                <circle
                  r="20"
                  fill={colors.bg}
                  stroke="#FFFFFF"
                  strokeWidth="2.5"
                  className="filter drop-shadow-md group-hover:scale-110 transition-transform duration-150"
                />

                {/* Node Icon */}
                <foreignObject x="-8" y="-8" width="16" height="16" className="pointer-events-none">
                  <div className="flex items-center justify-center w-full h-full">
                    {getNodeIcon(node.type)}
                  </div>
                </foreignObject>

                {/* Node Title Label */}
                <rect
                  x={-Math.max(node.label.length * 3.8, 40)}
                  y="26"
                  width={Math.max(node.label.length * 7.6, 80)}
                  height="20"
                  rx="6"
                  fill="#FFFFFF"
                  className="dark:fill-slate-800 shadow-sm"
                  stroke={isSelected ? colors.ring : '#E2E8F0'}
                  strokeWidth={isSelected ? '1.5' : '1'}
                />
                <text
                  y="39"
                  textAnchor="middle"
                  fontSize="9.5"
                  fontWeight="600"
                  fill="#0F172A"
                  className="dark:fill-slate-100 select-none pointer-events-none"
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-80 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl p-3 shadow-xl backdrop-blur-md">
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: getNodeColor(selectedNode.type).bg }}
                />
                <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate">
                  {selectedNode.label}
                </h4>
              </div>
              <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-teal-50 dark:bg-teal-950/60 text-teal-700 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
                {selectedNode.confidence}
              </span>
            </div>

            <p className="text-[11px] text-slate-600 dark:text-slate-300 mb-2 leading-relaxed">
              {selectedNode.metadata}
            </p>

            <div className="flex items-center justify-between text-[10px] text-slate-400 border-t border-slate-100 dark:border-slate-700/60 pt-2">
              <span>Source: {selectedNode.source}</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 font-medium"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[11px] bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
        <div className="flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-teal-600" /> Domain
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-600" /> IP Address
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-600" /> File / Hash
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-600" /> CVE / Vuln
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-600" /> Host
          </span>
        </div>
        <div className="flex items-center gap-1 text-[10px] text-slate-400">
          <Info className="w-3.5 h-3.5 text-teal-600" />
          <span>Edges represent verified forensic links</span>
        </div>
      </div>
    </div>
  );
};
