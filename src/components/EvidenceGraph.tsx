import React, { useState } from 'react';
import { EvidenceItem, Finding, CaseRecord } from '../types';
import { buildEvidenceGraph } from '../utils/evidenceCorrelation';
import { getAnalystProfile } from '../utils/storage';
import {
  Globe,
  Server,
  FileText,
  AlertTriangle,
  Shield,
  Laptop,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Info,
  FolderLock,
  ExternalLink,
  CheckCircle2,
  X,
  FileSearch,
} from 'lucide-react';

export interface GraphNode {
  id: string;
  label: string;
  type: 'case' | 'domain' | 'ip' | 'file' | 'hash' | 'cve' | 'host' | 'finding';
  x: number;
  y: number;
  confidence: string;
  source: string;
  metadata?: string;
  underlyingFindingId?: string;
  evidenceId?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
  reason: string;
  confidence: string;
  underlyingFindingId?: string;
}

interface EvidenceGraphProps {
  evidence: EvidenceItem[];
  findings?: Finding[];
  caseId: string;
  caseTitle?: string;
  onOpenFinding?: (findingId: string) => void;
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({
  evidence,
  findings = [],
  caseId,
  caseTitle,
  onOpenFinding,
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedLink, setSelectedLink] = useState<GraphLink | null>(null);
  const [activeFindingModal, setActiveFindingModal] = useState<Finding | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [filterType, setFilterType] = useState<string>('all');

  // Build nodes and links dynamically from ground-truth evidence correlation engine
  const caseRecordForGraph: CaseRecord = {
    id: caseId,
    title: caseTitle || 'Active Forensic Case',
    description: '',
    priority: 'High',
    status: 'In Progress',
    leadAnalyst: getAnalystProfile().name,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    scope: [],
    tags: [],
    evidence,
    findings,
    notes: [],
    auditLog: [],
  };

  const { nodes: corrNodes, edges: corrEdges } = buildEvidenceGraph([caseRecordForGraph]);

  const nodes: GraphNode[] = corrNodes.map((cn) => {
    let gType: GraphNode['type'] = 'finding';
    if (cn.type === 'case') gType = 'case';
    else if (cn.type === 'domain') gType = 'domain';
    else if (cn.type === 'ip') gType = 'ip';
    else if (cn.type === 'file') gType = 'file';
    else if (cn.type === 'hash') gType = 'hash';
    else if (cn.type === 'cve') gType = 'cve';
    else gType = 'finding';

    return {
      id: cn.id,
      label: cn.label.length > 22 ? `${cn.label.slice(0, 20)}...` : cn.label,
      type: gType,
      x: cn.x,
      y: cn.y,
      confidence: cn.confidence,
      source: cn.source,
      metadata: cn.metadata,
      underlyingFindingId: cn.underlyingFinding?.id,
      evidenceId: cn.underlyingEvidence?.id,
    };
  });

  const links: GraphLink[] = corrEdges.map((ce) => ({
    source: ce.source,
    target: ce.target,
    label: ce.reason.length > 22 ? `${ce.reason.slice(0, 20)}...` : ce.reason,
    reason: ce.reason,
    confidence: ce.confidence,
    underlyingFindingId: ce.underlyingFindingId || ce.sourceFindingId,
  }));

  const filteredNodes = nodes.filter((n) => filterType === 'all' || n.type === filterType);

  const getNodeColor = (type: GraphNode['type']) => {
    switch (type) {
      case 'case':
        return { bg: '#1E293B', ring: '#0D9488', text: '#F8FAFC' }; // Dark Slate / Teal Ring
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
      case 'finding':
        return { bg: '#EA580C', ring: '#F97316', text: '#FFEDD5' }; // Orange / Warning
      default:
        return { bg: '#475569', ring: '#64748B', text: '#F1F5F9' };
    }
  };

  const getNodeIcon = (type: GraphNode['type']) => {
    switch (type) {
      case 'case':
        return <FolderLock className="w-3.5 h-3.5 text-teal-400" />;
      case 'domain':
        return <Globe className="w-3.5 h-3.5 text-white" />;
      case 'ip':
        return <Server className="w-3.5 h-3.5 text-white" />;
      case 'file':
        return <FileText className="w-3.5 h-3.5 text-white" />;
      case 'cve':
        return <AlertTriangle className="w-3.5 h-3.5 text-white" />;
      case 'host':
        return <Laptop className="w-3.5 h-3.5 text-white" />;
      case 'finding':
        return <FileSearch className="w-3.5 h-3.5 text-white" />;
      default:
        return <Shield className="w-3.5 h-3.5 text-white" />;
    }
  };

  const handleOpenUnderlyingFinding = (findingId: string) => {
    const f = findings.find((item) => item.id === findingId);
    if (f) {
      setActiveFindingModal(f);
    } else if (onOpenFinding) {
      onOpenFinding(findingId);
    }
  };

  return (
    <div className="relative w-full rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-xs">
      {/* Graph Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 border-b border-slate-200/80 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80">
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
            <option value="finding">Observations & Findings</option>
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
              setSelectedLink(null);
            }}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition"
            title="Reset View"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full h-[420px] bg-slate-50/60 dark:bg-slate-950/40 flex items-center justify-center overflow-hidden">
        {/* Subtle grid pattern */}
        <div
          className="absolute inset-0 opacity-40 dark:opacity-20 pointer-events-none"
          style={{
            backgroundImage: 'radial-gradient(circle, #94a3b8 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        <svg
          viewBox="0 0 640 380"
          className="w-full h-full max-w-full cursor-grab active:cursor-grabbing transition-transform duration-200"
          style={{ transform: `scale(${zoomLevel})` }}
        >
          <defs>
            <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="18" refY="3" orient="auto">
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
            const isLinkSelected = selectedLink === link;

            return (
              <g key={`link-${idx}`} onClick={() => { setSelectedLink(link); setSelectedNode(null); }} className="cursor-pointer group">
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  stroke={isLinkSelected ? '#0D9488' : '#94A3B8'}
                  strokeWidth={isLinkSelected ? '2.5' : '1.5'}
                  strokeDasharray={isLinkSelected ? 'none' : '4,4'}
                  markerEnd="url(#arrowhead)"
                  className="transition-all"
                />
                {/* Edge Label Badge */}
                <rect
                  x={midX - 42}
                  y={midY - 9}
                  width="84"
                  height="18"
                  rx="4"
                  fill="#FFFFFF"
                  className="dark:fill-slate-800 shadow-2xs"
                  stroke={isLinkSelected ? '#0D9488' : '#CBD5E1'}
                  strokeWidth={isLinkSelected ? '1.5' : '0.8'}
                />
                <text
                  x={midX}
                  y={midY + 3.5}
                  textAnchor="middle"
                  fontSize="8"
                  fontWeight="600"
                  fill={isLinkSelected ? '#0D9488' : '#475569'}
                  className="dark:fill-slate-300 pointer-events-none select-none font-mono"
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
            const isCaseNode = node.type === 'case';

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => { setSelectedNode(node); setSelectedLink(null); }}
                className="cursor-pointer group"
              >
                {/* Outer Glow / Ring when selected */}
                {isSelected && (
                  <circle
                    r={isCaseNode ? '32' : '26'}
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
                  r={isCaseNode ? '25' : '19'}
                  fill={colors.bg}
                  stroke="#FFFFFF"
                  strokeWidth={isCaseNode ? '3' : '2'}
                  className="filter drop-shadow-md group-hover:scale-110 transition-transform duration-150"
                />

                {/* Node Icon */}
                <foreignObject
                  x={isCaseNode ? '-10' : '-8'}
                  y={isCaseNode ? '-10' : '-8'}
                  width={isCaseNode ? '20' : '16'}
                  height={isCaseNode ? '20' : '16'}
                  className="pointer-events-none"
                >
                  <div className="flex items-center justify-center w-full h-full">
                    {getNodeIcon(node.type)}
                  </div>
                </foreignObject>

                {/* Node Title Label Badge */}
                <rect
                  x={-Math.max(node.label.length * 3.6, 38)}
                  y="24"
                  width={Math.max(node.label.length * 7.2, 76)}
                  height="18"
                  rx="5"
                  fill="#FFFFFF"
                  className="dark:fill-slate-800 shadow-2xs"
                  stroke={isSelected ? colors.ring : '#E2E8F0'}
                  strokeWidth={isSelected ? '1.5' : '1'}
                />
                <text
                  y="36"
                  textAnchor="middle"
                  fontSize="9"
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
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-88 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl p-4 shadow-2xl backdrop-blur-md space-y-2 animate-in fade-in duration-150">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: getNodeColor(selectedNode.type).bg }}
                />
                <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate">
                  {selectedNode.label}
                </h4>
              </div>
              <div className="flex items-center gap-1">
                <span className="text-[9px] uppercase font-bold px-1.5 py-0.5 rounded bg-teal-50 dark:bg-teal-950/60 text-teal-700 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
                  {selectedNode.confidence}
                </span>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-sans">
              {selectedNode.metadata}
            </p>

            <div className="flex items-center justify-between text-[10px] text-slate-400 border-t border-slate-100 dark:border-slate-700/60 pt-2 font-mono">
              <span>Source: {selectedNode.source}</span>
              {selectedNode.underlyingFindingId && (
                <button
                  onClick={() => handleOpenUnderlyingFinding(selectedNode.underlyingFindingId!)}
                  className="flex items-center gap-1 font-semibold text-teal-600 dark:text-teal-400 hover:underline"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Open Underlying Finding</span>
                </button>
              )}
            </div>
          </div>
        )}

        {/* Selected Link / Relationship Drawer */}
        {selectedLink && (
          <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-88 bg-white dark:bg-slate-800 border border-teal-500/80 rounded-2xl p-4 shadow-2xl backdrop-blur-md space-y-2 animate-in fade-in duration-150">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold text-teal-700 dark:text-teal-300 flex items-center gap-1.5 font-mono">
                <CheckCircle2 className="w-3.5 h-3.5 text-teal-500" />
                Connection: {selectedLink.label}
              </span>
              <button
                onClick={() => setSelectedLink(null)}
                className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="p-2.5 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200/60 dark:border-slate-800 text-xs text-slate-800 dark:text-slate-200 leading-relaxed">
              <span className="font-semibold text-slate-500 dark:text-slate-400 text-[10px] uppercase block mb-1">
                Forensic Correlation Reason:
              </span>
              {selectedLink.reason}
            </div>

            <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 font-mono">
              <span>Confidence: {selectedLink.confidence}</span>
              {selectedLink.underlyingFindingId && (
                <button
                  onClick={() => handleOpenUnderlyingFinding(selectedLink.underlyingFindingId!)}
                  className="flex items-center gap-1 font-semibold text-teal-600 dark:text-teal-400 hover:underline"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Inspect Source Finding</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[11px] bg-white dark:bg-slate-900 border-t border-slate-200/80 dark:border-slate-800 text-slate-500 dark:text-slate-400">
        <div className="flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-900 dark:bg-slate-100" /> Case
          </span>
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
            <span className="w-2.5 h-2.5 rounded-full bg-orange-600" /> Finding Observation
          </span>
        </div>
        <div className="flex items-center gap-1 text-[10px] text-slate-400">
          <Info className="w-3.5 h-3.5 text-teal-600" />
          <span>Click any node or link to review verifiable correlation reason</span>
        </div>
      </div>

      {/* Underlying Finding Modal Dialog */}
      {activeFindingModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 dark:border-slate-800 space-y-4 animate-in fade-in duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <FileSearch className="w-5 h-5 text-orange-600" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Underlying Investigation Finding ({activeFindingModal.id})
                </h3>
              </div>
              <button
                onClick={() => setActiveFindingModal(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block mb-0.5">Finding Title</span>
                <p className="text-sm font-bold text-slate-900 dark:text-white">{activeFindingModal.title}</p>
              </div>

              <div className="flex gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                  {activeFindingModal.severity} Severity
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300">
                  {activeFindingModal.confidence} Confidence
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  Status: {activeFindingModal.status}
                </span>
              </div>

              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block mb-0.5">Forensic Description</span>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/50 p-3 rounded-xl border border-slate-200/60 dark:border-slate-700/60">
                  {activeFindingModal.description}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-[11px] font-mono">
                <div>
                  <span className="text-slate-400 block">Source Tool:</span>
                  <span className="text-slate-800 dark:text-slate-200 font-semibold">{activeFindingModal.sourceTool}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Trigger Input:</span>
                  <span className="text-slate-800 dark:text-slate-200 font-semibold truncate block">{activeFindingModal.relevantInput}</span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end">
              <button
                onClick={() => setActiveFindingModal(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-xl text-xs font-semibold transition"
              >
                Close Finding
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
