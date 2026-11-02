import React, { useState, useMemo } from 'react';
import { CaseRecord, EvidenceItem, Finding, SeverityLevel, ConfidenceLevel, ViewTab, CorrelationStatus } from '../types';
import { FindingInspectorModal } from '../components/FindingInspectorModal';
import {
  Share2,
  Globe,
  Server,
  FileText,
  AlertTriangle,
  FolderLock,
  Layers,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Info,
  ExternalLink,
  ShieldCheck,
  Tag,
  Clock,
  CheckCircle,
  Eye,
  ChevronRight,
  Filter,
  ArrowRight,
  X,
  Check,
  Ban,
} from 'lucide-react';

interface EvidenceGraphViewProps {
  cases: CaseRecord[];
  activeCaseId: string;
  onSelectCase: (caseId: string) => void;
  onNavigateToTab: (tab: ViewTab) => void;
  onUpdateCorrelationOverride?: (caseId: string, edgeId: string, status: CorrelationStatus) => void;
  onUpdateFindingStatus?: (caseId: string, findingId: string, status: Finding['status']) => void;
}

export type { CorrelationNode, CorrelationEdge } from '../utils/evidenceCorrelation';
import { buildEvidenceGraph, CorrelationNode, CorrelationEdge } from '../utils/evidenceCorrelation';

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({
  cases,
  activeCaseId,
  onSelectCase,
  onNavigateToTab,
  onUpdateCorrelationOverride,
  onUpdateFindingStatus,
}) => {
  const [scopeMode, setScopeMode] = useState<'active' | 'global'>('active');
  const [filterType, setFilterType] = useState<string>('all');
  const [includeDismissed, setIncludeDismissed] = useState<boolean>(false);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [selectedNode, setSelectedNode] = useState<CorrelationNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<CorrelationEdge | null>(null);
  const [inspectedFinding, setInspectedFinding] = useState<Finding | null>(null);
  const [activeModalItem, setActiveModalItem] = useState<{
    type: 'finding' | 'evidence' | 'case';
    title: string;
    description: string;
    severity?: SeverityLevel;
    confidence: ConfidenceLevel;
    source: string;
    timestamp: string;
    details: Record<string, any>;
    rawInput?: string;
    caseId: string;
  } | null>(null);

  // Selected active case or fallback
  const currentCase = cases.find((c) => c.id === activeCaseId) || cases[0];
  const targetCases = scopeMode === 'active' ? (currentCase ? [currentCase] : []) : cases;

  // Build nodes and edges STRICTLY from recorded evidence & findings
  const { nodes, edges } = useMemo(
    () => buildEvidenceGraph(targetCases, { includeDismissed }),
    [targetCases, includeDismissed]
  );

  const filteredNodes = nodes.filter((n) => filterType === 'all' || n.type === filterType);
  const activeNodeIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = edges.filter(
    (e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target)
  );

  const getNodeColor = (type: CorrelationNode['type']) => {
    switch (type) {
      case 'case':
        return { bg: '#0F172A', ring: '#334155', text: '#F8FAFC' }; // Slate Dark
      case 'domain':
        return { bg: '#0D9488', ring: '#14B8A6', text: '#CCFBF1' }; // Teal
      case 'ip':
        return { bg: '#2563EB', ring: '#3B82F6', text: '#DBEAFE' }; // Blue
      case 'file':
      case 'hash':
        return { bg: '#7C3AED', ring: '#8B5CF6', text: '#EDE9FE' }; // Purple
      case 'cve':
        return { bg: '#DC2626', ring: '#EF4444', text: '#FEE2E2' }; // Red
      case 'observation':
        return { bg: '#D97706', ring: '#F59E0B', text: '#FEF3C7' }; // Amber
      default:
        return { bg: '#475569', ring: '#64748B', text: '#F1F5F9' };
    }
  };

  const getNodeIcon = (type: CorrelationNode['type']) => {
    switch (type) {
      case 'case':
        return <FolderLock className="w-3.5 h-3.5 text-white" />;
      case 'domain':
        return <Globe className="w-3.5 h-3.5 text-white" />;
      case 'ip':
        return <Server className="w-3.5 h-3.5 text-white" />;
      case 'file':
      case 'hash':
        return <FileText className="w-3.5 h-3.5 text-white" />;
      case 'cve':
        return <AlertTriangle className="w-3.5 h-3.5 text-white" />;
      case 'observation':
        return <Eye className="w-3.5 h-3.5 text-white" />;
      default:
        return <ShieldCheck className="w-3.5 h-3.5 text-white" />;
    }
  };

  const openUnderlyingDetails = (node: CorrelationNode) => {
    if (node.underlyingFinding) {
      setInspectedFinding(node.underlyingFinding);
      return;
    } else if (node.underlyingEvidence) {
      setActiveModalItem({
        type: 'evidence',
        title: node.underlyingEvidence.name,
        description: node.underlyingEvidence.notes || 'No analyst notes recorded.',
        confidence: node.underlyingEvidence.confidence,
        source: node.underlyingEvidence.source,
        timestamp: node.underlyingEvidence.timestamp,
        rawInput: node.underlyingEvidence.value,
        details: {
          'Evidence Type': node.underlyingEvidence.type.toUpperCase(),
          Value: node.underlyingEvidence.value,
          Case: node.underlyingEvidence.caseId || node.caseId,
        },
        caseId: node.caseId,
      });
    } else {
      const cs = cases.find((c) => c.id === node.caseId);
      setActiveModalItem({
        type: 'case',
        title: cs?.title || node.label,
        description: cs?.description || 'Active investigation case record.',
        severity: cs?.priority,
        confidence: 'Confirmed',
        source: 'Investigation Workspace Repository',
        timestamp: cs?.createdAt || node.timestamp,
        details: {
          Status: cs?.status,
          'Lead Analyst': cs?.leadAnalyst,
          Scope: cs?.scope?.join(', ') || 'N/A',
          Tags: cs?.tags?.join(', ') || 'None',
        },
        caseId: node.caseId,
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/80 dark:border-slate-800 p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Share2 className="w-5 h-5 text-teal-600" />
              <h1 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white">
                Defensible Evidence Correlation Graph
              </h1>
              <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300 border border-teal-300 dark:border-teal-800">
                Ground-Truth Links
              </span>
              {currentCase?.isTrainingScenario && (
                <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                  Training Sandbox
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Links cases, domains, files, hashes, CVEs, and observations strictly supported by recorded case evidence. Zero fabricated edges.
            </p>
          </div>

          {/* Scope Mode Switcher */}
          <div className="flex items-center gap-2 text-xs">
            <div className="flex items-center bg-slate-100 dark:bg-slate-800 p-1 rounded-xl border border-slate-200 dark:border-slate-700">
              <button
                onClick={() => setScopeMode('active')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  scopeMode === 'active'
                    ? 'bg-white dark:bg-slate-900 text-teal-700 dark:text-teal-300 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Active Case ({activeCaseId})
              </button>
              <button
                onClick={() => setScopeMode('global')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  scopeMode === 'global'
                    ? 'bg-white dark:bg-slate-900 text-teal-700 dark:text-teal-300 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Cross-Case Campaign ({cases.length} Cases)
              </button>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-100 dark:border-slate-800 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-slate-400 font-medium">Filter Entity:</span>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-1 text-slate-700 dark:text-slate-300 font-medium outline-none"
            >
              <option value="all">All Entities ({nodes.length})</option>
              <option value="case">Cases</option>
              <option value="domain">Domains</option>
              <option value="ip">IP Addresses</option>
              <option value="file">Files & Hashes</option>
              <option value="cve">Vulnerabilities (CVEs)</option>
              <option value="observation">Findings & Observations</option>
            </select>

            {scopeMode === 'active' && (
              <select
                value={currentCase?.id}
                onChange={(e) => onSelectCase(e.target.value)}
                className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-1 text-slate-700 dark:text-slate-300 font-mono font-semibold outline-none"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} - {c.title}
                  </option>
                ))}
              </select>
            )}

            <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 cursor-pointer select-none px-2 py-1 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition">
              <input
                type="checkbox"
                checked={includeDismissed}
                onChange={(e) => setIncludeDismissed(e.target.checked)}
                className="rounded text-teal-600 focus:ring-teal-500"
              />
              <span>Include Dismissed Links</span>
            </label>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 border border-slate-200 dark:border-slate-700 rounded-lg p-0.5 bg-slate-50 dark:bg-slate-800">
              <button
                onClick={() => setZoomLevel((z) => Math.min(z + 0.15, 1.8))}
                className="p-1 hover:bg-white dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoomLevel((z) => Math.max(z - 0.15, 0.6))}
                className="p-1 hover:bg-white dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => {
                  setZoomLevel(1);
                  setSelectedNode(null);
                  setSelectedEdge(null);
                }}
                className="p-1 hover:bg-white dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300"
                title="Reset View"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive SVG Canvas */}
      <div className="relative w-full rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-xs">
        <div className="relative w-full h-[420px] bg-slate-50/50 dark:bg-slate-950/40 flex items-center justify-center overflow-hidden">
          {/* Subtle grid pattern */}
          <div
            className="absolute inset-0 opacity-40 dark:opacity-20 pointer-events-none"
            style={{
              backgroundImage: 'radial-gradient(circle, #94a3b8 1px, transparent 1px)',
              backgroundSize: '24px 24px',
            }}
          />

          {filteredNodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center z-10 pointer-events-none">
              <div className="p-4 bg-white/90 dark:bg-slate-900/90 backdrop-blur-sm border border-slate-200 dark:border-slate-800 rounded-2xl shadow-lg max-w-sm pointer-events-auto">
                <Share2 className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  No Evidence Nodes in Scope
                </p>
                <p className="text-[11px] text-slate-400 mt-1">
                  {targetCases.length === 0
                    ? 'No active case selected. Select or create an investigation case to correlate evidence.'
                    : 'Attach domain, IP, hash, or CVE artifacts to this case to generate defensible correlation links.'}
                </p>
              </div>
            </div>
          )}

          <svg
            viewBox="0 0 640 400"
            className="w-full h-full max-w-full cursor-grab active:cursor-grabbing transition-transform duration-200 select-none"
            style={{ transform: `scale(${zoomLevel})` }}
          >
            <defs>
              <marker
                id="correlation-arrow"
                markerWidth="8"
                markerHeight="6"
                refX="16"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#94A3B8" />
              </marker>
              <marker
                id="correlation-arrow-active"
                markerWidth="8"
                markerHeight="6"
                refX="16"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#0D9488" />
              </marker>
            </defs>

            {/* Links / Edges */}
            {filteredEdges.map((edge) => {
              const src = nodes.find((n) => n.id === edge.source);
              const dst = nodes.find((n) => n.id === edge.target);
              if (!src || !dst) return null;

              const midX = (src.x + dst.x) / 2;
              const midY = (src.y + dst.y) / 2;
              const isEdgeSelected = selectedEdge?.id === edge.id;

              return (
                <g
                  key={edge.id}
                  onClick={() => {
                    setSelectedEdge(edge);
                    setSelectedNode(null);
                  }}
                  className="cursor-pointer group"
                >
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={isEdgeSelected ? '#0D9488' : '#94A3B8'}
                    strokeWidth={isEdgeSelected ? '2.5' : '1.5'}
                    strokeDasharray={isEdgeSelected ? 'none' : '4,3'}
                    markerEnd={isEdgeSelected ? 'url(#correlation-arrow-active)' : 'url(#correlation-arrow)'}
                    className="transition-all"
                  />
                  {/* Edge Reason Label Pill */}
                  <rect
                    x={midX - Math.min(edge.reason.length * 3.3, 55)}
                    y={midY - 8}
                    width={Math.min(edge.reason.length * 6.6, 110)}
                    height="16"
                    rx="4"
                    fill="#FFFFFF"
                    className="dark:fill-slate-800 shadow-xs"
                    stroke={isEdgeSelected ? '#0D9488' : '#CBD5E1'}
                    strokeWidth="0.8"
                  />
                  <text
                    x={midX}
                    y={midY + 3}
                    textAnchor="middle"
                    fontSize="7.5"
                    fontWeight="500"
                    fill={isEdgeSelected ? '#0D9488' : '#475569'}
                    className="dark:fill-slate-300 pointer-events-none select-none font-sans"
                  >
                    {edge.reason.length > 20 ? `${edge.reason.slice(0, 18)}...` : edge.reason}
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
                  onClick={() => {
                    setSelectedNode(node);
                    setSelectedEdge(null);
                  }}
                  className="cursor-pointer group"
                >
                  {/* Selection Ring */}
                  {isSelected && (
                    <circle
                      r="22"
                      fill="none"
                      stroke={colors.ring}
                      strokeWidth="2.5"
                      strokeDasharray="4,2"
                      className="animate-spin"
                      style={{ transformOrigin: '0 0' }}
                    />
                  )}

                  {/* Node Circle */}
                  <circle
                    r="16"
                    fill={colors.bg}
                    stroke="#FFFFFF"
                    strokeWidth="2"
                    className="filter drop-shadow-md group-hover:scale-110 transition-transform duration-150"
                  />

                  {/* Node Icon */}
                  <foreignObject x="-7" y="-7" width="14" height="14" className="pointer-events-none">
                    <div className="flex items-center justify-center w-full h-full">
                      {getNodeIcon(node.type)}
                    </div>
                  </foreignObject>

                  {/* Label Pill */}
                  <rect
                    x={-Math.min(node.label.length * 3.4, 45)}
                    y="20"
                    width={Math.min(node.label.length * 6.8, 90)}
                    height="17"
                    rx="5"
                    fill="#FFFFFF"
                    className="dark:fill-slate-800 shadow-xs"
                    stroke={isSelected ? colors.ring : '#E2E8F0'}
                    strokeWidth={isSelected ? '1.5' : '1'}
                  />
                  <text
                    y="31.5"
                    textAnchor="middle"
                    fontSize="8"
                    fontWeight="600"
                    fill="#0F172A"
                    className="dark:fill-slate-100 select-none pointer-events-none font-mono"
                  >
                    {node.label.length > 15 ? `${node.label.slice(0, 13)}..` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Node Inspection Drawer */}
          {selectedNode && (
            <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-88 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 shadow-xl space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: getNodeColor(selectedNode.type).bg }}
                  />
                  <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate max-w-[200px]">
                    {selectedNode.label}
                  </h4>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/60 p-2 rounded-lg border border-slate-200/50 dark:border-slate-800">
                {selectedNode.metadata || 'Recorded indicator in case scope.'}
              </div>

              <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                <span>Confidence: <strong className="text-teal-600 dark:text-teal-400">{selectedNode.confidence}</strong></span>
                <span>Case: <strong className="text-slate-700 dark:text-slate-300 font-mono">{selectedNode.caseId}</strong></span>
              </div>

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between gap-2">
                <span className="text-[10px] text-slate-400 truncate">Source: {selectedNode.source}</span>
                <button
                  onClick={() => openUnderlyingDetails(selectedNode)}
                  className="px-2.5 py-1 text-[11px] font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-lg transition flex items-center gap-1 shrink-0"
                >
                  <span>Open Underlying Finding</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>
            </div>
          )}

          {/* Edge Inspection Drawer */}
          {selectedEdge && (
            <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-88 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 shadow-xl space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Share2 className="w-3.5 h-3.5 text-teal-600 shrink-0" />
                  <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate">
                    Correlated Relationship
                  </h4>
                </div>
                <button
                  onClick={() => setSelectedEdge(null)}
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 mb-1">
                <span
                  className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                    selectedEdge.isInferred
                      ? 'bg-purple-100 text-purple-800 dark:bg-purple-950/80 dark:text-purple-300 border border-purple-300 dark:border-purple-700'
                      : 'bg-teal-100 text-teal-800 dark:bg-teal-950/80 dark:text-teal-300 border border-teal-300 dark:border-teal-700'
                  }`}
                >
                  {selectedEdge.isInferred ? 'Inferred Correlation' : 'Directly Observed Link'}
                </span>
                <span
                  className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                    selectedEdge.status === 'dismissed'
                      ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300'
                      : selectedEdge.status === 'confirmed'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-300'
                      : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300'
                  }`}
                >
                  {selectedEdge.status?.toUpperCase() || (selectedEdge.isInferred ? 'UNVERIFIED' : 'CONFIRMED')}
                </span>
                {selectedEdge.sourceFindingId && (
                  <span className="text-[9px] font-mono text-slate-500 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                    Ref: {selectedEdge.sourceFindingId}
                  </span>
                )}
              </div>

              <div className="p-2 bg-teal-50 dark:bg-teal-950/60 border border-teal-200 dark:border-teal-800 rounded-lg text-xs text-teal-800 dark:text-teal-300">
                <p className="font-semibold text-xs">Reason for Connection:</p>
                <p className="text-[11px] mt-0.5">{selectedEdge.reason}</p>
                {selectedEdge.inferredReason && (
                  <p className="text-[10px] text-amber-700 dark:text-amber-400 mt-1 italic border-t border-teal-200/50 dark:border-teal-800/50 pt-1">
                    Inference Basis: {selectedEdge.inferredReason}
                  </p>
                )}
              </div>

              <div className="text-[10px] text-slate-500 dark:text-slate-400 space-y-1">
                <p>Telemetry Source: <strong className="text-slate-700 dark:text-slate-300">{selectedEdge.evidenceSource}</strong></p>
                <p>Provenance: <strong className="text-slate-700 dark:text-slate-300">{selectedEdge.provenance || selectedEdge.evidenceSource}</strong></p>
                <p>Confidence: <strong className="text-teal-600 dark:text-teal-400">{selectedEdge.confidence}</strong></p>
                {selectedEdge.timestamp && (
                  <p>Timestamp: <span className="font-mono text-slate-600 dark:text-slate-300">{selectedEdge.timestamp}</span></p>
                )}
              </div>

              {/* Analyst Correlation Verification Controls */}
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800 space-y-1.5">
                <span className="text-[10px] font-bold uppercase text-slate-400 block">Analyst Link Verification:</span>
                <div className="flex gap-1.5">
                  <button
                    onClick={() => {
                      if (onUpdateCorrelationOverride) {
                        onUpdateCorrelationOverride(activeCaseId, selectedEdge.id, 'confirmed');
                        setSelectedEdge((prev) => (prev ? { ...prev, status: 'confirmed' } : null));
                      }
                    }}
                    className={`flex-1 px-2 py-1 rounded text-[10px] font-semibold transition border ${
                      selectedEdge.status === 'confirmed'
                        ? 'bg-emerald-600 text-white border-emerald-600'
                        : 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800 hover:bg-emerald-100'
                    }`}
                  >
                    Confirm
                  </button>
                  <button
                    onClick={() => {
                      if (onUpdateCorrelationOverride) {
                        onUpdateCorrelationOverride(activeCaseId, selectedEdge.id, 'unverified');
                        setSelectedEdge((prev) => (prev ? { ...prev, status: 'unverified' } : null));
                      }
                    }}
                    className={`flex-1 px-2 py-1 rounded text-[10px] font-semibold transition border ${
                      selectedEdge.status === 'unverified'
                        ? 'bg-amber-600 text-white border-amber-600'
                        : 'bg-amber-50 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-200 dark:border-amber-800 hover:bg-amber-100'
                    }`}
                  >
                    Unverified
                  </button>
                  <button
                    onClick={() => {
                      if (onUpdateCorrelationOverride) {
                        onUpdateCorrelationOverride(activeCaseId, selectedEdge.id, 'dismissed');
                        setSelectedEdge((prev) => (prev ? { ...prev, status: 'dismissed' } : null));
                      }
                    }}
                    className={`flex-1 px-2 py-1 rounded text-[10px] font-semibold transition border ${
                      selectedEdge.status === 'dismissed'
                        ? 'bg-red-600 text-white border-red-600'
                        : 'bg-red-50 text-red-800 dark:bg-red-950/60 dark:text-red-300 border-red-200 dark:border-red-800 hover:bg-red-100'
                    }`}
                  >
                    Dismiss
                  </button>
                </div>
                <p className="text-[9px] text-slate-400 italic">
                  Defensible DFIR: Dismissing flags this analytical correlation without modifying original evidence records.
                </p>
              </div>

              {/* Action Buttons to Open Underlying Finding / Entities */}
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800 space-y-1.5">
                {selectedEdge.underlyingFinding ? (
                  <button
                    onClick={() => setInspectedFinding(selectedEdge.underlyingFinding!)}
                    className="w-full px-2.5 py-1.5 text-[11px] font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-lg transition flex items-center justify-center gap-1.5"
                  >
                    <span>Inspect Finding Details</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                ) : (
                  <div className="flex gap-1.5">
                    {(() => {
                      const srcNode = nodes.find((n) => n.id === selectedEdge.source);
                      const dstNode = nodes.find((n) => n.id === selectedEdge.target);
                      return (
                        <>
                          {srcNode && (
                            <button
                              onClick={() => openUnderlyingDetails(srcNode)}
                              className="flex-1 px-2 py-1 text-[10px] font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg transition flex items-center justify-center gap-1 truncate"
                              title={srcNode.label}
                            >
                              <span>Src: {srcNode.label.slice(0, 10)}..</span>
                              <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                            </button>
                          )}
                          {dstNode && (
                            <button
                              onClick={() => openUnderlyingDetails(dstNode)}
                              className="flex-1 px-2 py-1 text-[10px] font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg transition flex items-center justify-center gap-1 truncate"
                              title={dstNode.label}
                            >
                              <span>Dst: {dstNode.label.slice(0, 10)}..</span>
                              <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                            </button>
                          )}
                        </>
                      );
                    })()}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-[11px] bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
          <div className="flex flex-wrap items-center gap-3">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-900 dark:bg-slate-300" /> Case Master
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
              <span className="w-2.5 h-2.5 rounded-full bg-red-600" /> Vulnerability (CVE)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-600" /> Observation / Finding
            </span>
          </div>

          <div className="flex items-center gap-1 text-[10px] text-slate-400">
            <Info className="w-3.5 h-3.5 text-teal-600" />
            <span>Click any node to open underlying finding</span>
          </div>
        </div>
      </div>

      {/* Modal: Underlying Finding / Evidence Record */}
      {activeModalItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg p-5 shadow-2xl space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300 border border-teal-300 dark:border-teal-800">
                  {activeModalItem.type.toUpperCase()} RECORD
                </span>
                <h3 className="text-base font-bold text-slate-900 dark:text-white mt-1">
                  {activeModalItem.title}
                </h3>
              </div>
              <button
                onClick={() => setActiveModalItem(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/60 p-3 rounded-xl border border-slate-200/50 dark:border-slate-800">
              {activeModalItem.description}
            </p>

            {activeModalItem.rawInput && (
              <div>
                <span className="text-[10px] font-semibold text-slate-400 uppercase">Raw Indicator Value / Digest</span>
                <p className="font-mono text-xs text-slate-800 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 p-2 rounded-lg break-all select-all mt-0.5">
                  {activeModalItem.rawInput}
                </p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                <span className="text-[10px] text-slate-400">Confidence Rating</span>
                <p className="font-semibold text-teal-600 dark:text-teal-400">{activeModalItem.confidence}</p>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                <span className="text-[10px] text-slate-400">Case Attribution</span>
                <p className="font-mono font-semibold text-slate-800 dark:text-slate-200">{activeModalItem.caseId}</p>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                <span className="text-[10px] text-slate-400">Collection Timestamp</span>
                <p className="font-semibold text-slate-700 dark:text-slate-300">
                  {new Date(activeModalItem.timestamp).toLocaleString()}
                </p>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                <span className="text-[10px] text-slate-400">Provenance Tool</span>
                <p className="font-semibold text-slate-700 dark:text-slate-300 truncate">{activeModalItem.source}</p>
              </div>
            </div>

            {/* Quick Action Pivots */}
            <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex flex-wrap items-center justify-end gap-2">
              <button
                onClick={() => {
                  onNavigateToTab('investigation-workspace');
                  setActiveModalItem(null);
                }}
                className="px-3 py-1.5 text-xs font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 text-slate-700 dark:text-slate-300 rounded-xl transition"
              >
                Open in Workspace
              </button>
              <button
                onClick={() => {
                  if (activeModalItem.title.includes('.exe') || activeModalItem.title.includes('3f2a8e')) {
                    onNavigateToTab('file-forensics');
                  } else if (activeModalItem.title.includes('CVE-')) {
                    onNavigateToTab('vulnerability-intel');
                  } else if (activeModalItem.title.includes('.net') || activeModalItem.title.includes('192.0.')) {
                    onNavigateToTab('domain-intel');
                  } else {
                    onNavigateToTab('investigation-workspace');
                  }
                  setActiveModalItem(null);
                }}
                className="px-3.5 py-1.5 text-xs font-semibold bg-teal-600 hover:bg-teal-700 text-white rounded-xl transition shadow-xs flex items-center gap-1.5"
              >
                <span>Pivot to Dedicated Tool</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Finding Inspector Modal */}
      {inspectedFinding && currentCase && (
        <FindingInspectorModal
          finding={inspectedFinding}
          caseEvidence={currentCase.evidence}
          caseFindings={currentCase.findings}
          onClose={() => setInspectedFinding(null)}
          onUpdateStatus={(fId, st) => {
            if (onUpdateFindingStatus) onUpdateFindingStatus(currentCase.id, fId, st);
            setInspectedFinding((prev) => (prev ? { ...prev, status: st } : null));
          }}
          onNavigateToFinding={(fId) => {
            const next = currentCase.findings.find((f) => f.id === fId);
            if (next) setInspectedFinding(next);
          }}
        />
      )}
    </div>
  );
};
