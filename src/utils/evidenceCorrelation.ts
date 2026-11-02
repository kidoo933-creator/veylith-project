import { CaseRecord, EvidenceItem, Finding, ConfidenceLevel } from '../types';

export interface CorrelationNode {
  id: string;
  type: 'case' | 'domain' | 'ip' | 'file' | 'hash' | 'cve' | 'observation';
  label: string;
  caseId: string;
  confidence: ConfidenceLevel;
  source: string;
  timestamp: string;
  metadata?: string;
  underlyingEvidence?: EvidenceItem;
  underlyingFinding?: Finding;
  x: number;
  y: number;
}

export type CorrelationType =
  | 'DOMAIN_TO_IP'
  | 'IP_TO_PCAP_ENDPOINT'
  | 'FILE_TO_HASH'
  | 'CVE_TO_ASSET'
  | 'DNS_TO_NETWORK'
  | 'FINDING_TO_EVIDENCE'
  | 'FINDING_TO_FINDING'
  | 'SCOPE_ARTIFACT';

export interface CorrelationEdge {
  id: string;
  source: string;
  target: string;
  reason: string;
  evidenceSource: string;
  confidence: ConfidenceLevel;
  underlyingFindingId?: string;
  underlyingFinding?: Finding;
  sourceFindingId?: string;
  timestamp: string;
  provenance: string;
  isInferred: boolean;
  inferredReason?: string;
  correlationType?: CorrelationType;
  status?: 'confirmed' | 'unverified' | 'dismissed';
}

export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Checks for exact IP address occurrence in text.
 * Strictly prevents substring matching (e.g. '10.0.0.1' inside '10.0.0.15' or '110.0.0.1').
 */
export function hasExactIpMatch(text: string, ip: string): boolean {
  if (!text || !ip) return false;
  const trimmed = ip.trim();
  if (!trimmed) return false;

  // Exact whole value match
  if (text.trim() === trimmed) return true;

  // IPv4: delimiters must not be digits or dots
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
    const regex = new RegExp(`(?<=^|[^0-9.])${escapeRegex(trimmed)}(?=[^0-9.]|$)`);
    return regex.test(text);
  }

  // IPv6: delimiters must not be hex characters or colons
  if (trimmed.includes(':')) {
    const regex = new RegExp(`(?<=^|[^a-fA-F0-9:])${escapeRegex(trimmed)}(?=[^a-fA-F0-9:]|$)`, 'i');
    return regex.test(text);
  }

  return false;
}

/**
 * Checks for exact domain occurrence in text.
 * Strictly prevents substring collisions (e.g. 'example.com' inside 'badexample.com' or 'example.company.com').
 */
export function hasExactDomainMatch(text: string, domain: string): boolean {
  if (!text || !domain) return false;
  const cleanDomain = domain.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!cleanDomain || !cleanDomain.includes('.')) return false;

  // Whole domain token match: boundary cannot be a valid hostname character (alphanumeric, hyphen, or dot)
  const regex = new RegExp(`(?<=^|[^a-zA-Z0-9.-])${escapeRegex(cleanDomain)}(?=[^a-zA-Z0-9.-]|$)`, 'i');
  return regex.test(text);
}

/**
 * Checks for exact cryptographic hash occurrence in text.
 * Strictly prevents substring collisions (e.g. 32-char prefix inside a 64-char SHA-256).
 */
export function hasExactHashMatch(text: string, hash: string): boolean {
  if (!text || !hash) return false;
  const cleanHash = hash.trim().toLowerCase();
  if (!/^[a-f0-9]{32,64}$/i.test(cleanHash)) return false;

  const regex = new RegExp(`(?<=^|[^a-fA-F0-9])${escapeRegex(cleanHash)}(?=[^a-fA-F0-9]|$)`, 'i');
  return regex.test(text);
}

/**
 * Checks for exact CVE ID occurrence in text.
 * Strictly prevents prefix collisions (e.g. CVE-2023-1234 inside CVE-2023-12345).
 */
export function hasExactCveMatch(text: string, cveId: string): boolean {
  if (!text || !cveId) return false;
  const cleanCve = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cleanCve)) return false;

  const regex = new RegExp(`(?<=^|[^a-zA-Z0-9_-])${escapeRegex(cleanCve)}(?=[^a-zA-Z0-9_-]|$)`, 'i');
  return regex.test(text);
}

/**
 * Deterministically builds an evidence correlation graph from case records.
 * Strictly avoids connecting unrelated entities simply because they share a case.
 */
/**
 * Deterministically builds an evidence correlation graph from case records.
 * Strictly avoids connecting unrelated entities simply because they share a case.
 */
export function buildEvidenceGraph(
  cases: CaseRecord[],
  options?: { includeDismissed?: boolean }
): {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
} {
  const nodeList: CorrelationNode[] = [];
  const edgeList: CorrelationEdge[] = [];
  const nodeMap = new Map<string, CorrelationNode>();
  const edgeSet = new Set<string>();

  cases.forEach((cs, cIdx) => {
    const addEdge = (edge: CorrelationEdge) => {
      const key = `${edge.source}->${edge.target}:${edge.reason}`;
      const reverseKey = `${edge.target}->${edge.source}:${edge.reason}`;
      if (!edgeSet.has(key) && !edgeSet.has(reverseKey)) {
        edgeSet.add(key);

        // Apply analyst overrides or explicit case dismissal/unverified arrays
        if (cs.dismissedCorrelationIds?.includes(edge.id)) {
          edge.status = 'dismissed';
          if (!options?.includeDismissed) {
            return;
          }
        } else if (cs.unverifiedCorrelationIds?.includes(edge.id)) {
          edge.status = 'unverified';
          edge.confidence = 'Potential';
        } else if (cs.correlationOverrides?.[edge.id]) {
          edge.status = cs.correlationOverrides[edge.id];
          if (edge.status === 'unverified') {
            edge.confidence = 'Potential';
          }
          if (options?.includeDismissed === false && edge.status === 'dismissed') {
            return;
          }
        } else if (!edge.status) {
          edge.status = edge.isInferred ? 'unverified' : 'confirmed';
        }

        edgeList.push(edge);
      }
    };

    // 1. Case Root Node
    const caseNodeId = `case-${cs.id}`;
    if (!nodeMap.has(caseNodeId)) {
      const caseNode: CorrelationNode = {
        id: caseNodeId,
        type: 'case',
        label: `${cs.id} (${cs.title})`,
        caseId: cs.id,
        confidence: 'Confirmed',
        source: 'Case Master Record',
        timestamp: cs.createdAt,
        metadata: `Priority: ${cs.priority} • Status: ${cs.status} • Lead: ${cs.leadAnalyst}`,
        x: 320 + (cIdx % 2 === 0 ? -160 : 160) * (cIdx > 0 ? 1 : 0),
        y: 70 + cIdx * 90,
      };
      nodeMap.set(caseNodeId, caseNode);
      nodeList.push(caseNode);
    }

    // 2. Evidence Artifact Nodes
    cs.evidence.forEach((ev, eIdx) => {
      const evNodeId = `ev-${cs.id}-${ev.id}`;
      let evType: CorrelationNode['type'] = 'observation';
      if (ev.type === 'domain') evType = 'domain';
      else if (ev.type === 'ip') evType = 'ip';
      else if (ev.type === 'file') evType = 'file';
      else if (ev.type === 'hash') evType = 'hash';
      else if (ev.type === 'cve') evType = 'cve';
      else evType = 'observation';

      if (!nodeMap.has(evNodeId)) {
        const angle = (eIdx / Math.max(cs.evidence.length, 1)) * 2 * Math.PI;
        const radius = 130 + (eIdx % 2) * 35;
        const parentX = nodeMap.get(caseNodeId)?.x || 320;
        const parentY = nodeMap.get(caseNodeId)?.y || 160;

        const evNode: CorrelationNode = {
          id: evNodeId,
          type: evType,
          label: ev.name,
          caseId: cs.id,
          confidence: ev.confidence,
          source: ev.source,
          timestamp: ev.timestamp,
          metadata: ev.notes || ev.value,
          underlyingEvidence: ev,
          x: Math.max(50, Math.min(590, parentX + Math.cos(angle) * radius)),
          y: Math.max(60, Math.min(340, parentY + Math.sin(angle) * radius)),
        };
        nodeMap.set(evNodeId, evNode);
        nodeList.push(evNode);

        // Edge: Case -> Scope Artifact (Direct ground-truth relationship)
        addEdge({
          id: `edge-${caseNodeId}-${evNodeId}`,
          source: caseNodeId,
          target: evNodeId,
          reason: `Scope Artifact (${ev.source})`,
          evidenceSource: ev.source,
          confidence: ev.confidence,
          timestamp: ev.timestamp || cs.createdAt,
          provenance: `Case Manifest (${cs.id})`,
          isInferred: false,
          correlationType: 'SCOPE_ARTIFACT',
          status: 'confirmed',
        });
      }
    });

    // 3. Finding Nodes and Direct Evidence Citations
    cs.findings.forEach((finding, fIdx) => {
      const findingNodeId = `finding-${cs.id}-${finding.id}`;
      if (!nodeMap.has(findingNodeId)) {
        const findingNode: CorrelationNode = {
          id: findingNodeId,
          type: 'observation',
          label: `Finding: ${finding.title}`,
          caseId: cs.id,
          confidence: finding.confidence,
          source: finding.sourceTool,
          timestamp: finding.collectedAt,
          metadata: finding.description,
          underlyingFinding: finding,
          x: 200 + (fIdx * 140) % 360,
          y: 310 - (fIdx % 2) * 50,
        };
        nodeMap.set(findingNodeId, findingNode);
        nodeList.push(findingNode);

        // Direct Edge: Finding -> Cited Evidence Item
        finding.evidenceIds.forEach((evId) => {
          const citedEvNodeId = `ev-${cs.id}-${evId}`;
          if (nodeMap.has(citedEvNodeId)) {
            addEdge({
              id: `edge-${findingNodeId}-${citedEvNodeId}`,
              source: findingNodeId,
              target: citedEvNodeId,
              reason: `Directly Cited in [${finding.id}] ${finding.title}`,
              evidenceSource: finding.sourceTool,
              confidence: finding.confidence,
              underlyingFindingId: finding.id,
              underlyingFinding: finding,
              sourceFindingId: finding.id,
              timestamp: finding.collectedAt,
              provenance: finding.sourceTool,
              isInferred: false,
              correlationType: 'FINDING_TO_EVIDENCE',
              status: 'confirmed',
            });
          }
        });
      }

      // 4. Inferred relationship between evidence items co-cited together in the same finding
      if (finding.evidenceIds.length >= 2) {
        for (let i = 0; i < finding.evidenceIds.length; i++) {
          for (let j = i + 1; j < finding.evidenceIds.length; j++) {
            const srcEvId = `ev-${cs.id}-${finding.evidenceIds[i]}`;
            const dstEvId = `ev-${cs.id}-${finding.evidenceIds[j]}`;
            if (nodeMap.has(srcEvId) && nodeMap.has(dstEvId)) {
              addEdge({
                id: `edge-${srcEvId}-${dstEvId}-${finding.id}`,
                source: srcEvId,
                target: dstEvId,
                reason: `Correlated via Finding [${finding.id}]: ${finding.title}`,
                evidenceSource: finding.sourceTool,
                confidence: finding.confidence,
                underlyingFindingId: finding.id,
                underlyingFinding: finding,
                sourceFindingId: finding.id,
                timestamp: finding.collectedAt,
                provenance: finding.sourceTool,
                isInferred: true,
                inferredReason: `Both evidence items were jointly cited in analytical finding [${finding.id}]`,
                correlationType: 'FINDING_TO_EVIDENCE',
              });
            }
          }
        }
      }
    });

    // 5. Finding <-> Finding Correlation (Shared Evidence or Documented Linkage)
    if (cs.findings.length >= 2) {
      for (let i = 0; i < cs.findings.length; i++) {
        for (let j = i + 1; j < cs.findings.length; j++) {
          const f1 = cs.findings[i];
          const f2 = cs.findings[j];
          const f1NodeId = `finding-${cs.id}-${f1.id}`;
          const f2NodeId = `finding-${cs.id}-${f2.id}`;
          if (nodeMap.has(f1NodeId) && nodeMap.has(f2NodeId)) {
            const sharedEvIds = f1.evidenceIds.filter((id) => f2.evidenceIds.includes(id));
            const isExplicitlyRelated =
              f1.relatedFindingIds?.includes(f2.id) || f2.relatedFindingIds?.includes(f1.id);

            if (sharedEvIds.length > 0 || isExplicitlyRelated) {
              addEdge({
                id: `edge-finding-${cs.id}-${f1.id}-${f2.id}`,
                source: f1NodeId,
                target: f2NodeId,
                reason: sharedEvIds.length > 0
                  ? `Correlated Investigation Findings (Shared Evidence: ${sharedEvIds.join(', ')})`
                  : `Related Finding Linkage ([${f1.id}] <-> [${f2.id}])`,
                evidenceSource: 'Investigation Finding Correlation Engine',
                confidence: 'Inferred',
                timestamp: f1.collectedAt || f2.collectedAt || cs.createdAt,
                provenance: `Analytical Finding Manifest (${cs.id})`,
                isInferred: true,
                inferredReason: sharedEvIds.length > 0
                  ? `Findings jointly cite common verified evidence item(s): ${sharedEvIds.join(', ')}`
                  : `Documented relationship between findings ${f1.id} and ${f2.id}`,
                correlationType: 'FINDING_TO_FINDING',
                sourceFindingId: f1.id,
                underlyingFindingId: f2.id,
              });
            }
          }
        }
      }
    }

    // 6. Explicit Ground-Truth Telemetry Links (Strict boundary matching only)
    const domains = cs.evidence.filter((e) => e.type === 'domain');
    const ips = cs.evidence.filter((e) => e.type === 'ip');
    const files = cs.evidence.filter((e) => e.type === 'file');
    const hashes = cs.evidence.filter((e) => e.type === 'hash');
    const cves = cs.evidence.filter((e) => e.type === 'cve');
    const pcaps = cs.evidence.filter((e) => e.type === 'pcap');

    // (a) Domain <-> IP: only when exact IP appears in domain telemetry or exact domain appears in IP telemetry
    domains.forEach((d) => {
      const dNodeId = `ev-${cs.id}-${d.id}`;
      ips.forEach((ip) => {
        const ipNodeId = `ev-${cs.id}-${ip.id}`;
        const hasMatch =
          hasExactIpMatch(d.notes || '', ip.value) ||
          hasExactDomainMatch(ip.notes || '', d.name) ||
          hasExactDomainMatch(ip.notes || '', d.value) ||
          d.value === ip.value;

        if (hasMatch) {
          addEdge({
            id: `edge-${dNodeId}-${ipNodeId}-direct`,
            source: dNodeId,
            target: ipNodeId,
            reason: `Observed DNS Resolution (${d.value || d.name} -> ${ip.value})`,
            evidenceSource: 'Recorded Telemetry Notes',
            confidence: 'Confirmed',
            timestamp: d.timestamp || ip.timestamp || cs.createdAt,
            provenance: 'Observed Telemetry Note',
            isInferred: false,
            correlationType: 'DOMAIN_TO_IP',
            status: 'confirmed',
          });
        }
      });

      // (b) File <-> Domain: only when exact domain appears in file static strings telemetry
      files.forEach((f) => {
        const fNodeId = `ev-${cs.id}-${f.id}`;
        if (hasExactDomainMatch(f.notes || '', d.name) || hasExactDomainMatch(f.value || '', d.name)) {
          addEdge({
            id: `edge-${fNodeId}-${dNodeId}-direct`,
            source: fNodeId,
            target: dNodeId,
            reason: `Extracted C2 Target (${d.name})`,
            evidenceSource: 'Static Analysis Artifact',
            confidence: 'Observed',
            timestamp: f.timestamp || cs.createdAt,
            provenance: 'Static String Artifact',
            isInferred: false,
            correlationType: 'DNS_TO_NETWORK',
            status: 'confirmed',
          });
        }
      });
    });

    // (c) File <-> Hash: only when cryptographic hash matches exactly
    files.forEach((f) => {
      const fNodeId = `ev-${cs.id}-${f.id}`;
      hashes.forEach((h) => {
        const hNodeId = `ev-${cs.id}-${h.id}`;
        const isMatch =
          f.value.toLowerCase() === h.value.toLowerCase() ||
          hasExactHashMatch(f.notes || '', h.value);

        if (isMatch) {
          addEdge({
            id: `edge-${fNodeId}-${hNodeId}-direct`,
            source: fNodeId,
            target: hNodeId,
            reason: `Cryptographic Hash Match (${h.value.slice(0, 12)}...)`,
            evidenceSource: 'Integrity Verification',
            confidence: 'Confirmed',
            timestamp: f.timestamp || h.timestamp || cs.createdAt,
            provenance: 'Cryptographic Hash Telemetry',
            isInferred: false,
            correlationType: 'FILE_TO_HASH',
            status: 'confirmed',
          });
        }
      });
    });

    // (d) CVE <-> Asset: only when exact CVE ID appears in asset notes or asset name appears in CVE notes
    cves.forEach((c) => {
      const cNodeId = `ev-${cs.id}-${c.id}`;
      [...ips, ...files, ...domains].forEach((asset) => {
        const assetNodeId = `ev-${cs.id}-${asset.id}`;
        const hasCveMatch =
          hasExactCveMatch(asset.notes || '', c.name) ||
          hasExactCveMatch(asset.notes || '', c.value) ||
          hasExactDomainMatch(c.notes || '', asset.name) ||
          hasExactIpMatch(c.notes || '', asset.name);

        if (hasCveMatch) {
          addEdge({
            id: `edge-${assetNodeId}-${cNodeId}-direct`,
            source: assetNodeId,
            target: cNodeId,
            reason: `Vulnerability Impact Recorded for ${asset.name}`,
            evidenceSource: 'Vulnerability Intelligence Record',
            confidence: 'Inferred',
            timestamp: c.timestamp || asset.timestamp || cs.createdAt,
            provenance: 'Vulnerability Intelligence Record',
            isInferred: true,
            inferredReason: `Asset notes record impact for vulnerability ${c.name}`,
            correlationType: 'CVE_TO_ASSET',
          });
        }
      });
    });

    // (e) IP <-> PCAP: only when exact IP appears in PCAP packet metadata or conversation notes
    pcaps.forEach((pcap) => {
      const pcapNodeId = `ev-${cs.id}-${pcap.id}`;
      ips.forEach((ip) => {
        const ipNodeId = `ev-${cs.id}-${ip.id}`;
        if (hasExactIpMatch(pcap.notes || '', ip.value) || hasExactIpMatch(pcap.value || '', ip.value)) {
          addEdge({
            id: `edge-${ipNodeId}-${pcapNodeId}-pcap`,
            source: ipNodeId,
            target: pcapNodeId,
            reason: `Observed PCAP Endpoint Traffic (${ip.value} in ${pcap.name})`,
            evidenceSource: 'PCAP Conversation Frame Matrix',
            confidence: 'Confirmed',
            timestamp: pcap.timestamp || ip.timestamp || cs.createdAt,
            provenance: `Demuxed from capture ${pcap.name}`,
            isInferred: false,
            correlationType: 'IP_TO_PCAP_ENDPOINT',
            status: 'confirmed',
          });
        }
      });

      // (f) Domain <-> PCAP: only when exact domain appears in PCAP DNS queries or packet notes
      domains.forEach((d) => {
        const dNodeId = `ev-${cs.id}-${d.id}`;
        if (hasExactDomainMatch(pcap.notes || '', d.name) || hasExactDomainMatch(pcap.value || '', d.name)) {
          addEdge({
            id: `edge-${dNodeId}-${pcapNodeId}-dns`,
            source: dNodeId,
            target: pcapNodeId,
            reason: `Network Protocol Observation (${d.name} in ${pcap.name})`,
            evidenceSource: 'Packet Capture Protocol Stream',
            confidence: 'Observed',
            timestamp: pcap.timestamp || d.timestamp || cs.createdAt,
            provenance: `Decoded packet stream from ${pcap.name}`,
            isInferred: false,
            correlationType: 'DNS_TO_NETWORK',
            status: 'confirmed',
          });
        }
      });
    });
  });

  return { nodes: nodeList, edges: edgeList };
}
