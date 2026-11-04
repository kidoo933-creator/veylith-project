import {
  Finding,
  EvidenceItem,
  MitreAttackMapping,
  MitreOverrideStatus,
  ConfidenceLevel,
} from '../types';
import { MITRE_TECHNIQUES, MITRE_TACTICS } from '../data/mitreAttackData';

export { MITRE_TECHNIQUES, MITRE_TACTICS };

/**
 * Maps findings and evidence to MITRE ATT&CK techniques based on defensible forensic rules.
 * Strictly distinguishes evidence-supported mappings from AI-suggested or analyst-defined mappings.
 */
export function mapFindingsToMitreAttack(
  findings: Finding[],
  evidence: EvidenceItem[] = [],
  overrides: Record<string, MitreOverrideStatus> = {}
): MitreAttackMapping[] {
  const mappings: MitreAttackMapping[] = [];
  const mappedKeys = new Set<string>();

  for (const finding of findings) {
    const text = `${finding.title} ${finding.description} ${finding.observedResult} ${finding.detectionMethod || ''}`.toLowerCase();

    // Rule 1: Masquerading (PE executable disguised as PDF, etc.)
    if (text.includes('masquerad') || (text.includes('extension') && text.includes('magic'))) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1036.001')!;
      addMapping({
        finding,
        technique: tech,
        provenance: 'evidence-supported',
        confidence: finding.confidence || 'Confirmed',
        justification: `Direct forensic observation: File magic bytes do not match file extension (${finding.targetEntity}).`,
      });
    }

    // Rule 2: Obfuscation / Software Packing
    if (text.includes('packed') || text.includes('entropy') || text.includes('upx')) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1027')!;
      addMapping({
        finding,
        technique: tech,
        provenance: text.includes('upx') ? 'evidence-supported' : 'ai-suggested',
        confidence: text.includes('upx') ? 'Confirmed' : 'Inferred',
        justification: `Observed high Shannon entropy or packing indicators consistent with payload obfuscation.`,
      });
    }

    // Rule 3: Cleartext Credentials in Network Traffic
    if (text.includes('cleartext') && (text.includes('credential') || text.includes('basic') || text.includes('password'))) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1552.001')!;
      addMapping({
        finding,
        technique: tech,
        provenance: 'evidence-supported',
        confidence: 'Confirmed',
        justification: `Direct telemetry observation: Unencrypted credentials or basic authorization tokens observed in stream payload.`,
      });
    }

    // Rule 4: DNS Tunneling / Exfiltration
    if (text.includes('dns tunneling') || text.includes('high-entropy dns') || text.includes('dns exfiltration')) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1071.004')!;
      addMapping({
        finding,
        technique: tech,
        provenance: 'evidence-supported',
        confidence: 'Confirmed',
        justification: `Anomalous DNS query volume, query length > 40 chars, or hex-encoded subdomains detected in PCAP stream.`,
      });
      // Also exfiltration
      const exfilTech = MITRE_TECHNIQUES.find((t) => t.id === 'T1048.003')!;
      addMapping({
        finding,
        technique: exfilTech,
        provenance: 'ai-suggested',
        confidence: 'Inferred',
        justification: `Potential data exfiltration pathway using alternative DNS transport. Requires staging verification.`,
      });
    }

    // Rule 5: Port Scan / Network Reconnaissance
    if (text.includes('syn port scan') || text.includes('syn flood') || text.includes('reconnaissance')) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1046')!;
      addMapping({
        finding,
        technique: tech,
        provenance: 'evidence-supported',
        confidence: 'Confirmed',
        justification: `High ratio of TCP SYN frames without complete handshakes across target endpoints.`,
      });
    }

    // Rule 6: Missing Security Hardening Headers (Defense Evasion / Weak Perimeter)
    if (text.includes('hsts') || text.includes('csp') || text.includes('security header')) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1562.001')!;
      addMapping({
        finding,
        technique: tech,
        provenance: 'ai-suggested',
        confidence: 'Inferred',
        justification: `Sub-optimal edge defensive configuration observed during passive HTTP evaluation. Note: Missing headers facilitate attacks rather than constitute active exploitation.`,
      });
    }

    // Rule 7: Known CVE / Exploit Vulnerability
    if (finding.category === 'Vulnerability & Exploit' || text.includes('cve-')) {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1190')!;
      addMapping({
        finding,
        technique: tech,
        provenance: finding.confidence === 'Confirmed' ? 'evidence-supported' : 'ai-suggested',
        confidence: finding.confidence,
        justification: `Documented public vulnerability or unpatched external edge gateway component.`,
      });
    }
  }

  // Also check direct evidence items if not covered
  for (const item of evidence) {
    if (item.type === 'cve') {
      const tech = MITRE_TECHNIQUES.find((t) => t.id === 'T1190')!;
      const key = `${item.id}-${tech.id}`;
      if (!mappedKeys.has(key)) {
        mappedKeys.add(key);
        const mapId = `MAP-${item.id}-${tech.id}`;
        mappings.push({
          id: mapId,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tacticId: tech.tacticId,
          tacticName: tech.tacticName,
          mappingProvenance: 'evidence-supported',
          confidence: item.confidence || 'Confirmed',
          evidenceId: item.id,
          justification: `Direct asset association with CVE record (${item.value}).`,
          overrideStatus: overrides[mapId],
          officialReference: tech.referenceUrl,
        });
      }
    }
  }

  function addMapping(params: {
    finding: Finding;
    technique: (typeof MITRE_TECHNIQUES)[0];
    provenance: 'evidence-supported' | 'ai-suggested';
    confidence: ConfidenceLevel;
    justification: string;
  }) {
    const key = `${params.finding.id}-${params.technique.id}`;
    if (mappedKeys.has(key)) return;
    mappedKeys.add(key);

    const mapId = `MAP-${params.finding.id}-${params.technique.id}`;
    mappings.push({
      id: mapId,
      techniqueId: params.technique.id,
      techniqueName: params.technique.name,
      tacticId: params.technique.tacticId,
      tacticName: params.technique.tacticName,
      mappingProvenance: params.provenance,
      confidence: params.confidence,
      findingId: params.finding.id,
      justification: params.justification,
      overrideStatus: overrides[mapId],
      officialReference: params.technique.referenceUrl,
    });
  }

  // Filter out analyst-rejected mappings
  return mappings.filter((m) => m.overrideStatus !== 'rejected');
}
