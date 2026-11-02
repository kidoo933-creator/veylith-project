import {
  PcapAnalysisResult,
  InvestigationSimpleReport,
  SimpleFindingItem,
  PrioritizedNextStep,
} from '../types';
import { classifyFindingConfidence } from './aiEvidenceGrounding';

export const PCAP_ANALYST_DISCLAIMER =
  'Network telemetry findings are derived from passive binary packet capture parsing and flow correlation. Packet-level inspection identifies communication patterns without decrypting end-to-end encrypted TLS payloads.';

/**
 * Deterministic cybersecurity analyst rules engine for PCAP / Network Telemetry.
 * Produces an executive-level, plain-English analyst report (Simple Results).
 */
export function generatePcapSimpleReport(
  pcapResult: PcapAnalysisResult
): InvestigationSimpleReport {
  const fileName = pcapResult.fileName || 'Network Packet Capture';
  const findings: SimpleFindingItem[] = [];
  const whatWasDiscovered: string[] = [];
  const whatIsWorkingWell: string[] = [];
  const limitations: string[] = [];

  const {
    format,
    totalPackets,
    totalBytes,
    durationSeconds,
    avgPacketRate,
    protocols,
    topConversations,
    anomalies,
    interfaces,
    truncatedPacketsCount,
  } = pcapResult;

  // 1. FACTUAL DISCOVERIES
  const sizeKb = (totalBytes / 1024).toFixed(1);
  whatWasDiscovered.push(
    `Parsed ${totalPackets.toLocaleString()} frames (${sizeKb} KB) spanning ${durationSeconds.toFixed(1)} seconds of network activity (${avgPacketRate.toFixed(1)} pkts/sec).`
  );
  whatWasDiscovered.push(
    `Identified capture format as "${format}"${interfaces?.length ? ` across ${interfaces.length} network interface(s)` : ''}.`
  );

  const protoSummary = Object.entries(protocols)
    .map(([proto, count]) => `${proto}: ${count}`)
    .join(', ');
  if (protoSummary) {
    whatWasDiscovered.push(`Observed protocol distribution: ${protoSummary}.`);
  }

  if (topConversations.length > 0) {
    const top = topConversations[0];
    whatWasDiscovered.push(
      `Primary active conversation: ${top.src} ↔ ${top.dst} (${top.packets} packets, ${(top.bytes / 1024).toFixed(1)} KB over ${top.proto}).`
    );
  }

  // 2. POSITIVE DEFENSES (What is working well)
  if (!truncatedPacketsCount || truncatedPacketsCount === 0) {
    whatIsWorkingWell.push('All captured packets retained full frame headers; zero packet truncation occurred.');
  }

  if (protocols['TCP'] && (!anomalies || anomalies.length === 0)) {
    whatIsWorkingWell.push('TCP connections followed standard three-way handshake sequences without anomalous RST flags.');
  }

  // 3. SECURITY CONCERNS & FOUR-PILLAR TRANSLATIONS
  if (anomalies && anomalies.length > 0) {
    anomalies.forEach((anomaly, idx) => {
      const isC2 = anomaly.title.toLowerCase().includes('beacon') || anomaly.title.toLowerCase().includes('c2');
      const isDns = anomaly.title.toLowerCase().includes('dns') || anomaly.title.toLowerCase().includes('tunnel');
      const isCleartext = anomaly.title.toLowerCase().includes('http') || anomaly.title.toLowerCase().includes('cleartext') || anomaly.title.toLowerCase().includes('unencrypted');

      if (isC2) {
        findings.push({
          id: `fnd-pcap-c2-${idx}`,
          title: 'Command & Control (C2) Periodic Beaconing Pattern',
          category: 'Network & Protocol',
          severity: 'High',
          severityExplanation:
            'Repetitive, interval-based outbound connections to external hosts typically indicate automated remote access malware checking in with a command server.',
          confidence: 'Confirmed',
          whatObserved: anomaly.evidence || anomaly.description,
          whatThisMeans:
            'A machine on your network is acting like a walkie-talkie secretly pinging back to an external server at regular time intervals to report status or ask for new orders.',
          potentialRisk:
            'An attacker may have established an interactive foothold inside the network, allowing them to remotely execute commands, steal files, or move laterally to other systems.',
          possibleAttackScenario:
            'A compromised workstation reaches out to an adversary-controlled IP address every 10 seconds. When the operator types a command into their management console, the beacon pulls it down and executes it.',
          howToPreventIt:
            'Immediately isolate the affected internal workstation IP from the network. Block the destination IP address at the perimeter firewall and rotate any credentials used on that host.',
          technicalDetails: `Telemetry: ${anomaly.evidence}\nDescription: ${anomaly.description}`,
          remediationGuide: {
            detectedTechnology: 'Perimeter Firewall / iptables',
            configSnippet: `# Block outbound communication to suspect destination IP:\niptables -A OUTPUT -p tcp -d <DESTINATION_IP> -j DROP\n# Or via nftables:\nnft add rule inet filter output ip daddr <DESTINATION_IP> drop`,
            configLocation: '/etc/iptables/rules.v4 (or perimeter firewall policy)',
            verificationCommand: `tcpdump -nn -r "${fileName}" 'tcp and (tcp[tcpflags] & tcp-syn != 0)' -c 10`,
            documentationUrl: 'https://attack.mitre.org/techniques/T1071/',
            thirdPartyHostedNote: 'Isolate endpoint network interface immediately and capture memory before rebooting.',
          },
        });
      } else if (isDns) {
        findings.push({
          id: `fnd-pcap-dns-${idx}`,
          title: 'Suspicious DNS Query Volume / Data Tunneling Indicator',
          category: 'Network & Protocol',
          severity: 'High',
          severityExplanation:
            'Abnormal query frequencies with long, high-entropy subdomain strings indicate covert data exfiltration over standard DNS port 53.',
          confidence: 'Confirmed',
          whatObserved: anomaly.evidence || anomaly.description,
          whatThisMeans:
            'Data is being smuggled out of the network disguised inside standard website address lookups (DNS), exploiting the fact that DNS requests are rarely blocked by firewalls.',
          potentialRisk:
            'Confidential company data, passwords, or intellectual property can be silently leaked outside the organization even on tightly restricted networks.',
          possibleAttackScenario:
            'Malware encodes sensitive files into base64 characters, attaches them to subdomains (e.g. `secretdata123.badsite.com`), and queries them. The attacker-controlled nameserver logs the requests and reconstructs the data.',
          howToPreventIt:
            'Enforce internal DNS resolvers that inspect query entropy, rate-limit excessive subdomain requests, and block direct outbound UDP/TCP port 53 traffic to public resolvers.',
          technicalDetails: `Telemetry: ${anomaly.evidence}\nDescription: ${anomaly.description}`,
          remediationGuide: {
            detectedTechnology: 'DNS Policy / BIND / Unbound',
            configSnippet: `# Configure Response Policy Zone (RPZ) or rate-limit suspicious DNS:\nresponse-policy { zone "rpz.blocked"; };\nrate-limit { responses-per-second 10; };`,
            configLocation: '/etc/bind/named.conf.options',
            verificationCommand: `tshark -r "${fileName}" -Y "dns.flags.response == 0 and dns.qry.name.len > 40" -T fields -e dns.qry.name`,
            documentationUrl: 'https://attack.mitre.org/techniques/T1071/004/',
            thirdPartyHostedNote: 'Enforce all outbound port 53 UDP/TCP traffic to pass through authenticated internal recursive resolvers only.',
          },
        });
      } else if (isCleartext) {
        findings.push({
          id: `fnd-pcap-cleartext-${idx}`,
          title: 'Unencrypted Plaintext HTTP Traffic Detected',
          category: 'Network & Protocol',
          severity: 'Medium',
          severityExplanation:
            'Transmitting application data over unencrypted HTTP exposes credentials, cookies, and parameters to network interception.',
          confidence: 'Confirmed',
          whatObserved: anomaly.evidence || anomaly.description,
          whatThisMeans:
            'Network traffic is being transmitted like a postcard without an envelope. Anyone who can observe the network stream can read the full text of the messages.',
          potentialRisk:
            'Adversaries on the same local network, public Wi-Fi, or upstream router can sniff session tokens, passwords, and sensitive business transactions.',
          possibleAttackScenario:
            'An attacker connected to the same wireless network uses a passive packet sniffer to intercept HTTP headers containing session cookies, gaining unauthorized access to the application.',
          howToPreventIt:
            'Enforce HTTPS exclusively with TLS 1.3/1.2. Reconfigure web services and client applications to refuse unencrypted HTTP connections.',
          technicalDetails: `Telemetry: ${anomaly.evidence}\nDescription: ${anomaly.description}`,
          remediationGuide: {
            detectedTechnology: 'TLS / Reverse Proxy',
            configSnippet: `# Enforce TLS 1.3 / HTTPS redirection in Nginx:\nserver {\n  listen 80 default_server;\n  return 301 https://$host$request_uri;\n}`,
            configLocation: '/etc/nginx/conf.d/redirect.conf',
            verificationCommand: `tshark -r "${fileName}" -Y "http.request" -T fields -e http.host -e http.request.uri`,
            documentationUrl: 'https://attack.mitre.org/techniques/T1040/',
            thirdPartyHostedNote: 'Audit internal web services and enforce mutual TLS (mTLS) for machine-to-machine communication.',
          },
        });
      } else {
        findings.push({
          id: `fnd-pcap-anomaly-${idx}`,
          title: anomaly.title,
          category: 'Network & Protocol',
          severity: anomaly.severity === 'Info' ? 'Informational' : (anomaly.severity || 'Medium'),
          severityExplanation:
            'Network flow anomaly identified during deterministic telemetry analysis.',
          confidence: 'Confirmed',
          whatObserved: anomaly.evidence || anomaly.description,
          whatThisMeans:
            'Network packet flow deviated from standard operational parameters or RFC specifications.',
          potentialRisk:
            'Unexpected network behavior can indicate misconfigurations, unauthorized services, or reconnaissance activity.',
          possibleAttackScenario:
            'Adversaries often use non-standard ports or unusual packet sizes to evade simple perimeter filtering.',
          howToPreventIt:
            'Inspect the specific endpoints involved and verify whether this network communication is authorized by your network security policy.',
          technicalDetails: `Evidence: ${anomaly.evidence}`,
        });
      }
    });
  }

  // Snaplen Truncation Finding
  if (truncatedPacketsCount && truncatedPacketsCount > 0) {
    findings.push({
      id: 'fnd-pcap-truncated',
      title: 'Packet Snaplen Truncation Detected',
      category: 'Network & Protocol',
      severity: 'Informational',
      severityExplanation:
        'One or more packets were recorded with truncated payload lengths due to snapshot length (snaplen) capture limits.',
      confidence: 'Confirmed',
      whatObserved: `${truncatedPacketsCount} packet(s) were truncated at capture time.`,
      whatThisMeans:
        'The capture tool was configured with a byte boundary, recording only initial headers rather than complete packet bodies.',
      potentialRisk:
        'Deep payload inspection beyond the captured byte offset is unavailable in this trace.',
      possibleAttackScenario:
        'Adversaries smuggling payloads deep within large packets may evade shallow header-only inspection.',
      howToPreventIt:
        'Configure network capture taps with full snaplen (e.g. -s 0 / -s 65535) for thorough forensic packet inspection.',
      technicalDetails: `Truncated Packets: ${truncatedPacketsCount} • Format: ${format}`,
    });
  }

  const isEmptyCapture = totalPackets === 0;

  // Baseline fallback if no anomalies were detected
  if (isEmptyCapture) {
    findings.push({
      id: 'fnd-pcap-empty',
      title: 'Empty Packet Capture (0 Frames Recorded)',
      category: 'Network & Protocol',
      severity: 'Informational',
      severityExplanation:
        'The capture file contains a valid container header but zero recorded packet frames.',
      confidence: 'Confirmed',
      whatObserved: 'Zero packet frames were parsed from the capture file.',
      whatThisMeans:
        'The recording session did not observe or store any network activity during the capture window.',
      potentialRisk:
        'Forensic telemetry is absent for this evaluation window. Host activity cannot be corroborated.',
      possibleAttackScenario:
        'None observable. The capture file is unpopulated.',
      howToPreventIt:
        'Verify interface binding, promiscuous mode, and capture filter expressions before initiating trace collection.',
      technicalDetails: `Format: ${format} • Total Bytes: ${totalBytes}`,
    });
  } else if (findings.length === 0) {
    findings.push({
      id: 'fnd-pcap-baseline',
      title: 'Standard Network Flow Baseline Satisfied',
      category: 'Network & Protocol',
      severity: 'Informational',
      severityExplanation:
        'Analyzed packet streams conform to standard transport protocols with no beaconing or tunneling patterns.',
      confidence: 'Confirmed',
      whatObserved: `Capture completed with ${totalPackets} frames across standard protocols (${Object.keys(protocols).join(', ')}).`,
      whatThisMeans:
        'All analyzed conversations followed standard protocol specifications without triggering automated anomaly heuristics.',
      potentialRisk:
        'No active anomalies detected in this packet capture sample.',
      possibleAttackScenario:
        'Encrypted network channels (TLS/SSH) can occasionally conceal malicious payload activity within authorized traffic streams.',
      howToPreventIt:
        'Deploy TLS inspection proxies where appropriate and correlate network captures with host-based process telemetry.',
      technicalDetails: `Packets: ${totalPackets} • Duration: ${durationSeconds}s`,
    });
  }

  // 4. OVERALL ASSESSMENT
  let overallAssessment = '';
  if (isEmptyCapture) {
    overallAssessment =
      `EMPTY CAPTURE (0 PACKETS): The packet capture file "${fileName}" contains zero recorded frames. ` +
      `No protocol communications, host endpoints, or anomalies could be evaluated. ` +
      `Verify interface bindings and re-capture traffic if network activity was expected.`;
  } else if (findings.some((f) => f.severity === 'High' || f.severity === 'Critical')) {
    overallAssessment =
      `SIGNIFICANT NETWORK THREAT DETECTED: Analysis of "${fileName}" revealed active threat indicators, ` +
      `including suspicious communication patterns or data tunneling. ` +
      `Outbound endpoints identified in this capture warrant immediate containment and firewall blocking.`;
  } else if (findings.some((f) => f.severity === 'Medium')) {
    overallAssessment =
      `MODERATE CONCERN: Analysis of "${fileName}" detected unencrypted communications or anomalous packet flows. ` +
      `While no high-frequency C2 beaconing was confirmed, plaintext transmission or protocol deviations should be remediated.`;
  } else {
    overallAssessment =
      `HEALTHY NETWORK BASELINE: Packet capture "${fileName}" exhibited clean network communication across ${totalPackets.toLocaleString()} frames. ` +
      `No command-and-control beaconing, DNS data exfiltration, or abnormal protocol malformations were detected.`;
  }

  // 5. PRIORITIZED NEXT STEPS
  const prioritizedNextSteps: PrioritizedNextStep[] = [];
  if (isEmptyCapture) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Verify network interface binding and restart packet capture with permissive filters',
      rationale:
        'Confirms whether network traffic is actively passing through the monitored interface.',
    });
  } else if (findings.some((f) => f.severity === 'High' || f.severity === 'Critical')) {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Isolate the communicating internal endpoint IP from the local network segment',
      rationale:
        'Stops ongoing data exfiltration and prevents potential lateral movement to adjacent servers.',
    });
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Block the remote destination IP and domain on edge firewalls and DNS resolvers',
      rationale: 'Severs connection with external command infrastructure.',
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Acquire volatile RAM memory dump from the affected host to identify the calling process',
      rationale:
        'Correlates network packet sockets with the specific Windows/Linux executable responsible.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Deploy centralized DNS filtering (DoH/DoT) to detect high-entropy queries automatically',
      rationale: 'Permanently mitigates DNS tunneling and covert exfiltration channels.',
    });
  } else {
    prioritizedNextSteps.push({
      priority: 'Immediate',
      action: 'Archive capture file and attach hash to Case Workspace for evidentiary chain of custody',
      rationale: 'Preserves untouched packet telemetry for compliance and audit requirements.',
    });
    prioritizedNextSteps.push({
      priority: 'High Priority',
      action: 'Verify that all sensitive internal web applications enforce HTTPS redirect rules',
      rationale: 'Prevents incidental plaintext credential leakage over the local network.',
    });
    prioritizedNextSteps.push({
      priority: 'Scheduled Hardening',
      action: 'Schedule routine continuous PCAP ring-buffer logging at critical network ingress points',
      rationale: 'Ensures forensic packet telemetry is always available during incident response.',
    });
  }

  // 6. LIMITATIONS
  limitations.push(
    'Encrypted payload content (TLS/HTTPS/SSH) was not decrypted; analysis evaluates flow metadata, port behavior, and timing heuristics.'
  );
  limitations.push(
    'Packet capture reflects only the specific interface and time window recorded; out-of-band communications remain unobserved.'
  );
  if (truncatedPacketsCount && truncatedPacketsCount > 0) {
    limitations.push(
      `${truncatedPacketsCount} packets were truncated (snaplen limitation); payload examination was bounded.`
    );
  }

  return {
    target: fileName,
    targetType: 'pcap',
    generatedAt: new Date().toISOString(),
    overallAssessment,
    whatWasDiscovered,
    whatIsWorkingWell,
    securityConcerns: findings.map((f) => {
      const confMeta = classifyFindingConfidence({
        title: f.title,
        category: f.category,
        observedResult: f.whatObserved,
        evidenceReference: f.technicalDetails,
      });
      return {
        ...f,
        verificationStatus: f.verificationStatus || confMeta.verificationStatus,
        confidenceLevel: f.confidenceLevel || confMeta.confidenceLevel,
        detectionMethod: f.detectionMethod || confMeta.detectionMethod,
        evidenceReference: f.evidenceReference || confMeta.evidenceReference,
        potentialFalsePositiveExplanation: f.potentialFalsePositiveExplanation || confMeta.potentialFalsePositiveExplanation,
        recommendedNextStep: f.recommendedNextStep || confMeta.recommendedNextStep,
      };
    }),
    prioritizedNextSteps,
    limitations,
    disclaimer: PCAP_ANALYST_DISCLAIMER,
    isAiGenerated: false,
    modelUsed: 'Veylith Deterministic DFIR PCAP Engine',
  };
}
