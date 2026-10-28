import { CaseRecord, EvidenceItem, Finding, SeverityLevel } from '../types';

const STORAGE_KEY = 'veylith_cases_v1';
const ACTIVE_CASE_KEY = 'veylith_active_case_id';

export const INITIAL_CASES: CaseRecord[] = [
  {
    id: '#VY-2025-0047',
    title: 'Malicious File Analysis',
    description: 'Analysis of a suspicious executable file identified in internal perimeter telemetry attempting outbound beaconing to untrusted infrastructure.',
    priority: 'High',
    status: 'In Progress',
    leadAnalyst: 'Alex Carter',
    createdAt: '2025-04-21T09:30:00Z',
    updatedAt: '2025-04-22T14:18:00Z',
    scope: ['Perimeter Gateway', 'DESKTOP-01', 'DNS Logs'],
    tags: ['malware', 'file_analysis', 'C2', 'powershell'],
    evidence: [
      {
        id: 'ev-1',
        caseId: '#VY-2025-0047',
        name: 'invoice_update.exe',
        type: 'file',
        value: '3f2a8e01bf284dc1799a941829e248b19c4d7e23118a8bcf105d15c89c4d',
        confidence: 'Observed',
        source: 'Endpoint Agent (DESKTOP-01)',
        timestamp: '2025-04-21T10:15:00Z',
        notes: 'File masquerading as PDF invoice with MZ header and high entropy.',
      },
      {
        id: 'ev-2',
        caseId: '#VY-2025-0047',
        name: 'malicious-site.net',
        type: 'domain',
        value: 'malicious-site.net',
        confidence: 'Confirmed',
        source: 'DNS Telemetry & HTTP Probe',
        timestamp: '2025-04-21T11:00:00Z',
        notes: 'DGA-like domain created 14 days ago without valid TLS.',
      },
      {
        id: 'ev-3',
        caseId: '#VY-2025-0047',
        name: '192.0.2.45',
        type: 'ip',
        value: '192.0.2.45',
        confidence: 'Observed',
        source: 'Firewall Egress Log',
        timestamp: '2025-04-21T11:30:00Z',
        notes: 'Target IP for recurrent 60s beacon packets.',
      },
      {
        id: 'ev-4',
        caseId: '#VY-2025-0047',
        name: 'CVE-2024-6678',
        type: 'cve',
        value: 'CVE-2024-6678 (CVSS 8.8)',
        confidence: 'Inferred',
        source: 'Vulnerability Intelligence',
        timestamp: '2025-04-22T08:00:00Z',
        notes: 'Known RCE vulnerability leveraged for initial broker access.',
      },
    ],
    findings: [
      {
        id: 'f-1',
        title: 'Binary Masquerading via Disguised Extension',
        description: 'The artifact invoice_update.exe has a PE32 executable header despite being delivered with PDF branding.',
        severity: 'High',
        confidence: 'Observed',
        status: 'Investigating',
        sourceTool: 'Veylith File Forensics',
        collectedAt: '2025-04-21T10:20:00Z',
        relevantInput: 'invoice_update.exe',
        evidenceIds: ['ev-1'],
      },
      {
        id: 'f-2',
        title: 'C2 Infrastructure Communication Link',
        description: 'Periodic beaconing observed from host DESKTOP-01 to 192.0.2.45 matching domain malicious-site.net.',
        severity: 'Critical',
        confidence: 'Confirmed',
        status: 'Unresolved',
        sourceTool: 'Veylith Evidence Correlator',
        collectedAt: '2025-04-21T12:00:00Z',
        relevantInput: '192.0.2.45',
        evidenceIds: ['ev-2', 'ev-3'],
      },
    ],
    notes: [
      {
        id: 'n-1',
        author: 'Alex Carter',
        text: 'Initial triage completed. Host DESKTOP-01 has been isolated pending RAM forensics capture.',
        timestamp: '2025-04-21T10:45:00Z',
      },
      {
        id: 'n-2',
        author: 'Alex Carter',
        text: 'Correlated C2 IP address with known bulletproof hosting ASN. Escalating to Incident Commander.',
        timestamp: '2025-04-22T09:15:00Z',
      },
    ],
    auditLog: [
      {
        id: 'a-1',
        action: 'CASE_CREATED',
        actor: 'Alex Carter',
        timestamp: '2025-04-21T09:30:00Z',
        details: 'Case initiated from perimeter telemetry trigger.',
      },
      {
        id: 'a-2',
        action: 'EVIDENCE_ADDED',
        actor: 'Alex Carter',
        timestamp: '2025-04-21T10:15:00Z',
        details: 'Added file artifact invoice_update.exe with SHA-256 hash.',
      },
      {
        id: 'a-3',
        action: 'EVIDENCE_CORRELATED',
        actor: 'Veylith Correlation Engine',
        timestamp: '2025-04-21T12:00:00Z',
        details: 'Correlated domain malicious-site.net with IP 192.0.2.45.',
      },
    ],
  },
  {
    id: '#VY-2025-0048',
    title: 'Suspicious Domain Investigation',
    description: 'Investigation into newly registered lookalike domain mimicking corporate VPN portal.',
    priority: 'High',
    status: 'In Progress',
    leadAnalyst: 'Alex Carter',
    createdAt: '2025-04-22T07:15:00Z',
    updatedAt: '2025-04-22T12:30:00Z',
    scope: ['Domain Infrastructure', 'Certificate Transparency'],
    tags: ['phishing', 'typosquatting', 'dns'],
    evidence: [
      {
        id: 'ev-5',
        caseId: '#VY-2025-0048',
        name: 'login-corp-auth.com',
        type: 'domain',
        value: 'login-corp-auth.com',
        confidence: 'Observed',
        source: 'Certificate Transparency Logs',
        timestamp: '2025-04-22T07:30:00Z',
        notes: 'Domain registered via NameCheap with Let’s Encrypt certificate.',
      },
    ],
    findings: [
      {
        id: 'f-3',
        title: 'High-Probability Brand Impersonation Domain',
        description: 'Domain incorporates corporate brand name with auth prefix, targeting employee Single Sign-On credentials.',
        severity: 'High',
        confidence: 'Confirmed',
        status: 'Investigating',
        sourceTool: 'Veylith Domain Intelligence',
        collectedAt: '2025-04-22T08:00:00Z',
        relevantInput: 'login-corp-auth.com',
        evidenceIds: ['ev-5'],
      },
    ],
    notes: [
      {
        id: 'n-3',
        author: 'Alex Carter',
        text: 'Submitted registrar takedown abuse report and updated proxy blocklists.',
        timestamp: '2025-04-22T08:30:00Z',
      },
    ],
    auditLog: [
      {
        id: 'a-4',
        action: 'CASE_CREATED',
        actor: 'Alex Carter',
        timestamp: '2025-04-22T07:15:00Z',
        details: 'Created case based on proactive domain monitoring alert.',
      },
    ],
  },
  {
    id: '#VY-2025-0046',
    title: 'Ransomware Campaign (IoC)',
    description: 'Cross-organization threat correlation for Akira / LockBit 3.0 affiliate activity indicators.',
    priority: 'Critical',
    status: 'Analyzing',
    leadAnalyst: 'Alex Carter',
    createdAt: '2025-04-20T11:00:00Z',
    updatedAt: '2025-04-22T06:00:00Z',
    scope: ['Threat Intelligence', 'Active Directory', 'EDR'],
    tags: ['ransomware', 'akira', 'lockbit', 'ioc'],
    evidence: [],
    findings: [],
    notes: [],
    auditLog: [],
  },
  {
    id: '#VY-2025-0045',
    title: 'Phishing Infrastructure',
    description: 'Bulk analysis of adversary reverse-proxy infrastructure using Evilginx2.',
    priority: 'Medium',
    status: 'Open',
    leadAnalyst: 'Security Analyst Team',
    createdAt: '2025-04-19T14:20:00Z',
    updatedAt: '2025-04-21T18:40:00Z',
    scope: ['Email Gateway', 'MFA Logs'],
    tags: ['evilginx', 'reverse_proxy', 'session_hijacking'],
    evidence: [],
    findings: [],
    notes: [],
    auditLog: [],
  },
  {
    id: '#VY-2025-0044',
    title: 'Vulnerability Assessment',
    description: 'Audit of edge routers and VPN appliances against CISA KEV CVE-2024-3400 advisory.',
    priority: 'Low',
    status: 'Closed',
    leadAnalyst: 'Alex Carter',
    createdAt: '2025-04-18T08:00:00Z',
    updatedAt: '2025-04-21T17:00:00Z',
    scope: ['Edge Gateways'],
    tags: ['cisa_kev', 'patching', 'audit'],
    evidence: [],
    findings: [],
    notes: [],
    auditLog: [],
  },
];

export function getStoredCases(): CaseRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_CASES));
      return INITIAL_CASES;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : INITIAL_CASES;
  } catch {
    return INITIAL_CASES;
  }
}

export function saveCases(cases: CaseRecord[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  } catch (err) {
    console.error('Failed to save cases to local storage:', err);
  }
}

export function getActiveCaseId(): string {
  return localStorage.getItem(ACTIVE_CASE_KEY) || '#VY-2025-0047';
}

export function setActiveCaseId(id: string): void {
  localStorage.setItem(ACTIVE_CASE_KEY, id);
}

export function createCase(newCase: {
  title: string;
  description: string;
  priority: SeverityLevel;
  leadAnalyst: string;
  scope: string[];
  tags: string[];
}): CaseRecord {
  const cases = getStoredCases();
  const nextNum = cases.length + 45;
  const id = `#VY-2025-${String(nextNum).padStart(4, '0')}`;
  const now = new Date().toISOString();

  const createdRecord: CaseRecord = {
    id,
    title: newCase.title,
    description: newCase.description,
    priority: newCase.priority,
    status: 'Open',
    leadAnalyst: newCase.leadAnalyst || 'Alex Carter',
    createdAt: now,
    updatedAt: now,
    scope: newCase.scope,
    tags: newCase.tags,
    evidence: [],
    findings: [],
    notes: [],
    auditLog: [
      {
        id: `audit-${Date.now()}`,
        action: 'CASE_CREATED',
        actor: newCase.leadAnalyst || 'Alex Carter',
        timestamp: now,
        details: `Case ${id} initialized.`,
      },
    ],
  };

  cases.unshift(createdRecord);
  saveCases(cases);
  setActiveCaseId(id);
  return createdRecord;
}

export function addEvidenceToCase(caseId: string, evidenceData: Omit<EvidenceItem, 'id' | 'timestamp'>): EvidenceItem {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);

  const now = new Date().toISOString();
  const item: EvidenceItem = {
    ...evidenceData,
    id: `ev-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    caseId,
    timestamp: now,
  };

  c.evidence.push(item);
  c.updatedAt = now;
  c.auditLog.push({
    id: `audit-${Date.now()}`,
    action: 'EVIDENCE_ADDED',
    actor: 'Security Analyst',
    timestamp: now,
    details: `Added ${item.type} evidence: "${item.name}" (${item.confidence})`,
  });

  saveCases(cases);
  return item;
}

export function addFindingToCase(caseId: string, findingData: Omit<Finding, 'id' | 'collectedAt'>): Finding {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);

  const now = new Date().toISOString();
  const finding: Finding = {
    ...findingData,
    id: `f-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    collectedAt: now,
  };

  c.findings.push(finding);
  c.updatedAt = now;
  c.auditLog.push({
    id: `audit-${Date.now()}`,
    action: 'FINDING_LOGGED',
    actor: 'Security Analyst',
    timestamp: now,
    details: `Logged finding: "${finding.title}" [${finding.severity}]`,
  });

  saveCases(cases);
  return finding;
}

export function addNoteToCase(caseId: string, author: string, text: string): void {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;

  const now = new Date().toISOString();
  c.notes.push({
    id: `note-${Date.now()}`,
    author,
    text,
    timestamp: now,
  });
  c.updatedAt = now;
  saveCases(cases);
}

export function updateCaseStatus(caseId: string, status: CaseRecord['status']): void {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;

  c.status = status;
  c.updatedAt = new Date().toISOString();
  c.auditLog.push({
    id: `audit-${Date.now()}`,
    action: 'STATUS_UPDATED',
    actor: 'Security Analyst',
    timestamp: c.updatedAt,
    details: `Case status changed to ${status}.`,
  });
  saveCases(cases);
}

export function deleteCase(caseId: string): void {
  let cases = getStoredCases();
  cases = cases.filter((c) => c.id !== caseId);
  saveCases(cases);
}
