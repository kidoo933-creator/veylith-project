import { CaseRecord, EvidenceItem, Finding, SeverityLevel, CorrelationStatus, HypothesisItem } from '../types';
import { normalizeFinding } from './findingNormalization';
import { createHypothesisItem } from './hypothesisEngine';
import { TRAINING_SCENARIO_CASES, INITIAL_CASES } from '../data/trainingFixtures';

export { TRAINING_SCENARIO_CASES, INITIAL_CASES };

// Partitioned LocalStorage Keys
export const OPERATIONAL_STORAGE_KEY = 'veylith_cases_v2';
export const TRAINING_STORAGE_KEY = 'veylith_training_cases_v2';
export const APP_MODE_KEY = 'veylith_app_mode_v2';
export const ACTIVE_CASE_KEY = 'veylith_active_case_id_v2';
export const REPORTS_STORAGE_KEY = 'veylith_generated_reports_v2';
export const ANALYST_PROFILE_KEY = 'veylith_analyst_profile_v2';
export const LEGACY_STORAGE_KEYS = ['veylith_cases_v1', 'veylith_active_case_id', 'veylith_cases'];

export type AppMode = 'operational' | 'training';

export type UserRole = 'lead_investigator' | 'forensics_analyst' | 'triage_specialist' | 'read_only_auditor';

export interface AnalystProfile {
  name: string;
  role: string;
  userRole?: UserRole;
  tenantId?: string;
  email: string;
  callsign: string;
}

export const DEFAULT_ANALYST_PROFILE: AnalystProfile = {
  name: 'SecOps Analyst',
  role: 'Digital Forensics Analyst',
  userRole: 'lead_investigator',
  tenantId: 'tenant-default',
  email: 'hacktheboxmeyou@gmail.com',
  callsign: 'SA',
};

export const ROLE_PERMISSIONS: Record<
  UserRole,
  {
    canCreateCase: boolean;
    canEditCase: boolean;
    canDeleteCase: boolean;
    canAddEvidence: boolean;
    canLogFinding: boolean;
    canOverrideCorrelation: boolean;
    canExportReport: boolean;
    canPurgeStorage: boolean;
  }
> = {
  lead_investigator: {
    canCreateCase: true,
    canEditCase: true,
    canDeleteCase: true,
    canAddEvidence: true,
    canLogFinding: true,
    canOverrideCorrelation: true,
    canExportReport: true,
    canPurgeStorage: true,
  },
  forensics_analyst: {
    canCreateCase: true,
    canEditCase: true,
    canDeleteCase: false,
    canAddEvidence: true,
    canLogFinding: true,
    canOverrideCorrelation: true,
    canExportReport: true,
    canPurgeStorage: false,
  },
  triage_specialist: {
    canCreateCase: true,
    canEditCase: false,
    canDeleteCase: false,
    canAddEvidence: true,
    canLogFinding: true,
    canOverrideCorrelation: false,
    canExportReport: true,
    canPurgeStorage: false,
  },
  read_only_auditor: {
    canCreateCase: false,
    canEditCase: false,
    canDeleteCase: false,
    canAddEvidence: false,
    canLogFinding: false,
    canOverrideCorrelation: false,
    canExportReport: true,
    canPurgeStorage: false,
  },
};

export function assertRolePermission(action: keyof (typeof ROLE_PERMISSIONS)['lead_investigator']): void {
  const profile = getAnalystProfile();
  const role: UserRole = profile.userRole || 'lead_investigator';
  const perms = ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.lead_investigator;
  if (!perms[action]) {
    throw new Error(`RBAC Authorization Denied: Role "${role}" lacks permission "${action}".`);
  }
}

export function assertTenantAccess(caseRecord: CaseRecord, activeTenantId?: string): void {
  const tenant = activeTenantId || getAnalystProfile().tenantId || 'tenant-default';
  const caseTenant = caseRecord.tenantId || 'tenant-default';
  if (caseTenant !== tenant) {
    throw new Error(
      `Tenant Isolation Violation: Access denied to case ${caseRecord.id} (case tenant: ${caseTenant}, active session tenant: ${tenant})`
    );
  }
}

export function computeFastAuditHash(
  prevHash: string,
  action: string,
  actor: string,
  timestamp: string,
  details: string
): string {
  const payload = `${prevHash}|${action}|${actor}|${timestamp}|${details}`;
  let h1 = 0xdeadbeef ^ 0;
  let h2 = 0x41c6ce57 ^ 0;
  let h3 = 0x811c9dc5 ^ 0;
  let h4 = 0x9e3779b9 ^ 0;

  for (let i = 0; i < payload.length; i++) {
    const ch = payload.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
    h3 = Math.imul(h3 ^ ch, 2246822519);
    h4 = Math.imul(h4 ^ ch, 3266489917);
  }

  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h3 ^ (h3 >>> 13), 3266489909);
  h3 = Math.imul(h3 ^ (h3 >>> 16), 2246822507) ^ Math.imul(h4 ^ (h4 >>> 13), 3266489909);
  h4 = Math.imul(h4 ^ (h4 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);

  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return (hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h1 ^ h3) + hex(h2 ^ h4) + hex(h1 ^ h4) + hex(h2 ^ h3)).toLowerCase();
}

export function createChainedAuditEntry(
  existingAuditLog: CaseRecord['auditLog'],
  action: string,
  actor: string,
  details: string,
  timestamp?: string
): CaseRecord['auditLog'][0] {
  const ts = timestamp || new Date().toISOString();
  const lastEntry = existingAuditLog && existingAuditLog.length > 0 ? existingAuditLog[existingAuditLog.length - 1] : null;
  const prevHash = lastEntry?.hash || '0000000000000000000000000000000000000000000000000000000000000000';
  const hash = computeFastAuditHash(prevHash, action, actor, ts, details);
  return {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    action,
    actor,
    timestamp: ts,
    details,
    hash,
    prevHash,
  };
}

export function verifyCaseAuditTrailIntegrity(caseRecord: CaseRecord): {
  isValid: boolean;
  brokenAtIndex?: number;
  reason?: string;
} {
  const logs = caseRecord.auditLog || [];
  if (logs.length === 0) return { isValid: true };

  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];
    if (!entry.hash) continue; // skip unhashed legacy entries

    const expectedPrev = i === 0 ? '0000000000000000000000000000000000000000000000000000000000000000' : logs[i - 1].hash;
    if (entry.prevHash && expectedPrev && entry.prevHash !== expectedPrev) {
      return {
        isValid: false,
        brokenAtIndex: i,
        reason: `Hash chain mismatch at index ${i}: prevHash "${entry.prevHash}" does not match previous entry hash "${expectedPrev}".`,
      };
    }

    const calculatedHash = computeFastAuditHash(
      entry.prevHash || expectedPrev || '',
      entry.action,
      entry.actor,
      entry.timestamp,
      entry.details
    );
    if (entry.hash !== calculatedHash) {
      return {
        isValid: false,
        brokenAtIndex: i,
        reason: `Entry digest mismatch at index ${i}: entry has been tampered with or modified after generation.`,
      };
    }
  }

  return { isValid: true };
}

export interface GeneratedReportRecord {
  id: string;
  caseId: string;
  caseTitle: string;
  format: 'pdf' | 'json' | 'html';
  timestamp: string; // UTC ISO-8601
  analystName: string;
  findingCount: number;
  evidenceCount: number;
  isTrainingScenario?: boolean;
}

/**
 * Automatically purges legacy unpartitioned storage keys so returning browsers
 * never retain obsolete mock or seeded fixtures in operational mode.
 */
export function purgeLegacyStorage(): void {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
  try {
    for (const key of LEGACY_STORAGE_KEYS) {
      if (localStorage.getItem(key) !== null) {
        localStorage.removeItem(key);
      }
    }
  } catch {
    // Gracefully ignore storage security exceptions in sandbox environments
  }
}

// Execute immediately on script evaluation
purgeLegacyStorage();

export function getAppMode(): AppMode {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return 'operational';
  try {
    const mode = localStorage.getItem(APP_MODE_KEY);
    return mode === 'training' ? 'training' : 'operational';
  } catch {
    return 'operational';
  }
}

export function setAppMode(mode: AppMode): void {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(APP_MODE_KEY, mode);
  } catch {}
}

let inMemoryProfile: AnalystProfile = { ...DEFAULT_ANALYST_PROFILE };

export function getAnalystProfile(): AnalystProfile {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return inMemoryProfile;
  try {
    const raw = localStorage.getItem(ANALYST_PROFILE_KEY);
    if (!raw) return inMemoryProfile;
    const parsed = JSON.parse(raw);
    return {
      name: parsed.name || inMemoryProfile.name,
      role: parsed.role || inMemoryProfile.role,
      userRole: parsed.userRole || inMemoryProfile.userRole,
      tenantId: parsed.tenantId || inMemoryProfile.tenantId,
      email: parsed.email || inMemoryProfile.email,
      callsign: parsed.callsign || inMemoryProfile.callsign,
    };
  } catch {
    return inMemoryProfile;
  }
}

export function setAnalystProfile(profile: Partial<AnalystProfile>): AnalystProfile {
  const current = getAnalystProfile();
  const updated: AnalystProfile = { ...current, ...profile };
  inMemoryProfile = updated;
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    try {
      localStorage.setItem(ANALYST_PROFILE_KEY, JSON.stringify(updated));
    } catch {}
  }
  return updated;
}

/**
 * Retrieve persisted generated report audit records.
 */
export function getGeneratedReports(mode?: AppMode): GeneratedReportRecord[] {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(REPORTS_STORAGE_KEY);
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    const targetMode = mode || getAppMode();
    if (targetMode === 'operational') {
      return list.filter((r: GeneratedReportRecord) => !r.isTrainingScenario);
    } else {
      return list.filter((r: GeneratedReportRecord) => Boolean(r.isTrainingScenario));
    }
  } catch {
    return [];
  }
}

export function recordGeneratedReport(report: Omit<GeneratedReportRecord, 'id' | 'timestamp'>): GeneratedReportRecord {
  const now = new Date().toISOString();
  const isTraining = report.isTrainingScenario ?? (getAppMode() === 'training');
  const record: GeneratedReportRecord = {
    ...report,
    id: `rep-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: now,
    isTrainingScenario: isTraining,
  };
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    try {
      const raw = localStorage.getItem(REPORTS_STORAGE_KEY);
      const list = raw ? JSON.parse(raw) : [];
      list.unshift(record);
      localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(list));
    } catch {}
  }
  return record;
}

export function clearGeneratedReports(mode?: AppMode): void {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
  try {
    if (!mode) {
      localStorage.removeItem(REPORTS_STORAGE_KEY);
    } else {
      const raw = localStorage.getItem(REPORTS_STORAGE_KEY);
      if (!raw) return;
      const list = JSON.parse(raw);
      if (Array.isArray(list)) {
        const filtered =
          mode === 'operational'
            ? list.filter((r: GeneratedReportRecord) => r.isTrainingScenario)
            : list.filter((r: GeneratedReportRecord) => !r.isTrainingScenario);
        localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(filtered));
      }
    }
  } catch {}
}

/**
 * In operational mode, strictly returns user-created operational cases (empty on clean slate).
 * In training mode, returns the isolated sandbox fixtures.
 */
export function getStoredCases(): CaseRecord[] {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return [];
  try {
    const mode = getAppMode();
    const key = mode === 'training' ? TRAINING_STORAGE_KEY : OPERATIONAL_STORAGE_KEY;
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveCases(cases: CaseRecord[]): void {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
  try {
    const mode = getAppMode();
    const key = mode === 'training' ? TRAINING_STORAGE_KEY : OPERATIONAL_STORAGE_KEY;
    localStorage.setItem(key, JSON.stringify(cases));
  } catch (err) {
    console.error('Failed to save cases to local storage:', err);
  }
}

/**
 * Loads isolated verification fixtures strictly into the training partition.
 * Never pollutes or modifies operational storage.
 */
export function loadTrainingScenario(): CaseRecord[] {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return TRAINING_SCENARIO_CASES;
  try {
    setAppMode('training');
    const cloned: CaseRecord[] = JSON.parse(JSON.stringify(TRAINING_SCENARIO_CASES));
    localStorage.setItem(TRAINING_STORAGE_KEY, JSON.stringify(cloned));
    if (cloned.length > 0) {
      localStorage.setItem(ACTIVE_CASE_KEY, cloned[0].id);
    }
    return cloned;
  } catch {
    return TRAINING_SCENARIO_CASES;
  }
}

/**
 * Exits training mode and returns back to the authentic operational environment.
 */
export function exitTrainingMode(): CaseRecord[] {
  setAppMode('operational');
  const opCases = getStoredCases();
  if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
    try {
      if (opCases.length > 0) {
        localStorage.setItem(ACTIVE_CASE_KEY, opCases[0].id);
      } else {
        localStorage.removeItem(ACTIVE_CASE_KEY);
      }
    } catch {}
  }
  return opCases;
}

/**
 * Wipes cases for the active partition, or wipes everything back to pristine clean slate.
 */
export function clearAllCases(): CaseRecord[] {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return [];
  try {
    const mode = getAppMode();
    if (mode === 'training') {
      localStorage.setItem(TRAINING_STORAGE_KEY, JSON.stringify([]));
      clearGeneratedReports('training');
      setAppMode('operational');
    }
    localStorage.setItem(OPERATIONAL_STORAGE_KEY, JSON.stringify([]));
    localStorage.removeItem(ACTIVE_CASE_KEY);
    clearGeneratedReports('operational');
    return [];
  } catch {
    return [];
  }
}

export function getActiveCaseId(): string {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return '';
  const stored = localStorage.getItem(ACTIVE_CASE_KEY);
  if (stored) return stored;
  const cases = getStoredCases();
  return cases.length > 0 ? cases[0].id : '';
}

export function setActiveCaseId(id: string): void {
  if (typeof window === 'undefined' || typeof localStorage === 'undefined') return;
  localStorage.setItem(ACTIVE_CASE_KEY, id);
}

// -------------------------------------------------------------
// METRIC AUDIT FUNCTIONS (Accurate, Ground-Truth Derived)
// -------------------------------------------------------------

/**
 * Count only cases whose actual status qualifies as active:
 * 'Open', 'In Progress', 'Analyzing'. Exclude 'Closed' and 'Archived'.
 */
export function getActiveCasesCount(cases: CaseRecord[]): number {
  if (!Array.isArray(cases) || cases.length === 0) return 0;
  const activeStatuses = new Set(['Open', 'In Progress', 'Analyzing']);
  return cases.filter((c) => activeStatuses.has(c.status)).length;
}

/**
 * Count actual unique persisted evidence records across cases.
 * Deduplicated by ID or (type + ':' + value).
 */
export function getUniqueEvidenceCount(cases: CaseRecord[]): number {
  if (!Array.isArray(cases) || cases.length === 0) return 0;
  const seen = new Set<string>();
  for (const c of cases) {
    if (!Array.isArray(c.evidence)) continue;
    for (const ev of c.evidence) {
      const key = ev.id || `${ev.type}:${ev.value}`;
      seen.add(key);
    }
  }
  return seen.size;
}

/**
 * Count indicators that have genuinely been reviewed according to an audit event or non-default status.
 * Do not simply count domains, IPs, CVEs, or file hashes that exist somewhere in storage.
 */
export function getIndicatorsReviewedCount(cases: CaseRecord[]): number {
  if (!Array.isArray(cases) || cases.length === 0) return 0;
  const reviewedIndicators = new Set<string>();

  for (const c of cases) {
    // 1. Findings with reviewed status (not 'Unresolved')
    if (Array.isArray(c.findings)) {
      for (const f of c.findings) {
        if (f.status && f.status !== 'Unresolved') {
          reviewedIndicators.add(`finding:${f.id}`);
          if (f.targetEntity) reviewedIndicators.add(`entity:${f.targetEntity}`);
        }
      }
    }

    // 2. Correlation overrides explicitly recorded by analyst
    if (c.correlationOverrides) {
      for (const [edgeId, status] of Object.entries(c.correlationOverrides)) {
        if (status) {
          reviewedIndicators.add(`override:${edgeId}`);
        }
      }
    }

    // 3. Audit trail events indicating analyst review actions
    if (Array.isArray(c.auditLog)) {
      for (const audit of c.auditLog) {
        if (
          audit.action === 'CORRELATION_OVERRIDE' ||
          audit.action === 'FINDING_STATUS_UPDATED' ||
          audit.action === 'STATUS_UPDATED'
        ) {
          reviewedIndicators.add(`audit:${audit.id}`);
        }
      }
    }
  }

  return reviewedIndicators.size;
}

/**
 * Count actual generated report records from persisted report registry.
 */
export function getReportsGeneratedCount(mode?: AppMode): number {
  return getGeneratedReports(mode).length;
}

// -------------------------------------------------------------
// CASE MUTATION OPERATIONS
// -------------------------------------------------------------

export function createCase(newCase: {
  title: string;
  description: string;
  priority: SeverityLevel;
  leadAnalyst: string;
  scope: string[];
  tags: string[];
  tenantId?: string;
}): CaseRecord {
  assertRolePermission('canCreateCase');
  const cases = getStoredCases();
  const nextNum = cases.length + 1;
  const id = `#VY-2025-${String(nextNum).padStart(4, '0')}`;
  const now = new Date().toISOString();
  const profile = getAnalystProfile();
  const analystName = newCase.leadAnalyst?.trim() || profile.name;
  const tenantId = newCase.tenantId || profile.tenantId || 'tenant-default';

  const initialAudit = createChainedAuditEntry(
    [],
    'CASE_CREATED',
    analystName,
    `Case ${id} initialized for tenant ${tenantId}.`,
    now
  );

  const createdRecord: CaseRecord = {
    id,
    tenantId,
    title: newCase.title,
    description: newCase.description,
    priority: newCase.priority,
    status: 'Open',
    leadAnalyst: analystName,
    createdAt: now,
    updatedAt: now,
    scope: newCase.scope,
    tags: newCase.tags,
    evidence: [],
    findings: [],
    notes: [],
    auditLog: [initialAudit],
  };

  cases.unshift(createdRecord);
  saveCases(cases);
  setActiveCaseId(id);
  return createdRecord;
}

export function addEvidenceToCase(
  caseId: string,
  evidenceData: Omit<EvidenceItem, 'id' | 'timestamp'>,
  activeTenantId?: string
): EvidenceItem {
  assertRolePermission('canAddEvidence');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);
  assertTenantAccess(c, activeTenantId);

  const now = new Date().toISOString();
  const item: EvidenceItem = {
    ...evidenceData,
    id: `ev-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    caseId,
    timestamp: now,
  };

  const actor = getAnalystProfile().name;
  c.evidence.push(item);
  c.updatedAt = now;
  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'EVIDENCE_ADDED',
      actor,
      `Added ${item.type} evidence: "${item.name}" (${item.confidence})`,
      now
    )
  );

  saveCases(cases);
  return item;
}

export function addFindingToCase(
  caseId: string,
  findingData: Partial<Finding>,
  activeTenantId?: string
): Finding {
  assertRolePermission('canLogFinding');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);
  assertTenantAccess(c, activeTenantId);

  const finding = normalizeFinding(findingData, caseId);
  const actor = getAnalystProfile().name;

  c.findings.push(finding);
  c.updatedAt = finding.collectedAt;
  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'FINDING_LOGGED',
      actor,
      `Logged finding [${finding.id}]: "${finding.title}" [${finding.severity}] (${finding.category})`,
      finding.collectedAt
    )
  );

  saveCases(cases);
  return finding;
}

export function updateFindingStatus(
  caseId: string,
  findingId: string,
  status: Finding['status'],
  analystName?: string,
  rationale?: string,
  activeTenantId?: string
): Finding | null {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return null;
  assertTenantAccess(c, activeTenantId);

  const finding = c.findings.find((f) => f.id === findingId);
  if (!finding) return null;

  const oldStatus = finding.status;
  finding.status = status;
  const now = new Date().toISOString();
  c.updatedAt = now;
  const effectiveAnalyst = analystName || getAnalystProfile().name;

  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'FINDING_STATUS_UPDATED',
      effectiveAnalyst,
      `Updated finding [${finding.id}] status from ${oldStatus} to ${status}.${rationale ? ` Reason: ${rationale}` : ''}`,
      now
    )
  );

  saveCases(cases);
  return finding;
}

export function updateCorrelationOverride(
  caseId: string,
  edgeId: string,
  status: CorrelationStatus,
  analystName?: string,
  reason?: string,
  activeTenantId?: string
): void {
  assertRolePermission('canOverrideCorrelation');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  if (!c.correlationOverrides) {
    c.correlationOverrides = {};
  }
  c.correlationOverrides[edgeId] = status;
  const now = new Date().toISOString();
  c.updatedAt = now;
  const effectiveAnalyst = analystName || getAnalystProfile().name;

  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'CORRELATION_OVERRIDE',
      effectiveAnalyst,
      `Analyst marked correlation [${edgeId}] as ${status.toUpperCase()}.${reason ? ` Justification: ${reason}` : ''}`,
      now
    )
  );

  saveCases(cases);
}

export function dismissCorrelation(
  caseId: string,
  edgeId: string,
  analystName?: string,
  reason?: string,
  activeTenantId?: string
): void {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  if (!c.dismissedCorrelationIds) c.dismissedCorrelationIds = [];
  if (!c.dismissedCorrelationIds.includes(edgeId)) {
    c.dismissedCorrelationIds.push(edgeId);
  }
  saveCases(cases);
  updateCorrelationOverride(caseId, edgeId, 'dismissed', analystName, reason, activeTenantId);
}

export function markCorrelationUnverified(
  caseId: string,
  edgeId: string,
  analystName?: string,
  reason?: string,
  activeTenantId?: string
): void {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  if (!c.unverifiedCorrelationIds) c.unverifiedCorrelationIds = [];
  if (!c.unverifiedCorrelationIds.includes(edgeId)) {
    c.unverifiedCorrelationIds.push(edgeId);
  }
  saveCases(cases);
  updateCorrelationOverride(caseId, edgeId, 'unverified', analystName, reason, activeTenantId);
}

export function restoreCorrelation(
  caseId: string,
  edgeId: string,
  analystName?: string,
  activeTenantId?: string
): void {
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  if (c.dismissedCorrelationIds) {
    c.dismissedCorrelationIds = c.dismissedCorrelationIds.filter((id) => id !== edgeId);
  }
  if (c.unverifiedCorrelationIds) {
    c.unverifiedCorrelationIds = c.unverifiedCorrelationIds.filter((id) => id !== edgeId);
  }
  saveCases(cases);
  updateCorrelationOverride(caseId, edgeId, 'confirmed', analystName, 'Restored to confirmed status', activeTenantId);
}

export function addNoteToCase(caseId: string, author: string, text: string, activeTenantId?: string): void {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  const now = new Date().toISOString();
  const effectiveAuthor = author?.trim() || getAnalystProfile().name;
  c.notes.push({
    id: `note-${Date.now()}`,
    author: effectiveAuthor,
    text,
    timestamp: now,
  });
  c.updatedAt = now;
  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'NOTE_ADDED',
      effectiveAuthor,
      `Analyst added case note (${text.slice(0, 40)}...)`,
      now
    )
  );
  saveCases(cases);
}

export function updateCaseStatus(caseId: string, status: CaseRecord['status'], activeTenantId?: string): void {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return;
  assertTenantAccess(c, activeTenantId);

  c.status = status;
  c.updatedAt = new Date().toISOString();
  const actor = getAnalystProfile().name;
  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'STATUS_UPDATED',
      actor,
      `Case status changed to ${status}.`,
      c.updatedAt
    )
  );
  saveCases(cases);
}

export function deleteCase(caseId: string, activeTenantId?: string): void {
  assertRolePermission('canDeleteCase');
  let cases = getStoredCases();
  const target = cases.find((c) => c.id === caseId);
  if (target) {
    assertTenantAccess(target, activeTenantId);
  }
  cases = cases.filter((c) => c.id !== caseId);
  saveCases(cases);
}

export function getCaseById(caseId: string, activeTenantId?: string): CaseRecord | undefined {
  const cases = getStoredCases();
  const target = cases.find((c) => c.id === caseId);
  if (target && activeTenantId) {
    assertTenantAccess(target, activeTenantId);
  }
  return target;
}

export function addHypothesisToCase(
  caseId: string,
  data: {
    title: string;
    premise: string;
    confidence: 'High' | 'Medium' | 'Low';
    supportingEvidenceIds?: string[];
    contradictingEvidenceIds?: string[];
    alternativeExplanations?: string[];
    openQuestions?: string[];
    nextSteps?: string[];
    isAiSuggested?: boolean;
    author?: string;
  },
  activeTenantId?: string
): HypothesisItem {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);
  assertTenantAccess(c, activeTenantId);

  const effectiveAuthor = data.author?.trim() || getAnalystProfile().name;
  const hypothesis = createHypothesisItem(caseId, {
    ...data,
    author: effectiveAuthor,
  });

  if (!c.hypotheses) c.hypotheses = [];
  c.hypotheses.push(hypothesis);
  const now = new Date().toISOString();
  c.updatedAt = now;

  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'HYPOTHESIS_CREATED',
      effectiveAuthor,
      `Analyst formulated investigative hypothesis [${hypothesis.id}]: "${hypothesis.title}" (${data.confidence} confidence).`,
      now
    )
  );

  saveCases(cases);
  return hypothesis;
}

export function updateHypothesisInCase(
  caseId: string,
  hypothesisId: string,
  updates: Partial<HypothesisItem>,
  analystName?: string,
  activeTenantId?: string
): CaseRecord {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);
  assertTenantAccess(c, activeTenantId);

  if (!c.hypotheses) c.hypotheses = [];
  const idx = c.hypotheses.findIndex((h) => h.id === hypothesisId);
  if (idx === -1) throw new Error(`Hypothesis ${hypothesisId} not found in case ${caseId}.`);

  const now = new Date().toISOString();
  const actor = analystName || getAnalystProfile().name;
  const current = c.hypotheses[idx];

  const changeNotes: string[] = [];
  if (updates.status && updates.status !== current.status) {
    changeNotes.push(`Status changed from ${current.status} to ${updates.status}`);
  }
  if (updates.confidence && updates.confidence !== current.confidence) {
    changeNotes.push(`Confidence updated from ${current.confidence} to ${updates.confidence}`);
  }
  if (updates.title && updates.title !== current.title) {
    changeNotes.push(`Title updated to "${updates.title}"`);
  }

  const updatedRevisions = [
    ...(current.revisions || []),
    {
      timestamp: now,
      analyst: actor,
      action: 'Hypothesis Updated',
      changeSummary: changeNotes.join(', ') || 'Updated hypothesis details or linked evidence.',
    },
  ];

  c.hypotheses[idx] = {
    ...current,
    ...updates,
    updatedAt: now,
    revisions: updatedRevisions,
  };
  c.updatedAt = now;

  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'HYPOTHESIS_UPDATED',
      actor,
      `Updated hypothesis [${hypothesisId}]: ${changeNotes.join(', ') || 'Modified details.'}`,
      now
    )
  );

  saveCases(cases);
  return c;
}

export function deleteHypothesisFromCase(caseId: string, hypothesisId: string, activeTenantId?: string): CaseRecord {
  assertRolePermission('canEditCase');
  const cases = getStoredCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) throw new Error(`Case ${caseId} not found.`);
  assertTenantAccess(c, activeTenantId);

  if (!c.hypotheses) return c;
  c.hypotheses = c.hypotheses.filter((h) => h.id !== hypothesisId);
  const now = new Date().toISOString();
  c.updatedAt = now;
  const actor = getAnalystProfile().name;

  c.auditLog.push(
    createChainedAuditEntry(
      c.auditLog,
      'HYPOTHESIS_DELETED',
      actor,
      `Deleted hypothesis [${hypothesisId}].`,
      now
    )
  );

  saveCases(cases);
  return c;
}
