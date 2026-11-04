import { CaseRecord, TimelineEvent, TimelineInconsistency, SeverityLevel, ConfidenceLevel } from '../types';

/**
 * Normalizes an arbitrary timestamp into an ISO-8601 UTC string while evaluating timezone integrity.
 */
export function normalizeUtcTimestamp(rawTimestamp: string | number | undefined): {
  utcIso: string;
  original: string;
  inconsistency?: TimelineInconsistency;
  details?: string;
  timezone?: string;
} {
  if (!rawTimestamp && rawTimestamp !== 0) {
    return {
      utcIso: '1970-01-01T00:00:00.000Z',
      original: 'None provided',
      inconsistency: 'EpochZero',
      details: 'Missing or null timestamp; defaulted to epoch baseline.',
    };
  }

  const origStr = String(rawTimestamp).trim();

  // Numeric epoch milliseconds or seconds
  if (typeof rawTimestamp === 'number' || /^\d{10,13}$/.test(origStr)) {
    const num = Number(rawTimestamp);
    if (num <= 0) {
      return {
        utcIso: '1970-01-01T00:00:00.000Z',
        original: origStr,
        inconsistency: 'EpochZero',
        details: 'Timestamp is zero or negative (unrecorded clock ticks).',
      };
    }
    const millis = num < 10000000000 ? num * 1000 : num;
    const d = new Date(millis);
    const now = Date.now();
    const isFuture = d.getTime() > now + 3600000; // 1 hour threshold for clock drift

    return {
      utcIso: d.toISOString(),
      original: `${origStr} (Unix timestamp)`,
      timezone: 'UTC',
      inconsistency: isFuture ? 'FutureDate' : undefined,
      details: isFuture ? `Timestamp ${d.toISOString()} is in the future relative to current audit clock.` : undefined,
    };
  }

  // String timestamp parsing
  let detectedTz = 'Unspecified';
  let hasTz = false;
  if (origStr.endsWith('Z')) {
    detectedTz = 'UTC (Z)';
    hasTz = true;
  } else if (/[+-]\d{2}:?\d{2}$/.test(origStr)) {
    const match = origStr.match(/([+-]\d{2}:?\d{2})$/);
    detectedTz = match ? match[1] : 'Offset';
    hasTz = true;
  }

  const parsed = Date.parse(origStr);
  if (isNaN(parsed)) {
    return {
      utcIso: '1970-01-01T00:00:00.000Z',
      original: origStr,
      inconsistency: 'EpochZero',
      details: `Failed to parse unformatted date string: "${origStr}".`,
    };
  }

  const d = new Date(parsed);
  const now = Date.now();
  const isFuture = d.getTime() > now + 3600000;

  let inconsistency: TimelineInconsistency | undefined = undefined;
  let details: string | undefined = undefined;

  if (isFuture) {
    inconsistency = 'FutureDate';
    details = `Timestamp ${d.toISOString()} is in the future relative to system clock. Potential clock skew or deliberate anti-forensics timestamp manipulation.`;
  } else if (!hasTz) {
    inconsistency = 'MissingTimezone';
    details = `Timestamp string "${origStr}" does not declare an explicit UTC offset (Z or +/-HH:MM). Normalized assuming system local time.`;
  }

  return {
    utcIso: d.toISOString(),
    original: origStr,
    timezone: detectedTz,
    inconsistency,
    details,
  };
}

/**
 * Builds a unified, chronological timeline across all evidence items, findings,
 * audit log entries, notes, and case lifecycle events within an active CaseRecord.
 */
export function buildCaseTimeline(caseRecord: CaseRecord): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  // 1. Case Creation Event
  if (caseRecord.createdAt) {
    const norm = normalizeUtcTimestamp(caseRecord.createdAt);
    events.push({
      id: `TL-CASE-INIT`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'audit',
      source: 'Case Management',
      sourceId: caseRecord.id,
      title: `Case Initialized: ${caseRecord.id}`,
      description: `Investigation initialized with classification "${caseRecord.classification || 'TLP:AMBER'}". Lead Analyst: ${caseRecord.leadAnalyst}.`,
      confidence: 'Confirmed',
      targetEntity: caseRecord.title,
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['lifecycle', 'case-init'],
    });
  }

  // 2. Evidence Ingestion Events
  (caseRecord.evidence || []).forEach((ev) => {
    const norm = normalizeUtcTimestamp(ev.timestamp);
    events.push({
      id: `TL-EV-${ev.id}`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'evidence',
      source: ev.source || 'Evidence Intake',
      sourceId: ev.id,
      title: `Evidence Ingested: ${ev.name}`,
      description: `Type: [${ev.type.toUpperCase()}] Value: ${ev.value}. Source: ${ev.source}. ${ev.notes ? `Notes: ${ev.notes}` : ''}`,
      confidence: ev.confidence || 'Confirmed',
      targetEntity: ev.value,
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['evidence', ev.type],
    });
  });

  // 3. Technical Finding Observations
  (caseRecord.findings || []).forEach((f) => {
    const rawTs = f.collectedAt || f.timestamp;
    const norm = normalizeUtcTimestamp(rawTs);
    events.push({
      id: `TL-FND-${f.id}`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'finding',
      source: f.sourceTool || 'Forensic Sensor',
      sourceId: f.id,
      title: `Finding Logged: ${f.title}`,
      description: `Observed: ${f.observedResult}. Target: ${f.targetEntity}. Category: ${f.category}. Status: ${f.status}.`,
      severity: f.severity,
      confidence: f.confidence || 'Confirmed',
      targetEntity: f.targetEntity,
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['finding', f.category.toLowerCase().replace(/\s+/g, '-')],
    });
  });

  // 4. Audit Log Actions
  (caseRecord.auditLog || []).forEach((log) => {
    const norm = normalizeUtcTimestamp(log.timestamp);
    events.push({
      id: `TL-AUDIT-${log.id}`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'audit',
      source: 'Security Audit Log',
      sourceId: log.id,
      title: `Audit Action: ${log.action}`,
      description: `Actor: ${log.actor}. Details: ${log.details}. ${log.hash ? `Integrity Hash: ${log.hash.slice(0, 16)}...` : ''}`,
      confidence: 'Confirmed',
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['audit'],
    });
  });

  // 5. Analyst Notes
  (caseRecord.notes || []).forEach((note) => {
    const norm = normalizeUtcTimestamp(note.timestamp);
    events.push({
      id: `TL-NOTE-${note.id}`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'note',
      source: `Analyst Note: ${note.author}`,
      sourceId: note.id,
      title: `Analyst Annotation by ${note.author}`,
      description: note.text,
      confidence: 'Inferred',
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['analyst-note'],
    });
  });

  // 6. Investigative Hypotheses
  (caseRecord.hypotheses || []).forEach((hyp) => {
    const norm = normalizeUtcTimestamp(hyp.createdAt);
    events.push({
      id: `TL-HYP-${hyp.id}`,
      utcTimestamp: norm.utcIso,
      originalTimestamp: norm.original,
      timezone: norm.timezone,
      eventType: 'hypothesis',
      source: `Hypothesis Engine (${hyp.author})`,
      sourceId: hyp.id,
      title: `Hypothesis Formulated: ${hyp.title}`,
      description: `Premise: ${hyp.premise}. Status: ${hyp.status} (Confidence: ${hyp.confidence}). Supporting Evidence: ${hyp.supportingEvidenceIds.length} items.`,
      confidence: hyp.confidence === 'High' ? 'Confirmed' : hyp.confidence === 'Medium' ? 'Inferred' : 'Potential',
      isInconsistent: !!norm.inconsistency,
      inconsistencyType: norm.inconsistency,
      inconsistencyDetails: norm.details,
      tags: ['hypothesis', hyp.status.toLowerCase()],
    });
  });

  // Check for post-case closure inconsistencies
  if (caseRecord.status === 'Closed' && caseRecord.updatedAt) {
    const closedTime = new Date(caseRecord.updatedAt).getTime();
    events.forEach((ev) => {
      const evTime = new Date(ev.utcTimestamp).getTime();
      if (evTime > closedTime + 60000 && ev.id !== 'TL-CASE-INIT') {
        ev.isInconsistent = true;
        ev.inconsistencyType = 'PostCaseClosure';
        ev.inconsistencyDetails = `Event timestamp occurs after case closure (${caseRecord.updatedAt}).`;
      }
    });
  }

  // Sort strictly chronologically by normalized UTC timestamp
  return events.sort((a, b) => new Date(a.utcTimestamp).getTime() - new Date(b.utcTimestamp).getTime());
}

/**
 * Filters timeline events based on multi-dimensional criteria.
 */
export function filterTimelineEvents(
  events: TimelineEvent[],
  filters: {
    eventType?: string;
    source?: string;
    severity?: string;
    inconsistentOnly?: boolean;
    searchQuery?: string;
    sortOrder?: 'asc' | 'desc';
  }
): TimelineEvent[] {
  let filtered = events.filter((ev) => {
    if (filters.eventType && filters.eventType !== 'all' && ev.eventType !== filters.eventType) return false;
    if (filters.severity && filters.severity !== 'all' && ev.severity !== filters.severity) return false;
    if (filters.source && filters.source !== 'all' && ev.source !== filters.source) return false;
    if (filters.inconsistentOnly && !ev.isInconsistent) return false;

    if (filters.searchQuery && filters.searchQuery.trim()) {
      const q = filters.searchQuery.toLowerCase();
      const matchTitle = ev.title.toLowerCase().includes(q);
      const matchDesc = ev.description.toLowerCase().includes(q);
      const matchTarget = ev.targetEntity?.toLowerCase().includes(q) || false;
      const matchSource = ev.source.toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchTarget && !matchSource) return false;
    }

    return true;
  });

  if (filters.sortOrder === 'desc') {
    filtered = filtered.reverse();
  }

  return filtered;
}
